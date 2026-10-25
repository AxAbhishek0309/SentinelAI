"""
Core scanning engine — real Playwright headless browser scan.

Each scan runs in an isolated Chromium context. The engine collects:
  - All network requests/responses (method, url, status, content-type, timing)
  - Response headers for every page
  - document.cookie + localStorage + sessionStorage via JS execution
  - All <script> src URLs and inline script snippets
  - Page titles and HTTP status codes for every visited URL
  - TLS / HTTPS signal

Then passes raw data to analysis modules which produce Finding objects.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    async_playwright,
)

from models import (
    CookieItem,
    NetworkRequest,
    PageInfo,
    ScanLogEntry,
    ScanStatus,
    SecurityReport,
    StorageItem,
    SecretFinding,
)
from config import settings

if TYPE_CHECKING:
    from scanner.state import ScanState


async def run_scan(state: "ScanState") -> SecurityReport:
    """
    Entry point called by the background task.
    Drives status transitions and delegates work to sub-modules.
    """
    from scanner.analysis import analyse
    from scanner.ai import generate_ai_summary

    started_at = datetime.now(UTC)
    target_url = state.request.url

    try:
        await state.transition(ScanStatus.initializing, "Initializing secure browser environment")

        raw = await _browser_crawl(state, target_url)

        await state.transition(ScanStatus.finding_secrets, "Scanning for exposed secrets")
        await asyncio.sleep(0.1)  # yield so SSE can flush

        await state.transition(ScanStatus.generating_report, "Generating AI-powered report")
        findings, score, grade, headers, cookies, storage = await analyse(raw, target_url)

        ai_summary, ai_recs = await generate_ai_summary(
            target_url=target_url,
            findings=findings,
            score=score,
            tech_stack=raw["tech_stack"],
            headers=headers,
        )

        completed_at = datetime.now(UTC)
        duration = (completed_at - started_at).total_seconds()

        # Severity counts
        from models import Severity
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        report = SecurityReport(
            scan_id=state.scan_id,
            target_url=target_url,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=round(duration, 2),
            score=score,
            grade=grade,
            critical_count=counts[Severity.critical],
            high_count=counts[Severity.high],
            medium_count=counts[Severity.medium],
            low_count=counts[Severity.low],
            info_count=counts[Severity.info],
            pages=raw["pages"],
            network_requests=raw["requests"][:200],  # cap at 200
            cookies=cookies,
            storage_items=storage,
            security_headers=headers,
            secrets=raw["secrets"],
            findings=findings,
            ai_summary=ai_summary,
            ai_recommendations=ai_recs,
            tech_stack=raw["tech_stack"],
        )

        await state.complete(report)
        return report

    except asyncio.CancelledError:
        await state.cancel()
        raise
    except Exception as exc:
        await state.fail(str(exc))
        raise


# ---------------------------------------------------------------------------
# Browser crawl
# ---------------------------------------------------------------------------

async def _browser_crawl(state: "ScanState", target_url: str) -> dict:
    """
    Launch headless Chromium, crawl the target, collect all signals.
    Returns a raw dict consumed by the analysis layer.
    """
    await state.transition(ScanStatus.launching_browser, "Launching headless Chromium")

    requests_log: list[NetworkRequest] = []
    pages_visited: list[PageInfo] = []
    all_scripts: list[str] = []  # src URLs + inline content snippets
    response_headers_map: dict[str, dict] = {}  # url -> headers for main pages

    async with async_playwright() as pw:
        browser: Browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
            ],
        )

        context: BrowserContext = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36 SentinelAI/1.0"
            ),
            ignore_https_errors=False,  # we want TLS errors to surface
        )

        # Intercept all network
        async def on_request(req: Request):
            pass  # we record on response to get status

        async def on_response(resp: Response):
            try:
                req = resp.request
                timing = None
                try:
                    t = req.timing
                    if t and t.get("responseEnd") and t.get("requestStart"):
                        timing = int(t["responseEnd"] - t["requestStart"])
                except Exception:
                    pass

                ct = resp.headers.get("content-type", "")
                acao = resp.headers.get("access-control-allow-origin", "")
                flagged, flag_reason = _flag_request(req.url, req.method, resp.status, ct, acao)

                requests_log.append(
                    NetworkRequest(
                        method=req.method,
                        url=req.url,
                        status=resp.status,
                        content_type=ct or None,
                        duration_ms=timing,
                        flagged=flagged,
                        flag_reason=flag_reason,
                    )
                )
            except Exception:
                pass

        context.on("request", on_request)
        context.on("response", on_response)

        page: Page = await context.new_page()

        await state.transition(ScanStatus.collecting_requests, "Opening target URL")
        await state.log("info", f"Navigating to {target_url}")

        try:
            response = await page.goto(target_url, wait_until="networkidle", timeout=30_000)
            root_status = response.status if response else 0
        except Exception as e:
            await state.log("warn", f"Navigation issue: {e} — retrying with domcontentloaded")
            try:
                response = await page.goto(target_url, wait_until="domcontentloaded", timeout=20_000)
                root_status = response.status if response else 0
            except Exception as e2:
                await state.fail(f"Cannot reach {target_url}: {e2}")
                raise

        title = await page.title()
        pages_visited.append(PageInfo(url=target_url, title=title, status=root_status))

        # Capture response headers for root page
        if response:
            response_headers_map[target_url] = dict(response.headers)

        await state.log("ok", f"Loaded: {title or target_url} (HTTP {root_status})")
        await state.transition(ScanStatus.exploring_pages, "Exploring pages and links")

        # Collect internal links
        base_origin = urlparse(target_url).netloc
        links = await page.evaluate("""() => {
            return Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h.startsWith('http'))
        }""")

        internal_links = list({
            l for l in links
            if urlparse(l).netloc == base_origin
            and l != target_url
        })[:settings.max_pages_to_crawl - 1]

        await state.log("info", f"Found {len(internal_links)} internal links to visit")

        # Collect scripts from root page
        root_scripts = await _collect_scripts(page)
        all_scripts.extend(root_scripts)

        # Visit sub-pages
        for link in internal_links:
            try:
                sub_resp = await page.goto(link, wait_until="domcontentloaded", timeout=15_000)
                sub_status = sub_resp.status if sub_resp else 0
                sub_title = await page.title()
                pages_visited.append(PageInfo(url=link, title=sub_title, status=sub_status))
                if sub_resp:
                    response_headers_map[link] = dict(sub_resp.headers)
                sub_scripts = await _collect_scripts(page)
                all_scripts.extend(sub_scripts)
                await state.log("info", f"Visited: {link} ({sub_status})")
                await asyncio.sleep(0.5)
            except Exception as e:
                await state.log("warn", f"Could not visit {link}: {e}")
                pages_visited.append(PageInfo(url=link, title=None, status=None, visited=False))

        # Go back to root for storage/cookie inspection
        await page.goto(target_url, wait_until="domcontentloaded", timeout=20_000)

        await state.transition(ScanStatus.analyzing_javascript, "Analyzing JavaScript and storage")
        storage_data = await _collect_storage(page, target_url)
        cookies_raw = await context.cookies()
        tech_stack = await _detect_tech_stack(page)

        await state.log("info", f"Tech stack detected: {', '.join(tech_stack) or 'unknown'}")
        await state.log("info", f"Storage items: {len(storage_data['local']) + len(storage_data['session'])}")
        await state.log("info", f"Cookies: {len(cookies_raw)}")
        await state.log("info", f"Network requests: {len(requests_log)}")

        await state.transition(ScanStatus.inspecting_headers, "Inspecting security headers")
        # Headers already collected in response_headers_map

        await state.transition(ScanStatus.checking_cookies, "Auditing cookies and storage")

        # Fetch and scan JS bundle content — this is where most secrets leak
        await state.log("info", "Fetching JS bundles for deep secret scan…")
        bundle_secrets = await _fetch_and_scan_bundles(all_scripts, target_url, state)

        # Sync DOM/storage scan (returns findings + raw values for verification)
        dom_findings_raw = _find_secrets_in_scripts(all_scripts)
        storage_findings_raw = _find_secrets_in_storage(storage_data)

        # Verify DOM and storage findings live
        dom_secrets = await _verify_batch(dom_findings_raw, state)
        storage_secrets = await _verify_batch(storage_findings_raw, state)

        secrets_found = bundle_secrets + dom_secrets + storage_secrets
        if secrets_found:
            await state.log("warn", f"⚠ Found {len(secrets_found)} potential secret(s)")
        else:
            await state.log("ok", "No secrets detected in scripts or storage")

        await browser.close()

    return {
        "requests": requests_log,
        "pages": pages_visited,
        "response_headers_map": response_headers_map,
        "storage_data": storage_data,
        "cookies_raw": cookies_raw,
        "scripts": all_scripts,
        "secrets": secrets_found,
        "tech_stack": tech_stack,
        "is_https": target_url.startswith("https://"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _collect_scripts(page: Page) -> list[str]:
    """
    Collect:
      - Script src URLs (for path-based flagging)
      - Inline script content up to 8KB each
      - window.* globals that might expose config
      - meta tag content (generator, env vars sometimes leak here)
      - data-* attributes on root element and body
    """
    try:
        dom_content = await page.evaluate("""() => {
            const results = [];

            // Script tags
            document.querySelectorAll('script').forEach(s => {
                if (s.src) {
                    results.push('src:' + s.src);
                } else if (s.textContent && s.textContent.trim().length > 20) {
                    // Capture up to 8KB of each inline script
                    results.push('inline:' + s.textContent.slice(0, 8192));
                }
            });

            // window globals that commonly expose config
            const configKeys = [
                '__ENV__', '__env__', 'ENV', '_env', 'APP_CONFIG', 'appConfig',
                '__CONFIG__', 'config', 'CONFIG', '__RUNTIME_CONFIG__',
                'RUNTIME_CONFIG', '__PUBLIC_CONFIG__', 'publicConfig',
                '__NEXT_DATA__', '__NUXT__', '__SVELTEKIT_APP_VERSION_POLL_INTERVAL__',
                'VITE_', 'REACT_APP_', '__FIREBASE_CONFIG__', 'firebaseConfig',
                'supabase', '_supabaseUrl', 'SUPABASE_URL',
            ];
            for (const key of configKeys) {
                try {
                    const val = window[key];
                    if (val && typeof val === 'object') {
                        results.push('window:' + key + ':' + JSON.stringify(val).slice(0, 4096));
                    } else if (val && typeof val === 'string' && val.length > 8) {
                        results.push('window:' + key + ':' + val.slice(0, 512));
                    }
                } catch(e) {}
            }

            // Scan all window keys that look config-like
            try {
                Object.keys(window).forEach(k => {
                    if (/(?:key|token|secret|api|auth|config|env|firebase|supabase|stripe|twilio|sendgrid|openai|claude)/i.test(k)) {
                        try {
                            const v = window[k];
                            if (typeof v === 'string' && v.length > 8) {
                                results.push('window-global:' + k + ':' + v.slice(0, 256));
                            } else if (v && typeof v === 'object') {
                                results.push('window-global:' + k + ':' + JSON.stringify(v).slice(0, 1024));
                            }
                        } catch(e) {}
                    }
                });
            } catch(e) {}

            // Meta tags
            document.querySelectorAll('meta').forEach(m => {
                const content = m.getAttribute('content') || '';
                const name = m.getAttribute('name') || m.getAttribute('property') || '';
                if (content.length > 8) {
                    results.push('meta:' + name + ':' + content.slice(0, 512));
                }
            });

            // data-* on html + body (Next.js and others put config here)
            [document.documentElement, document.body].forEach(el => {
                if (!el) return;
                Array.from(el.attributes).forEach(attr => {
                    if (attr.name.startsWith('data-') && attr.value.length > 8) {
                        results.push('data-attr:' + attr.name + ':' + attr.value.slice(0, 512));
                    }
                });
            });

            return results;
        }""")
        return dom_content
    except Exception:
        return []


async def _collect_storage(page: Page, url: str) -> dict:
    """Read localStorage and sessionStorage safely."""
    try:
        return await page.evaluate("""() => {
            function dump(store) {
                const out = [];
                try {
                    for (let i = 0; i < store.length; i++) {
                        const k = store.key(i);
                        const v = store.getItem(k) || '';
                        out.push({ key: k, value: v.slice(0, 200) });
                    }
                } catch(e) {}
                return out;
            }
            return {
                local: dump(localStorage),
                session: dump(sessionStorage)
            };
        }""")
    except Exception:
        return {"local": [], "session": []}


async def _detect_tech_stack(page: Page) -> list[str]:
    """Detect frontend framework and libraries via DOM/global signals."""
    try:
        return await page.evaluate("""() => {
            const stack = [];
            // React
            if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot]') || document.querySelector('[data-reactid]')) stack.push('React');
            // Vue
            if (window.__VUE__ || window.Vue || document.querySelector('#app')?.__vue__) stack.push('Vue');
            // Angular
            if (window.ng || document.querySelector('[ng-version]')) stack.push('Angular');
            // Next.js
            if (window.__NEXT_DATA__) { stack.push('Next.js'); if (!stack.includes('React')) stack.push('React'); }
            // Nuxt
            if (window.__NUXT__) { stack.push('Nuxt'); if (!stack.includes('Vue')) stack.push('Vue'); }
            // Vite
            if (document.querySelector('script[type="module"][src*="@vite"]') || document.querySelector('script[src*="vite"]')) stack.push('Vite');
            // Webpack
            if (window.webpackChunk || window.webpackJsonp) stack.push('Webpack');
            // Svelte
            if (document.querySelector('[class*="svelte-"]')) stack.push('Svelte');
            // jQuery
            if (window.jQuery || window.$?.fn?.jquery) stack.push('jQuery ' + (window.jQuery?.fn?.jquery || ''));
            // Bootstrap
            if (window.bootstrap || document.querySelector('[data-bs-toggle]')) stack.push('Bootstrap');
            // Tailwind
            if (document.querySelector('[class*="tailwind"]') || document.querySelector('[class*="tw-"]')) stack.push('Tailwind CSS');
            // Check meta generator
            const gen = document.querySelector('meta[name="generator"]');
            if (gen) stack.push(gen.content);
            return [...new Set(stack.filter(Boolean))];
        }""")
    except Exception:
        return []


def _flag_request(url: str, method: str, status: int, content_type: str, acao: str = "") -> tuple[bool, str | None]:
    """Check if a request is worth flagging."""
    lower = url.lower()

    # CORS wildcard
    if acao == "*":
        return True, "CORS: Access-Control-Allow-Origin: *"

    # Sensitive file paths
    sensitive_patterns = [
        r"/\.env", r"/config\.js", r"/env\.js", r"/secrets",
        r"/admin", r"/api/internal", r"/__debug", r"/graphql",
        r"/\.git/", r"/wp-config", r"/phpinfo", r"/swagger",
        r"/api-docs", r"/openapi\.json", r"/actuator",
        r"/_debug", r"/__webpack_hmr", r"/server-info",
    ]
    for pat in sensitive_patterns:
        if re.search(pat, lower):
            return True, f"Sensitive path: {pat.strip(chr(47))}"

    # Error responses on API endpoints
    if status in (401, 403) and "/api/" in lower:
        return True, f"API auth failure ({status})"

    # Mixed content (HTTP asset on HTTPS page)
    if lower.startswith("http://") and not lower.startswith("http://localhost"):
        return True, "Insecure HTTP resource"

    return False, None


# ---------------------------------------------------------------------------
# Secret detection — comprehensive pattern library
# ---------------------------------------------------------------------------

# Load learned patterns from previous LLM discoveries
def _load_learned_patterns() -> list[tuple[str, re.Pattern, float]]:
    """Load patterns discovered by LLM from learned_patterns.json"""
    learned_file = Path(__file__).parent / "learned_patterns.json"
    if not learned_file.exists():
        return []
    try:
        with open(learned_file) as f:
            data = json.load(f)
        learned = []
        for p in data.get("patterns", []):
            try:
                pattern = re.compile(p["pattern"])
                learned.append((p["name"], pattern, p["confidence"]))
            except Exception:
                pass
        return learned
    except Exception:
        return []


_SECRET_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # ── Cloud providers ──────────────────────────────────────────────────────
    ("AWS Access Key ID",         re.compile(r"AKIA[0-9A-Z]{16}"), 0.97),
    ("AWS Secret Access Key",     re.compile(r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]"), 0.90),
    ("AWS Session Token",         re.compile(r"FwoGZXIvYXdzE[a-zA-Z0-9+/]{50,}"), 0.95),
    # Firebase API Key and GCP API Key share same pattern — merge into one finding labeled "Google/Firebase API Key"
    ("Google/Firebase API Key",   re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 0.97),
    ("GCP Service Account",       re.compile(r'"type":\s*"service_account"'), 0.90),
    ("Azure Storage Key",         re.compile(r"AccountKey=[a-zA-Z0-9+/]{88}=="), 0.97),
    ("Azure SAS Token",           re.compile(r"sig=[a-zA-Z0-9%]{40,}"), 0.80),
    ("Azure Client Secret",       re.compile(r"(?i)azure.{0,20}(secret|key|password)\s*[:=]\s*['\"][a-zA-Z0-9_\-~.]{30,}['\"]"), 0.85),

    # ── Payment ──────────────────────────────────────────────────────────────
    ("Stripe Secret Key",         re.compile(r"sk_(test|live)_[a-zA-Z0-9]{24,}"), 0.99),
    ("Stripe Publishable Key",    re.compile(r"pk_(test|live)_[a-zA-Z0-9]{24,}"), 0.95),
    ("Stripe Webhook Secret",     re.compile(r"whsec_[a-zA-Z0-9]{32,}"), 0.99),
    ("PayPal Client Secret",      re.compile(r"(?i)paypal.{0,20}secret\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"), 0.85),
    ("Square Access Token",       re.compile(r"sq0atp-[a-zA-Z0-9\-_]{22}"), 0.99),
    ("Square OAuth Secret",       re.compile(r"sq0csp-[a-zA-Z0-9\-_]{43}"), 0.99),

    # ── Source control ───────────────────────────────────────────────────────
    ("GitHub Personal Token",     re.compile(r"ghp_[a-zA-Z0-9]{30,}"), 0.99),
    ("GitHub OAuth Token",        re.compile(r"gho_[a-zA-Z0-9]{30,}"), 0.99),
    ("GitHub App Token",          re.compile(r"(ghu|ghs|ghr)_[a-zA-Z0-9]{30,}"), 0.99),
    ("GitHub Actions Token",      re.compile(r"ghsa-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}"), 0.95),
    ("GitLab Token",              re.compile(r"glpat-[a-zA-Z0-9\-_]{20}"), 0.99),
    ("npm Token",                 re.compile(r"npm_[a-zA-Z0-9]{36}"), 0.99),

    # ── AI / LLM ─────────────────────────────────────────────────────────────
    ("OpenAI API Key",            re.compile(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"), 0.99),
    ("OpenAI API Key (new)",      re.compile(r"sk-proj-[a-zA-Z0-9\-_]{50,}"), 0.99),
    ("OpenRouter API Key",        re.compile(r"sk-or-v1-[a-zA-Z0-9]{64}"), 0.99),
    ("Anthropic API Key",         re.compile(r"sk-ant-[a-zA-Z0-9\-_]{95}"), 0.99),
    ("Hugging Face Token",        re.compile(r"hf_[a-zA-Z0-9]{34}"), 0.99),
    ("Replicate API Token",       re.compile(r"r8_[a-zA-Z0-9]{40}"), 0.97),
    ("Cohere API Key",            re.compile(r"(?i)cohere.{0,10}['\"][a-zA-Z0-9]{40}['\"]"), 0.85),

    # ── Communication ────────────────────────────────────────────────────────
    ("Slack Bot Token",           re.compile(r"xoxb-[0-9]{8,}-[0-9]{8,}-[a-zA-Z0-9]{16,}"), 0.99),
    ("Slack User Token",          re.compile(r"xoxp-[0-9]{8,}-[0-9]{8,}-[0-9]{8,}-[a-zA-Z0-9]{16,}"), 0.99),
    ("Slack Webhook URL",         re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{16,}"), 0.99),
    ("Discord Bot Token",         re.compile(r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}"), 0.90),
    ("Discord Webhook",           re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,}"), 0.99),
    ("Twilio Account SID",        re.compile(r"AC[a-f0-9]{32}"), 0.90),
    # Twilio API Key SID must appear next to a Twilio-context keyword to avoid
    # false-positives on webpack chunk hashes and minified variable names
    ("Twilio API Key SID",        re.compile(r"(?i)twilio.{0,60}SK[a-f0-9]{32}|SK[a-f0-9]{32}.{0,60}twilio"), 0.90),
    ("SendGrid API Key",          re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"), 0.99),
    ("Mailgun API Key",           re.compile(r"key-[a-f0-9]{32}"), 0.92),
    ("Mailchimp API Key",         re.compile(r"(?i)mailchimp.{0,30}[a-f0-9]{32}-us[0-9]{1,2}|[a-f0-9]{32}-us[0-9]{1,2}.{0,30}mailchimp"), 0.90),
    ("Postmark Server Token",     re.compile(r"(?i)postmark.{0,10}['\"][a-zA-Z0-9\-]{36}['\"]"), 0.85),

    # ── Infrastructure / DevOps ───────────────────────────────────────────────
    ("Heroku API Key",            re.compile(r"(?i)heroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]"), 0.90),
    ("Cloudflare API Token",      re.compile(r"(?i)cloudflare.{0,10}['\"][a-zA-Z0-9_\-]{40}['\"]"), 0.85),
    ("Cloudflare Global API Key", re.compile(r"(?i)cf.{0,10}(api[_\-]?key|global).{0,10}['\"][a-f0-9]{37}['\"]"), 0.90),
    ("Vercel Token",              re.compile(r"(?i)vercel.{0,10}['\"][a-zA-Z0-9]{24}['\"]"), 0.80),
    ("Netlify Token",             re.compile(r"(?i)netlify.{0,10}['\"][a-zA-Z0-9\-_]{40}['\"]"), 0.80),
    ("Doppler Token",             re.compile(r"dp\.pt\.[a-zA-Z0-9]{40}"), 0.99),
    ("Vault Token",               re.compile(r"hvs\.[a-zA-Z0-9]{24}"), 0.95),
    ("DigitalOcean Token",        re.compile(r"dop_v1_[a-zA-Z0-9]{64}"), 0.99),
    ("Terraform Cloud Token",     re.compile(r"(?i)terraform.{0,10}['\"][a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,}['\"]"), 0.90),

    # ── Databases ────────────────────────────────────────────────────────────
    ("PostgreSQL Connection URL", re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^\s'\"]+"), 0.99),
    ("MySQL Connection URL",      re.compile(r"mysql://[^:]+:[^@]+@[^\s'\"]+"), 0.99),
    ("MongoDB Connection URL",    re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]+"), 0.99),
    ("Redis Connection URL",      re.compile(r"redis(?:s)?://[^:]*:[^@]+@[^\s'\"]+"), 0.99),
    ("Supabase URL + Key",        re.compile(r"https://[a-z]{20}\.supabase\.co"), 0.90),
    ("Supabase Anon Key",         re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), 0.80),
    # Firebase API Key removed — now merged with Google/Firebase API Key above
    ("Firebase DB URL",           re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), 0.90),
    ("PlanetScale Token",         re.compile(r"pscale_tkn_[a-zA-Z0-9_\-]{32}"), 0.99),
    ("Neon DB URL",               re.compile(r"postgres://[^:]+:[^@]+@[a-z0-9\-]+\.neon\.tech/[^\s'\"]+"), 0.99),
    ("CockroachDB URL",           re.compile(r"postgres://[^:]+:[^@]+@[a-z0-9\-]+\.cockroachlabs\.cloud[^\s'\"]+"), 0.99),

    # ── SaaS / Productivity ───────────────────────────────────────────────────
    ("Notion API Key",            re.compile(r"secret_[a-zA-Z0-9]{43}"), 0.99),
    ("Airtable API Key",          re.compile(r"pat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}"), 0.99),
    # Airtable Legacy requires context — "key" + 14 chars matches "keyboardShortcuts"
    ("Airtable Legacy Key",       re.compile(r"(?i)airtable.{0,30}key[a-zA-Z0-9]{14}|key[a-zA-Z0-9]{14}.{0,30}airtable"), 0.88),
    ("Linear API Key",            re.compile(r"lin_api_[a-zA-Z0-9]{30,}"), 0.99),
    ("Shopify Admin Token",       re.compile(r"shpat_[a-fA-F0-9]{32}"), 0.99),
    ("Shopify Storefront Token",  re.compile(r"shpss_[a-fA-F0-9]{32}"), 0.99),
    ("HubSpot API Key",           re.compile(r"(?i)hubspot.{0,10}['\"][a-zA-Z0-9\-]{36}['\"]"), 0.85),
    ("Intercom Token",            re.compile(r"(?i)intercom.{0,10}['\"][a-zA-Z0-9_]{52}['\"]"), 0.85),
    ("Segment Write Key",         re.compile(r"(?i)segment.{0,10}['\"][a-zA-Z0-9]{32}['\"]"), 0.80),
    ("Mixpanel Token",            re.compile(r"(?i)mixpanel.{0,10}['\"][a-f0-9]{32}['\"]"), 0.80),
    ("Amplitude API Key",         re.compile(r"(?i)amplitude.{0,10}['\"][a-f0-9]{32}['\"]"), 0.80),
    ("Datadog API Key",           re.compile(r"(?i)datadog.{0,10}['\"][a-zA-Z0-9]{32}['\"]"), 0.85),
    ("PagerDuty Integration Key", re.compile(r"(?i)pagerduty.{0,10}['\"][a-zA-Z0-9+]{32}['\"]"), 0.85),
    ("Sentry DSN",                re.compile(r"https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+"), 0.99),

    # ── Auth / Identity ───────────────────────────────────────────────────────
    ("JWT Token",                 re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"), 0.85),
    ("Bearer Token",              re.compile(r"Bearer\s+[a-zA-Z0-9\-_.]{20,}"), 0.75),
    ("Basic Auth in URL",         re.compile(r"https?://[^:@\s]+:[^:@\s]+@[^\s'\"]+"), 0.95),
    ("Auth0 Client Secret",       re.compile(r"(?i)auth0.{0,20}(client_?secret|secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{32,}['\"]"), 0.90),
    # Okta tokens start with 00 but require a Twilio/Okta context to avoid
    # matching zero-padded numbers, CSS padding values and minified identifiers
    ("Okta API Token",            re.compile(r"(?i)okta.{0,40}00[a-zA-Z0-9\-_]{38}|00[a-zA-Z0-9\-_]{38}.{0,40}okta"), 0.88),
    ("Clerk Secret Key",          re.compile(r"sk_(?:test|live)_[a-zA-Z0-9]{40,}"), 0.90),

    # ── Crypto / Blockchain ───────────────────────────────────────────────────
    ("Private Key PEM",           re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.99),
    ("Ethereum Private Key",      re.compile(r"(?i)(eth|ethereum).{0,20}(private[_-]?key|pk)\s*[:=]\s*['\"]0x[a-fA-F0-9]{64}['\"]"), 0.95),
    ("Mnemonic Phrase",           re.compile(r"(?i)(mnemonic|seed.?phrase)\s*[:=]\s*['\"][a-z]+(?: [a-z]+){11,23}['\"]"), 0.90),

    # ── Generic high-confidence patterns ─────────────────────────────────────
    ("Generic API Key",           re.compile(r"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]"), 0.75),
    ("Hardcoded Password",        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), 0.70),
    ("Private IPv4 Address",      re.compile(r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}"), 0.60),
    ("Internal Hostname",         re.compile(r"(?i)(internal|intra|corp|dev|staging|prod)[a-z0-9\-]*\.(internal|local|corp|lan)"), 0.65),
]

# Load and append learned patterns discovered by LLM
_SECRET_PATTERNS.extend(_load_learned_patterns())


async def _fetch_and_scan_bundles(scripts: list[str], base_url: str, state: "ScanState") -> list:
    """
    Fetch the actual content of up to 8 JS bundle files and scan them.
    Bundles are where secrets most commonly leak in production apps.
    For every match, call the live verifier before adding to results.
    Track fix_location with line context.
    """
    import httpx
    from scanner.verify import verify_secret

    src_urls = [s[4:] for s in scripts if s.startswith("src:") and s.endswith(".js")]
    parsed_base = urlparse(base_url)
    same_origin = [u for u in src_urls if urlparse(u).netloc == parsed_base.netloc]
    cross_origin = [u for u in src_urls if urlparse(u).netloc != parsed_base.netloc]
    ordered = same_origin[:6] + cross_origin[:2]

    found = []
    seen: set[str] = set()

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for url in ordered:
            try:
                resp = await client.get(url, headers={"Accept": "*/*"})
                if resp.status_code != 200:
                    continue
                content = resp.text
                lines = content.split("\n")
                await state.log("info", f"Scanning bundle: {url.split('/')[-1]} ({len(content)//1024}KB)")

                for name, pattern, confidence in _SECRET_PATTERNS:
                    for match in pattern.finditer(content):
                        raw_value = match.group(0)
                        preview = raw_value[:60]
                        redacted = preview[:6] + "***" + preview[-3:] if len(preview) > 10 else "***"
                        key = f"{name}:{url}:{match.start()}"
                        if key not in seen:
                            seen.add(key)
                            filename = url.split("/")[-1].split("?")[0]

                            # Find line number and context
                            pos = match.start()
                            line_num = content[:pos].count("\n") + 1
                            line_start = max(0, line_num - 2)
                            line_end = min(len(lines), line_num + 1)
                            context_lines = lines[line_start:line_end]
                            context = "\n".join(context_lines[:3])  # Max 3 lines
                            fix_loc = f"bundle:{filename}:line {line_num} — {context[:100]}"

                            # Live verification
                            vr = await verify_secret(name, raw_value)
                            if vr.status == "invalid":
                                await state.log("info", f"  ↳ {name} at {filename} — invalid (skipping)")
                                continue  # confirmed false positive — don't report
                            if vr.status == "confirmed":
                                await state.log("warn", f"  ↳ CONFIRMED LIVE: {name} at {filename} — {vr.detail}")
                            else:
                                await state.log("info", f"  ↳ {name} at {filename} — {vr.status}")

                            finding = SecretFinding(
                                pattern_name=name,
                                location=f"bundle:{filename}",
                                value_preview=redacted,
                                confidence=confidence,
                                verified=vr.status == "confirmed",
                                verification_status=vr.status,
                                verification_detail=vr.detail,
                                account_info=vr.account_info,
                            )
                            # Store fix_location in verification_detail for now (will be extracted in analysis)
                            finding.verification_detail = f"{vr.detail} | fix_location: {fix_loc}"
                            found.append(finding)
            except Exception:
                pass

    return found


def _find_secrets_in_scripts(scripts: list[str]) -> list[tuple]:
    """
    Returns list of (SecretFinding, raw_value) tuples.
    raw_value is used by _verify_batch — never stored or logged.
    """
    found: list[tuple] = []
    seen: set[str] = set()

    for script in scripts:
        if script.startswith("src:"):
            continue
        elif script.startswith("inline:"):
            location = "inline-script"
            content = script[7:]
        elif script.startswith("window:") or script.startswith("window-global:"):
            parts = script.split(":", 2)
            location = f"window.{parts[1]}"
            content = parts[2] if len(parts) > 2 else ""
        elif script.startswith("meta:"):
            parts = script.split(":", 2)
            location = f"<meta name={parts[1]}>"
            content = parts[2] if len(parts) > 2 else ""
        elif script.startswith("data-attr:"):
            parts = script.split(":", 2)
            location = f"data-attr:{parts[1]}"
            content = parts[2] if len(parts) > 2 else ""
        else:
            location = "unknown"
            content = script

        for name, pattern, confidence in _SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                raw_value = match.group(0)
                preview = raw_value[:60]
                redacted = preview[:6] + "***" + preview[-3:] if len(preview) > 10 else "***"
                key = f"{name}:{location[:80]}"
                if key not in seen:
                    seen.add(key)
                    found.append((
                        SecretFinding(
                            pattern_name=name,
                            location=location,
                            value_preview=redacted,
                            confidence=confidence,
                        ),
                        raw_value,
                    ))
    return found


def _find_secrets_in_storage(storage_data: dict) -> list[tuple]:
    """Returns list of (SecretFinding, raw_value) tuples."""
    found: list[tuple] = []
    seen: set[str] = set()

    sensitive_keys = re.compile(
        r"(?i)(token|secret|key|auth|password|passwd|pwd|credential|jwt|session|api|private|supabase|firebase|stripe|openai|claude|anthropic)"
    )
    all_items = [
        ("localStorage", i) for i in storage_data.get("local", [])
    ] + [
        ("sessionStorage", i) for i in storage_data.get("session", [])
    ]

    for store_type, item in all_items:
        key = item.get("key", "")
        val = item.get("value", "")

        if sensitive_keys.search(key) and len(val) > 8:
            dedup = f"SensitiveKey:{store_type}:{key}"
            if dedup not in seen:
                seen.add(dedup)
                redacted = val[:6] + "***" if len(val) > 9 else "***"
                found.append((
                    SecretFinding(
                        pattern_name="Sensitive Storage Key",
                        location=f"{store_type}:{key}",
                        value_preview=redacted,
                        confidence=0.70,
                    ),
                    val,
                ))

        for name, pattern, confidence in _SECRET_PATTERNS:
            match = pattern.search(val)
            if match:
                raw_value = match.group(0)
                preview = raw_value[:60]
                redacted = preview[:6] + "***" + preview[-3:] if len(preview) > 10 else "***"
                dedup = f"{name}:{store_type}:{key}"
                if dedup not in seen:
                    seen.add(dedup)
                    found.append((
                        SecretFinding(
                            pattern_name=name,
                            location=f"{store_type}:{key}",
                            value_preview=redacted,
                            confidence=confidence,
                        ),
                        raw_value,
                    ))
                break

    return found




async def _verify_batch(findings_raw: list[tuple], state: "ScanState") -> list[SecretFinding]:
    """
    Single unified pipeline for every secret found:

    Step 1 — Live API call via registered verifier
             confirmed → CRITICAL, add to report with account info
             invalid   → DROP (confirmed false positive)
             unverifiable | error → Step 2

    Step 2 — LLM judge: gets pattern name, preview, location,
             raw value snippet AND the API response snippet
             is_false_positive → DROP
             otherwise → keep with status="llm_likely_real"
    """
    from scanner.verify import verify_secret
    from scanner.ai import llm_judge_secret
    results: list[SecretFinding] = []

    for finding, raw_value in findings_raw:

        # ── Step 1: hit the actual service ──────────────────────────────────
        vr = await verify_secret(finding.pattern_name, raw_value)

        if vr.status == "invalid":
            await state.log("info",
                f"  ↳ DROPPED ({finding.pattern_name} @ {finding.location}): {vr.detail}")
            continue  # confirmed dead — don't report

        if vr.status == "confirmed":
            await state.log("warn",
                f"  ↳ ⚠ CONFIRMED LIVE: {finding.pattern_name} @ {finding.location} — {vr.detail}")
            finding.verified = True
            finding.verification_status = "confirmed"
            finding.verification_detail = vr.detail
            finding.account_info = vr.account_info
            results.append(finding)
            continue

        # ── Step 2: LLM judge for everything unverifiable/error ─────────────
        await state.log("info",
            f"  ↳ LLM judging {finding.pattern_name} @ {finding.location} ...")

        llm = await llm_judge_secret(
            pattern_name=finding.pattern_name,
            value_preview=finding.value_preview,
            location=finding.location,
            context_snippet=raw_value[:200],
            api_response=vr.raw_response,   # give LLM what the service actually returned
        )

        if llm.is_false_positive:
            await state.log("info",
                f"  ↳ LLM: false positive — {llm.reasoning}")
            continue  # LLM says noise — don't report

        await state.log("info",
            f"  ↳ LLM: likely real — {llm.reasoning}")

        finding.verified = False
        finding.verification_status = "llm_likely_real"
        finding.verification_detail = (
            f"LLM ({int(llm.confidence*100)}% confidence): {llm.reasoning}"
        )
        finding.account_info = vr.account_info
        results.append(finding)

    return results
