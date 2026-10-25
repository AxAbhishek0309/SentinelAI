"""
Security analysis layer.

Takes raw browser-collected data and produces:
  - List[Finding]  — structured vulnerability findings
  - score: int     — 0-100 security score
  - grade: str     — letter grade
  - headers: List[SecurityHeader]
  - cookies: List[CookieItem]
  - storage: List[StorageItem]
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from models import (
    CookieItem,
    Finding,
    FindingCategory,
    SecurityHeader,
    Severity,
    StorageItem,
)

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

HEADER_DEFINITIONS = [
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "required": True,
        "recommendation": "Add a strict CSP to prevent XSS. Example: default-src 'self'; script-src 'self' 'nonce-{random}'",
    },
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "required": True,
        "recommendation": "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "required": True,
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "required": True,
        "recommendation": "Set X-Content-Type-Options: nosniff",
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "required": False,
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "required": False,
        "recommendation": "Set Permissions-Policy to restrict camera, microphone, geolocation etc.",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "required": False,
        "recommendation": "Set Cross-Origin-Opener-Policy: same-origin",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "key": "cross-origin-resource-policy",
        "required": False,
        "recommendation": "Set Cross-Origin-Resource-Policy: same-origin",
    },
]

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def analyse(raw: dict, target_url: str) -> tuple[
    list[Finding],
    int,
    str,
    list[SecurityHeader],
    list[CookieItem],
    list[StorageItem],
]:
    findings: list[Finding] = []

    # Use root page headers
    root_headers = raw["response_headers_map"].get(target_url, {})
    # Normalise keys to lowercase
    root_headers = {k.lower(): v for k, v in root_headers.items()}

    parsed_headers, header_findings = _analyse_headers(root_headers, target_url, raw["is_https"])
    findings.extend(header_findings)

    cookie_items, cookie_findings = _analyse_cookies(raw["cookies_raw"])
    findings.extend(cookie_findings)

    storage_items, storage_findings = _analyse_storage(raw["storage_data"])
    findings.extend(storage_findings)

    network_findings = _analyse_network(raw["requests"], target_url)
    findings.extend(network_findings)

    cors_findings = _analyse_cors(raw["requests"], root_headers, target_url)
    findings.extend(cors_findings)

    secret_findings = _findings_from_secrets(raw["secrets"])
    findings.extend(secret_findings)

    tls_findings = _analyse_tls(target_url, root_headers)
    findings.extend(tls_findings)

    csp_detail_findings = _analyse_csp(root_headers)
    findings.extend(csp_detail_findings)

    score = _calculate_score(findings, raw["is_https"])
    grade = _score_to_grade(score)

    return findings, score, grade, parsed_headers, cookie_items, storage_items


# ---------------------------------------------------------------------------
# Header analysis
# ---------------------------------------------------------------------------

def _analyse_headers(
    headers: dict[str, str], target_url: str, is_https: bool
) -> tuple[list[SecurityHeader], list[Finding]]:
    parsed: list[SecurityHeader] = []
    findings: list[Finding] = []

    for defn in HEADER_DEFINITIONS:
        key = defn["key"]
        value = headers.get(key)
        present = value is not None

        # Grade the header
        if not present:
            grade = "F" if defn["required"] else "C"
        else:
            grade = _grade_header_value(key, value)

        parsed.append(SecurityHeader(
            name=defn["name"],
            present=present,
            value=value,
            grade=grade,
            recommendation=defn["recommendation"] if not present or grade in ("C", "D", "F") else None,
        ))

        if not present and defn["required"]:
            severity = Severity.high if key in (
                "content-security-policy", "strict-transport-security"
            ) else Severity.medium

            findings.append(Finding(
                category=FindingCategory.header,
                severity=severity,
                title=f"Missing {defn['name']} header",
                description=f"The {defn['name']} header is not set on the root page. This leaves users exposed to attacks.",
                location=target_url,
                evidence=f"Response headers did not include {defn['name']}",
                recommendation=defn["recommendation"],
                references=_header_references(key),
            ))
        elif present and grade in ("C", "D", "F"):
            findings.append(Finding(
                category=FindingCategory.header,
                severity=Severity.medium,
                title=f"Weak {defn['name']} configuration",
                description=f"The {defn['name']} header is present but its value may not provide adequate protection.",
                location=target_url,
                evidence=f"{defn['name']}: {value}",
                recommendation=defn["recommendation"],
                references=_header_references(key),
            ))

    return parsed, findings


def _grade_header_value(key: str, value: str) -> str:
    v = value.lower()
    if key == "content-security-policy":
        # Weak: uses unsafe-inline or unsafe-eval without nonce/hash
        if "unsafe-inline" in v and "nonce-" not in v and "'sha" not in v:
            return "C"
        if "unsafe-eval" in v:
            return "D"
        if "default-src" not in v and "script-src" not in v:
            return "C"
        return "A"
    if key == "strict-transport-security":
        if "max-age=0" in v:
            return "F"
        if "preload" in v and "includesubdomains" in v:
            return "A"
        if "includesubdomains" in v:
            return "B"
        return "C"
    if key == "x-frame-options":
        if v in ("deny", "sameorigin"):
            return "A"
        return "C"
    if key == "x-content-type-options":
        return "A" if v == "nosniff" else "C"
    if key == "referrer-policy":
        safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
        if v in safe:
            return "A"
        if "unsafe-url" in v or "no-referrer-when-downgrade" in v:
            return "D"
        return "B"
    return "B"


def _header_references(key: str) -> list[str]:
    base = {
        "content-security-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "strict-transport-security": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "x-frame-options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "x-content-type-options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "referrer-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        "permissions-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    }
    url = base.get(key)
    refs = ["https://owasp.org/www-project-secure-headers/"]
    if url:
        refs.insert(0, url)
    return refs


# ---------------------------------------------------------------------------
# CSP deep analysis
# ---------------------------------------------------------------------------

def _analyse_csp(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy", "")
    if not csp:
        return findings  # already reported as missing

    v = csp.lower()

    if "unsafe-eval" in v:
        findings.append(Finding(
            category=FindingCategory.csp,
            severity=Severity.high,
            title="CSP allows unsafe-eval",
            description="'unsafe-eval' in CSP allows JavaScript eval(), which can be exploited for XSS via injection into eval-adjacent sinks.",
            location="Content-Security-Policy header",
            evidence=csp[:200],
            recommendation="Remove 'unsafe-eval'. Use safer alternatives like JSON.parse() instead of eval().",
            references=["https://content-security-policy.com/unsafe-eval/"],
        ))

    if "unsafe-inline" in v and "nonce-" not in v and "'sha" not in v:
        findings.append(Finding(
            category=FindingCategory.csp,
            severity=Severity.high,
            title="CSP allows unsafe-inline without nonces",
            description="'unsafe-inline' without nonces negates most XSS protection provided by CSP.",
            location="Content-Security-Policy header",
            evidence=csp[:200],
            recommendation="Replace 'unsafe-inline' with per-request nonces: script-src 'nonce-{random}'",
            references=["https://content-security-policy.com/unsafe-inline/"],
        ))

    if re.search(r"script-src[^;]*\*", csp):
        findings.append(Finding(
            category=FindingCategory.csp,
            severity=Severity.medium,
            title="CSP script-src uses wildcard",
            description="A wildcard (*) in script-src allows scripts from any origin, undermining XSS protection.",
            location="Content-Security-Policy header",
            evidence=csp[:200],
            recommendation="Replace wildcard with explicit trusted origins.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        ))

    return findings


# ---------------------------------------------------------------------------
# CORS analysis
# ---------------------------------------------------------------------------

def _analyse_cors(requests: list, root_headers: dict[str, str], target_url: str) -> list[Finding]:
    findings: list[Finding] = []

    # Check root page response headers for CORS wildcard
    acao = root_headers.get("access-control-allow-origin", "")
    acac = root_headers.get("access-control-allow-credentials", "")

    if acao == "*":
        severity = Severity.critical if acac.lower() == "true" else Severity.high
        findings.append(Finding(
            category=FindingCategory.cors,
            severity=severity,
            title="Overly permissive CORS policy: Access-Control-Allow-Origin: *",
            description=(
                "The server allows cross-origin requests from any domain. "
                + ("Combined with Access-Control-Allow-Credentials: true, this is a critical misconfiguration that allows any site to make authenticated requests on behalf of the user. "
                   if acac.lower() == "true" else
                   "Any website can read responses from this API.")
            ),
            location=target_url,
            evidence=f"Access-Control-Allow-Origin: {acao}" + (f"\nAccess-Control-Allow-Credentials: {acac}" if acac else ""),
            recommendation=(
                "Replace wildcard with a specific allowed origin. "
                "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — browsers block this."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
            ],
        ))

    # Check individual requests for CORS wildcards on API endpoints
    cors_wildcard_apis = [
        r for r in requests
        if r.flagged and r.flag_reason == "CORS: Access-Control-Allow-Origin: *"
        and "/api/" in r.url.lower()
    ]
    if cors_wildcard_apis and acao != "*":  # avoid duplicate
        findings.append(Finding(
            category=FindingCategory.cors,
            severity=Severity.high,
            title=f"CORS wildcard on {len(cors_wildcard_apis)} API endpoint(s)",
            description="One or more API endpoints return Access-Control-Allow-Origin: * allowing any website to read their responses.",
            location="\n".join(r.url for r in cors_wildcard_apis[:3]),
            evidence=f"Example: {cors_wildcard_apis[0].url}",
            recommendation="Restrict CORS to known trusted origins only.",
            references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"],
        ))

    return findings


# ---------------------------------------------------------------------------

def _analyse_cookies(raw_cookies: list[dict]) -> tuple[list[CookieItem], list[Finding]]:
    items: list[CookieItem] = []
    findings: list[Finding] = []

    sensitive_name_pattern = re.compile(
        r"(?i)(session|auth|token|jwt|sid|identity|login|remember|csrf|xsrf)"
    )

    for c in raw_cookies:
        name = c.get("name", "")
        secure = c.get("secure", False)
        http_only = c.get("httpOnly", False)
        same_site = c.get("sameSite", None)
        domain = c.get("domain", "")
        path = c.get("path", "/")
        expires = c.get("expires", -1)

        issues: list[str] = []

        is_sensitive = bool(sensitive_name_pattern.search(name))

        if not secure:
            issues.append("Missing Secure flag — cookie transmitted over HTTP")
        if not http_only and is_sensitive:
            issues.append("Missing HttpOnly flag — accessible via JavaScript")
        if same_site in (None, "", "None") and not secure:
            issues.append("SameSite=None without Secure flag — CSRF risk")
        if same_site == "None" and secure:
            issues.append("SameSite=None — sent on all cross-site requests")

        items.append(CookieItem(
            name=name,
            domain=domain,
            path=path,
            secure=secure,
            http_only=http_only,
            same_site=same_site,
            session=expires == -1,
            issues=issues,
        ))

        if is_sensitive and not http_only:
            findings.append(Finding(
                category=FindingCategory.cookie,
                severity=Severity.high,
                title=f"Sensitive cookie '{name}' missing HttpOnly flag",
                description=f"The cookie '{name}' appears to be a session/auth cookie but is accessible via JavaScript. This enables session theft if XSS is present.",
                location=f"Cookie: {name}",
                evidence=f"Set-Cookie: {name}; HttpOnly not present",
                recommendation=f"Add HttpOnly flag: Set-Cookie: {name}=...; HttpOnly; Secure; SameSite=Strict",
                references=["https://owasp.org/www-community/HttpOnly"],
            ))

        if is_sensitive and not secure:
            findings.append(Finding(
                category=FindingCategory.cookie,
                severity=Severity.high,
                title=f"Sensitive cookie '{name}' missing Secure flag",
                description=f"The cookie '{name}' can be transmitted over plain HTTP connections, exposing it to network interception.",
                location=f"Cookie: {name}",
                evidence=f"Set-Cookie: {name}; Secure not present",
                recommendation=f"Add Secure flag: Set-Cookie: {name}=...; Secure; HttpOnly",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
            ))

        if same_site in (None, "") and is_sensitive:
            findings.append(Finding(
                category=FindingCategory.cookie,
                severity=Severity.medium,
                title=f"Cookie '{name}' missing SameSite attribute",
                description="Without SameSite, this cookie is sent with cross-site requests, creating CSRF risk.",
                location=f"Cookie: {name}",
                evidence=f"Set-Cookie: {name}; SameSite not set",
                recommendation="Add SameSite=Strict or SameSite=Lax to reduce CSRF exposure.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute"],
            ))

    return items, findings


# ---------------------------------------------------------------------------
# Storage analysis
# ---------------------------------------------------------------------------

def _analyse_storage(storage_data: dict) -> tuple[list[StorageItem], list[Finding]]:
    items: list[StorageItem] = []
    findings: list[Finding] = []

    sensitive_key_re = re.compile(
        r"(?i)(token|secret|key|auth|password|passwd|pwd|credential|jwt|session|api|private)"
    )

    for store_type, entries in [
        ("localStorage", storage_data.get("local", [])),
        ("sessionStorage", storage_data.get("session", [])),
    ]:
        for entry in entries:
            key = entry.get("key", "")
            value = entry.get("value", "")
            flagged = bool(sensitive_key_re.search(key))
            flag_reason = "Potentially sensitive key name" if flagged else None

            items.append(StorageItem(
                key=key,
                value_preview=value[:80] + ("…" if len(value) > 80 else ""),
                storage_type=store_type,
                flagged=flagged,
                flag_reason=flag_reason,
            ))

            if flagged and store_type == "localStorage":
                findings.append(Finding(
                    category=FindingCategory.storage,
                    severity=Severity.high,
                    title=f"Sensitive data in localStorage: '{key}'",
                    description=(
                        f"localStorage is accessible to any JavaScript on the page domain. "
                        f"Storing '{key}' here exposes it to XSS-based theft."
                    ),
                    location=f"localStorage:{key}",
                    evidence=f"localStorage key '{key}' contains value of length {len(value)}",
                    recommendation=(
                        "Store tokens in HttpOnly cookies instead of localStorage. "
                        "If localStorage is required, ensure robust CSP prevents XSS."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
                    ],
                ))

    return items, findings


# ---------------------------------------------------------------------------
# Network analysis
# ---------------------------------------------------------------------------

def _analyse_network(requests: list, target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    is_https = target_url.startswith("https://")

    # Mixed content
    mixed = [r for r in requests if r.flagged and r.flag_reason == "Insecure HTTP resource"]
    if mixed:
        findings.append(Finding(
            category=FindingCategory.mixed_content,
            severity=Severity.medium,
            title=f"Mixed content detected ({len(mixed)} HTTP resource(s) on HTTPS page)",
            description="HTTP resources loaded on an HTTPS page can be intercepted and modified by MITM attackers.",
            location="\n".join(r.url for r in mixed[:5]),
            evidence=f"{len(mixed)} insecure resource(s) detected: {mixed[0].url}",
            recommendation="Serve all resources over HTTPS. Update hardcoded HTTP URLs.",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
        ))

    # Sensitive paths accessible
    sensitive = [r for r in requests if r.flagged and r.flag_reason and "Sensitive path" in r.flag_reason]
    for r in sensitive[:5]:
        findings.append(Finding(
            category=FindingCategory.network,
            severity=Severity.high,
            title=f"Sensitive path accessible: {r.url.split('?')[0][-60:]}",
            description=f"The path '{r.url}' returned HTTP {r.status} and may expose configuration or sensitive data.",
            location=r.url,
            evidence=f"{r.method} {r.url} → {r.status}",
            recommendation="Restrict access to sensitive paths. Return 403/404 for config files from the internet.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    # CORS issues — look for Access-Control-Allow-Origin: *
    # (we detect this from response headers map in the engine layer but flag here)
    # Check for API auth failures
    api_failures = [r for r in requests if r.flagged and r.flag_reason and "API auth" in r.flag_reason]
    if api_failures:
        findings.append(Finding(
            category=FindingCategory.network,
            severity=Severity.info,
            title=f"{len(api_failures)} API endpoint(s) returning authentication errors",
            description="API endpoints returned 401/403, which may indicate insufficient access control or exposed endpoints.",
            location="\n".join(r.url for r in api_failures[:3]),
            evidence=f"Example: {api_failures[0].method} {api_failures[0].url} → {api_failures[0].status}",
            recommendation="Verify these endpoints require and enforce authentication. Ensure error messages don't leak stack traces.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
        ))

    return findings


# ---------------------------------------------------------------------------
# TLS analysis
# ---------------------------------------------------------------------------

def _analyse_tls(target_url: str, headers: dict) -> list[Finding]:
    findings: list[Finding] = []

    if not target_url.startswith("https://"):
        findings.append(Finding(
            category=FindingCategory.tls,
            severity=Severity.critical,
            title="Site not served over HTTPS",
            description="The target URL uses plain HTTP. All traffic is transmitted in cleartext and is vulnerable to interception and modification.",
            location=target_url,
            evidence=f"URL scheme: http://",
            recommendation="Obtain a TLS certificate (Let's Encrypt is free) and redirect all HTTP traffic to HTTPS.",
            references=[
                "https://letsencrypt.org/",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            ],
        ))

    hsts = headers.get("strict-transport-security", "")
    if target_url.startswith("https://") and not hsts:
        findings.append(Finding(
            category=FindingCategory.tls,
            severity=Severity.medium,
            title="HSTS not enabled",
            description="HTTPS is used but Strict-Transport-Security is missing. Browsers won't enforce HTTPS-only connections, leaving users vulnerable to SSL stripping.",
            location=target_url,
            evidence="No Strict-Transport-Security header in response",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        ))

    return findings


# ---------------------------------------------------------------------------
# Findings from secrets
# ---------------------------------------------------------------------------

def _findings_from_secrets(secrets: list) -> list[Finding]:
    findings: list[Finding] = []
    for s in secrets:
        # Extract fix_location from verification_detail if present
        fix_loc = None
        detail = s.verification_detail
        if " | fix_location: " in detail:
            parts = detail.split(" | fix_location: ", 1)
            detail = parts[0]
            fix_loc = parts[1]
        
        # Confirmed live via API → always critical
        # LLM says likely real → high
        # Unverifiable pattern match → medium (confidence-weighted)
        if s.verified or s.verification_status == "confirmed":
            severity = Severity.critical
            status_note = f"LIVE credential confirmed — {detail}"
            if s.account_info:
                # Include account info in evidence so the report shows WHO was exposed
                acct = ", ".join(f"{k}: {v}" for k, v in s.account_info.items() if v)
                status_note += f"\nAccount: {acct}"
        elif s.verification_status == "llm_likely_real":
            severity = Severity.high
            status_note = detail
        elif s.confidence >= 0.90:
            severity = Severity.high
            status_note = f"Pattern confidence: {int(s.confidence*100)}%. Verification: {s.verification_status}"
        else:
            severity = Severity.medium
            status_note = f"Pattern confidence: {int(s.confidence*100)}%. Verification: {s.verification_status}"

        findings.append(Finding(
            category=FindingCategory.secret,
            severity=severity,
            title=f"{'⚠ CONFIRMED LIVE' if s.verified else 'Potential'} exposed secret: {s.pattern_name}",
            description=(
                f"A pattern matching '{s.pattern_name}' was found at '{s.location}'. "
                + ("This credential was verified as live and active. " if s.verified else "")
                + "Exposed secrets can lead to account takeover, data breaches, or infrastructure compromise."
            ),
            location=s.location,
            evidence=f"Value preview: {s.value_preview}\nStatus: {status_note}",
            recommendation=(
                "Immediately rotate the exposed credential. "
                "Move secrets to environment variables on the server. "
                "Never embed API keys or tokens in client-side code or storage."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            fix_location=fix_loc,
        ))
    return findings


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

SEVERITY_DEDUCTIONS = {
    Severity.critical: 25,
    Severity.high: 10,
    Severity.medium: 5,
    Severity.low: 2,
    Severity.info: 0,
}


def _calculate_score(findings: list[Finding], is_https: bool) -> int:
    score = 100
    if not is_https:
        score -= 30  # hard penalty

    for f in findings:
        score -= SEVERITY_DEDUCTIONS[f.severity]

    return max(0, min(100, score))


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "A-"
    if score >= 75:
        return "B+"
    if score >= 70:
        return "B"
    if score >= 65:
        return "B-"
    if score >= 55:
        return "C+"
    if score >= 45:
        return "C"
    if score >= 35:
        return "D"
    return "F"
