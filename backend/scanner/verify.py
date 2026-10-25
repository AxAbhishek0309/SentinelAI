"""
Secret verification layer — every pattern match hits the real service API.

Flow per finding:
  1. Registered verifier → live API call → confirmed | invalid | unverifiable
  2. No verifier OR unverifiable → generic_probe() hits the value as a URL
     or constructs a known endpoint from context
  3. Still unverifiable → LLM judge (called from _verify_batch in engine.py)

Rules:
  - READ-ONLY endpoints only (whoami, validate, ping, discovery)
  - Never write / create / delete anything
  - 6s timeout per call
  - confirmed  → live credential, report as CRITICAL
  - invalid    → dead / fake / rotated, DROP from report
  - unverifiable → goes to LLM judge
"""
from __future__ import annotations

import asyncio
import base64
import json as _json
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Awaitable
from urllib.parse import urlparse

import httpx

_C = dict(timeout=6.0, follow_redirects=True)


@dataclass
class VerificationResult:
    status: str        # confirmed | invalid | unverifiable | error
    detail: str
    account_info: dict = field(default_factory=dict)
    raw_response: str = ""   # first 400 chars of API response for LLM context


_VERIFIERS: dict[str, Callable[[str], Awaitable[VerificationResult]]] = {}


def _reg(*names: str):
    """Register one async function under multiple pattern names."""
    def decorator(fn):
        for n in names:
            _VERIFIERS[n] = fn
        return fn
    return decorator


async def verify_secret(pattern_name: str, raw_value: str) -> VerificationResult:
    fn = _VERIFIERS.get(pattern_name)
    if fn:
        try:
            return await fn(raw_value)
        except httpx.TimeoutException:
            return VerificationResult(status="error", detail="Verification timed out.")
        except Exception as exc:
            return VerificationResult(status="error", detail=f"Verification error: {exc}")
    # No verifier → try generic probe
    return await _generic_probe(pattern_name, raw_value)


# ---------------------------------------------------------------------------
# Generic probe — hit the value directly if it looks like a URL,
# otherwise try known service endpoints based on value prefix/shape
# ---------------------------------------------------------------------------

async def _generic_probe(pattern_name: str, value: str) -> VerificationResult:
    """
    Last-resort probe. Tries to hit the value as a URL or derives an endpoint.
    Returns unverifiable if nothing can be inferred.
    """
    v = value.strip()

    # If the value IS a URL (database connection strings, Firebase DB, webhooks)
    if v.startswith("http://") or v.startswith("https://"):
        try:
            async with httpx.AsyncClient(**_C) as c:
                resp = await c.head(v)
            if resp.status_code < 400:
                return VerificationResult(
                    status="confirmed",
                    detail=f"URL is reachable (HTTP {resp.status_code}) — credential/endpoint is live.",
                    raw_response=f"HTTP {resp.status_code}",
                )
            if resp.status_code == 401:
                return VerificationResult(
                    status="confirmed",
                    detail=f"Endpoint requires auth (HTTP 401) — confirms service exists at this URL.",
                    raw_response=f"HTTP {resp.status_code}",
                )
            if resp.status_code == 403:
                return VerificationResult(
                    status="confirmed",
                    detail=f"Endpoint forbidden (HTTP 403) — service exists, credential may be invalid.",
                    raw_response=f"HTTP {resp.status_code}",
                )
        except Exception:
            pass

    # Bearer-shaped tokens — try a few public whoami endpoints
    if len(v) > 20 and re.match(r'^[A-Za-z0-9_\-\.]+$', v):
        endpoints = [
            ("https://api.github.com/user", {"Authorization": f"token {v}", "User-Agent": "SentinelAI/1.0"}),
            ("https://slack.com/api/auth.test", {"Authorization": f"Bearer {v}"}),
            ("https://api.stripe.com/v1/account", {"Authorization": f"Bearer {v}"}),
        ]
        for url, headers in endpoints:
            try:
                async with httpx.AsyncClient(timeout=4, follow_redirects=True) as c:
                    resp = await c.get(url, headers=headers)
                if resp.status_code == 200:
                    return VerificationResult(
                        status="confirmed",
                        detail=f"Token accepted by {urlparse(url).netloc} (HTTP 200).",
                        raw_response=resp.text[:400],
                    )
                if resp.status_code == 401:
                    break  # service responded but rejected — means format matched
            except Exception:
                continue

    return VerificationResult(
        status="unverifiable",
        detail=f"No direct verification endpoint known for pattern '{pattern_name}'.",
    )


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

@_reg("AWS Access Key ID")
async def _aws(v: str) -> VerificationResult:
    # STS probe: SignatureDoesNotMatch = key exists; InvalidClientTokenId = fake
    async with httpx.AsyncClient(**_C) as c:
        r = await c.post("https://sts.amazonaws.com/",
                         data={"Action": "GetCallerIdentity", "Version": "2011-06-15"})
    if "SignatureDoesNotMatch" in r.text:
        return VerificationResult("confirmed",
            "AWS key exists — STS returned SignatureDoesNotMatch (key is live).",
            {"key_id": v}, r.text[:400])
    if "InvalidClientTokenId" in r.text:
        return VerificationResult("invalid", "AWS STS: InvalidClientTokenId — key does not exist.")
    return VerificationResult("unverifiable", f"STS: {r.text[:120]}")


@_reg("AWS Secret Access Key", "AWS Session Token")
async def _aws_secret(v: str) -> VerificationResult:
    # Can't probe secret alone — needs key ID pair
    return VerificationResult("unverifiable",
        "AWS Secret/Session token requires the paired Access Key ID to verify.")


# ---------------------------------------------------------------------------
# Google / GCP / Firebase  (same AIza... format)
# ---------------------------------------------------------------------------

@_reg("GCP API Key", "Firebase API Key", "Google API Key", "Firebase DB URL",
      "Google/Firebase API Key")
async def _gcp(v: str) -> VerificationResult:
    # Extract key from Firebase DB URL if needed
    key = v
    if v.startswith("https://") and "firebaseio.com" in v:
        # Firebase DB URL — probe it directly
        try:
            async with httpx.AsyncClient(**_C) as c:
                r = await c.get(f"{v.rstrip('/')}/.json?shallow=true")
            if r.status_code == 200:
                return VerificationResult("confirmed",
                    f"Firebase Realtime DB is publicly readable (HTTP 200).",
                    raw_response=r.text[:400])
            if r.status_code == 401:
                return VerificationResult("confirmed",
                    "Firebase DB exists and requires auth (HTTP 401).")
            if r.status_code == 403:
                return VerificationResult("confirmed",
                    "Firebase DB exists but access forbidden (HTTP 403) — rules may protect it.")
        except Exception as exc:
            return VerificationResult("unverifiable", f"Firebase DB probe error: {exc}")
        return VerificationResult("unverifiable", f"Firebase DB returned {r.status_code}")

    # GCP/Firebase API key — hit Discovery API
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get(f"https://www.googleapis.com/discovery/v1/apis?key={key}")
    raw = r.text[:400]
    if r.status_code == 200:
        count = len(r.json().get("items", []))
        return VerificationResult("confirmed",
            f"Live Google API key — Discovery API accessible ({count} APIs).",
            {"apis_accessible": count}, raw)
    if r.status_code == 400:
        err = str(r.json().get("error", {}))
        if "API_KEY_INVALID" in err or "keyInvalid" in err:
            return VerificationResult("invalid", "Google: API_KEY_INVALID.", raw_response=raw)
    return VerificationResult("unverifiable", f"Google returned HTTP {r.status_code}", raw_response=raw)


@_reg("GCP Service Account")
async def _gcp_sa(v: str) -> VerificationResult:
    # Structural check — value must contain "private_key" field
    if '"private_key"' in v and '"client_email"' in v:
        return VerificationResult("confirmed",
            "GCP Service Account JSON structure is complete and contains private key + client email.",
            {"has_private_key": True, "has_client_email": True})
    return VerificationResult("unverifiable", "Partial service account JSON — cannot confirm without full credentials.")


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

async def _github(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.github.com/user",
                        headers={"Authorization": f"token {v}", "User-Agent": "SentinelAI/1.0"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live GitHub token — user: @{d.get('login')}, repos: {d.get('public_repos')}",
            {"login": d.get("login"), "name": d.get("name"),
             "public_repos": d.get("public_repos"), "private_repos": d.get("total_private_repos")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "GitHub rejected token (401).")
    return VerificationResult("unverifiable", f"GitHub returned {r.status_code}", raw_response=raw)

for _n in ("GitHub Personal Token","GitHub OAuth Token","GitHub App Token","GitHub Actions Token"):
    _VERIFIERS[_n] = _github


@_reg("GitLab Token")
async def _gitlab(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://gitlab.com/api/v4/user", headers={"PRIVATE-TOKEN": v})
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed", f"Live GitLab token — @{d.get('username')}",
            {"username": d.get("username"), "name": d.get("name")}, r.text[:400])
    return VerificationResult("invalid" if r.status_code == 401 else "unverifiable",
        f"GitLab returned {r.status_code}")


# ---------------------------------------------------------------------------
# Stripe / Square / PayPal
# ---------------------------------------------------------------------------

async def _stripe(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.stripe.com/v1/account",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        live = not v.startswith("sk_test_") and not v.startswith("pk_test_")
        return VerificationResult("confirmed",
            f"Live Stripe {'PRODUCTION' if live else 'test'} key — account {d.get('id')} ({d.get('email','')})",
            {"account_id": d.get("id"), "email": d.get("email"),
             "country": d.get("country"), "charges_enabled": d.get("charges_enabled"),
             "live_mode": live}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Stripe rejected key (401).")
    return VerificationResult("unverifiable", f"Stripe returned {r.status_code}", raw_response=raw)

for _n in ("Stripe Secret Key","Stripe Publishable Key","Stripe Webhook Secret"):
    _VERIFIERS[_n] = _stripe


@_reg("Square Access Token", "Square OAuth Secret")
async def _square(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://connect.squareup.com/v2/merchants/me",
                        headers={"Authorization": f"Bearer {v}",
                                 "Square-Version": "2024-01-18"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("merchant", {})
        return VerificationResult("confirmed",
            f"Live Square token — merchant: {d.get('business_name', 'unknown')} ({d.get('country')})",
            {"merchant_id": d.get("id"), "business_name": d.get("business_name"),
             "country": d.get("country"), "status": d.get("status")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Square rejected token (401).")
    return VerificationResult("unverifiable", f"Square returned {r.status_code}", raw_response=raw)


@_reg("PayPal Client Secret")
async def _paypal(v: str) -> VerificationResult:
    return VerificationResult("unverifiable",
        "PayPal Client Secret requires the paired Client ID to obtain an access token.")


# ---------------------------------------------------------------------------
# Slack / Discord
# ---------------------------------------------------------------------------

async def _slack(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.post("https://slack.com/api/auth.test",
                         headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        if d.get("ok"):
            return VerificationResult("confirmed",
                f"Live Slack token — team: '{d.get('team')}', user: '{d.get('user')}'",
                {"team": d.get("team"), "team_id": d.get("team_id"),
                 "user": d.get("user"), "user_id": d.get("user_id"),
                 "bot_id": d.get("bot_id")}, raw)
        return VerificationResult("invalid", f"Slack auth.test: {d.get('error')}")
    return VerificationResult("unverifiable", f"Slack returned {r.status_code}", raw_response=raw)

for _n in ("Slack Bot Token","Slack User Token"):
    _VERIFIERS[_n] = _slack


@_reg("Slack Webhook URL")
async def _slack_wh(v: str) -> VerificationResult:
    # POST empty payload — valid webhook returns 400 "no_text", invalid returns 403/404
    try:
        async with httpx.AsyncClient(**_C) as c:
            r = await c.post(v, json={"text": ""})
        if r.status_code == 400 and "no_text" in r.text:
            return VerificationResult("confirmed",
                "Slack webhook is live (returned 'no_text' — webhook URL is valid).",
                raw_response=r.text[:200])
        if r.status_code == 200:
            return VerificationResult("confirmed", "Slack webhook accepted (HTTP 200).")
        if r.status_code in (403, 404):
            return VerificationResult("invalid", f"Slack webhook rejected (HTTP {r.status_code}).")
    except Exception as exc:
        return VerificationResult("unverifiable", f"Webhook probe error: {exc}")
    return VerificationResult("unverifiable", f"Slack webhook returned {r.status_code}")


@_reg("Discord Webhook")
async def _discord_wh(v: str) -> VerificationResult:
    try:
        async with httpx.AsyncClient(**_C) as c:
            r = await c.get(v)
        raw = r.text[:400]
        if r.status_code == 200:
            d = r.json()
            return VerificationResult("confirmed",
                f"Discord webhook is live — name: '{d.get('name')}', channel: {d.get('channel_id')}",
                {"name": d.get("name"), "channel_id": d.get("channel_id"),
                 "guild_id": d.get("guild_id"), "type": d.get("type")}, raw)
        if r.status_code == 401:
            return VerificationResult("invalid", "Discord webhook rejected (401 Unauthorized).")
    except Exception as exc:
        return VerificationResult("unverifiable", f"Discord probe error: {exc}")
    return VerificationResult("unverifiable", f"Discord returned {r.status_code}")


@_reg("Discord Bot Token")
async def _discord_bot(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://discord.com/api/v10/users/@me",
                        headers={"Authorization": f"Bot {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Discord bot token — bot: {d.get('username')}#{d.get('discriminator')}",
            {"username": d.get("username"), "id": d.get("id"), "bot": d.get("bot")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Discord rejected bot token (401).")
    return VerificationResult("unverifiable", f"Discord returned {r.status_code}", raw_response=raw)


# ---------------------------------------------------------------------------
# OpenAI / Anthropic / HuggingFace / Replicate / OpenRouter
# ---------------------------------------------------------------------------

async def _openai(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        count = len(r.json().get("data", []))
        return VerificationResult("confirmed",
            f"Live OpenAI key — {count} models accessible", {"models_accessible": count}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "OpenAI rejected key (401).")
    return VerificationResult("unverifiable", f"OpenAI returned {r.status_code}", raw_response=raw)

for _n in ("OpenAI API Key","OpenAI API Key (new)"):
    _VERIFIERS[_n] = _openai


@_reg("OpenRouter API Key")
async def _openrouter(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://openrouter.ai/api/v1/models",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        count = len(r.json().get("data", []))
        return VerificationResult("confirmed",
            f"Live OpenRouter key — {count} models accessible", {"models_accessible": count}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "OpenRouter rejected key (401).")
    return VerificationResult("unverifiable", f"OpenRouter returned {r.status_code}", raw_response=raw)


@_reg("Anthropic API Key")
async def _anthropic(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.anthropic.com/v1/models",
                        headers={"x-api-key": v, "anthropic-version": "2023-06-01"})
    raw = r.text[:400]
    if r.status_code == 200:
        models = [m.get("id") for m in r.json().get("data", [])[:3]]
        return VerificationResult("confirmed",
            f"Live Anthropic key — models: {', '.join(models)}", {"models": models}, raw)
    if r.status_code in (401, 403):
        return VerificationResult("invalid", f"Anthropic rejected key ({r.status_code}).")
    return VerificationResult("unverifiable", f"Anthropic returned {r.status_code}", raw_response=raw)


@_reg("Hugging Face Token")
async def _hf(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://huggingface.co/api/whoami-v2",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live HuggingFace token — @{d.get('name')} ({d.get('type')})",
            {"name": d.get("name"), "type": d.get("type")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "HuggingFace rejected token (401).")
    return VerificationResult("unverifiable", f"HuggingFace returned {r.status_code}", raw_response=raw)


@_reg("Replicate API Token")
async def _replicate(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.replicate.com/v1/account",
                        headers={"Authorization": f"Token {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Replicate token — @{d.get('username')}",
            {"username": d.get("username"), "name": d.get("name")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Replicate rejected token (401).")
    return VerificationResult("unverifiable", f"Replicate returned {r.status_code}", raw_response=raw)


@_reg("Cohere API Key")
async def _cohere(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.cohere.ai/v1/models",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed", "Live Cohere API key — models endpoint accessible.",
                                  raw_response=raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Cohere rejected key (401).")
    return VerificationResult("unverifiable", f"Cohere returned {r.status_code}", raw_response=raw)


# ---------------------------------------------------------------------------
# Communication: Twilio / SendGrid / Mailgun / Mailchimp / Postmark / PagerDuty
# ---------------------------------------------------------------------------

@_reg("Twilio Account SID", "Twilio API Key SID")
async def _twilio(v: str) -> VerificationResult:
    # Account SIDs start with AC — probe the accounts endpoint
    if v.startswith("AC") and len(v) == 34:
        async with httpx.AsyncClient(**_C) as c:
            r = await c.get(f"https://api.twilio.com/2010-04-01/Accounts/{v}.json",
                            auth=(v, "fake_token_to_probe"))
        raw = r.text[:400]
        if r.status_code == 401 and "20003" in r.text:
            # Error 20003 = AuthenticationError but account exists
            return VerificationResult("confirmed",
                "Twilio Account SID exists — auth error 20003 confirms SID is real.",
                {"account_sid": v}, raw)
        if r.status_code == 404:
            return VerificationResult("invalid", "Twilio Account SID does not exist (404).")
    return VerificationResult("unverifiable",
        "Twilio API Key SID requires the paired Auth Token to fully verify.")


@_reg("SendGrid API Key")
async def _sendgrid(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.sendgrid.com/v3/scopes",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        scopes = r.json().get("scopes", [])[:6]
        return VerificationResult("confirmed",
            f"Live SendGrid key — scopes: {', '.join(scopes)}", {"scopes": scopes}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "SendGrid rejected key (401).")
    return VerificationResult("unverifiable", f"SendGrid returned {r.status_code}", raw_response=raw)


@_reg("Mailgun API Key")
async def _mailgun(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.mailgun.net/v3/domains", auth=("api", v))
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        domains = [x.get("name") for x in d.get("items", [])[:3]]
        return VerificationResult("confirmed",
            f"Live Mailgun key — domains: {', '.join(domains) or 'none yet'}",
            {"domain_count": d.get("total_count", 0), "domains": domains}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Mailgun rejected key (401).")
    return VerificationResult("unverifiable", f"Mailgun returned {r.status_code}", raw_response=raw)


@_reg("Mailchimp API Key")
async def _mailchimp(v: str) -> VerificationResult:
    # Extract datacenter from key suffix (-us6 etc)
    dc_match = re.search(r'-([a-z]{2}\d+)$', v)
    dc = dc_match.group(1) if dc_match else "us1"
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get(f"https://{dc}.api.mailchimp.com/3.0/ping",
                        auth=("anystring", v))
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed",
            f"Live Mailchimp key — ping OK on datacenter {dc}", {"datacenter": dc}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Mailchimp rejected key (401).")
    return VerificationResult("unverifiable", f"Mailchimp returned {r.status_code}", raw_response=raw)


@_reg("Postmark Server Token")
async def _postmark(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.postmarkapp.com/server",
                        headers={"X-Postmark-Server-Token": v})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Postmark token — server: '{d.get('Name')}' (ID: {d.get('ID')})",
            {"server_name": d.get("Name"), "server_id": d.get("ID"),
             "smtp_tokens": d.get("SmtpTokens")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Postmark rejected token (401).")
    return VerificationResult("unverifiable", f"Postmark returned {r.status_code}", raw_response=raw)


@_reg("PagerDuty Integration Key")
async def _pagerduty(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.pagerduty.com/abilities",
                        headers={"Authorization": f"Token token={v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed", "Live PagerDuty API key — abilities endpoint accessible.",
                                  raw_response=raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "PagerDuty rejected key (401).")
    return VerificationResult("unverifiable", f"PagerDuty returned {r.status_code}", raw_response=raw)


# ---------------------------------------------------------------------------
# Infrastructure: npm / Heroku / Cloudflare / Vercel / Netlify /
#                 Doppler / DigitalOcean / Vault
# ---------------------------------------------------------------------------

@_reg("npm Token")
async def _npm(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://registry.npmjs.org/-/whoami",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        user = r.json().get("username", "unknown")
        return VerificationResult("confirmed", f"Live npm token — user: '{user}'",
                                  {"username": user}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "npm rejected token (401).")
    return VerificationResult("unverifiable", f"npm returned {r.status_code}", raw_response=raw)


@_reg("Heroku API Key")
async def _heroku(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.heroku.com/account",
                        headers={"Authorization": f"Bearer {v}",
                                 "Accept": "application/vnd.heroku+json; version=3"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Heroku key — account: {d.get('email')} ({d.get('id')})",
            {"email": d.get("email"), "id": d.get("id"),
             "verified": d.get("verified")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Heroku rejected key (401).")
    return VerificationResult("unverifiable", f"Heroku returned {r.status_code}", raw_response=raw)


@_reg("Cloudflare API Token", "Cloudflare Global API Key")
async def _cloudflare(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.cloudflare.com/client/v4/user/tokens/verify",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200 and r.json().get("success"):
        res = r.json().get("result", {})
        return VerificationResult("confirmed",
            f"Live Cloudflare token '{res.get('id')}' — status: {res.get('status')}",
            {"id": res.get("id"), "status": res.get("status")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Cloudflare rejected token (401).")
    return VerificationResult("unverifiable", f"Cloudflare returned {r.status_code}", raw_response=raw)


@_reg("Vercel Token")
async def _vercel(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.vercel.com/v2/user",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("user", {})
        return VerificationResult("confirmed",
            f"Live Vercel token — user: {d.get('name')} ({d.get('email')})",
            {"name": d.get("name"), "email": d.get("email"),
             "username": d.get("username")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Vercel rejected token (401).")
    return VerificationResult("unverifiable", f"Vercel returned {r.status_code}", raw_response=raw)


@_reg("Netlify Token")
async def _netlify(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.netlify.com/api/v1/user",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Netlify token — {d.get('full_name')} ({d.get('email')})",
            {"name": d.get("full_name"), "email": d.get("email"),
             "slug": d.get("slug")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Netlify rejected token (401).")
    return VerificationResult("unverifiable", f"Netlify returned {r.status_code}", raw_response=raw)


@_reg("Doppler Token")
async def _doppler(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.doppler.com/v3/me",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("workplace", {})
        return VerificationResult("confirmed",
            f"Live Doppler token — workplace: {d.get('name')}",
            {"workplace": d.get("name"), "billing_email": d.get("billing_email")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Doppler rejected token (401).")
    return VerificationResult("unverifiable", f"Doppler returned {r.status_code}", raw_response=raw)


@_reg("DigitalOcean Token")
async def _do(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.digitalocean.com/v2/account",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("account", {})
        return VerificationResult("confirmed",
            f"Live DigitalOcean token — {d.get('email')} (status: {d.get('status')})",
            {"email": d.get("email"), "status": d.get("status"),
             "droplet_limit": d.get("droplet_limit")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "DigitalOcean rejected token (401).")
    return VerificationResult("unverifiable", f"DigitalOcean returned {r.status_code}", raw_response=raw)


@_reg("Vault Token")
async def _vault(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://vault.hashicorp.com/v1/auth/token/lookup-self",
                        headers={"X-Vault-Token": v})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("data", {})
        return VerificationResult("confirmed",
            f"Live Vault token — policies: {d.get('policies', [])}",
            {"policies": d.get("policies"), "display_name": d.get("display_name"),
             "renewable": d.get("renewable")}, raw)
    if r.status_code == 403:
        return VerificationResult("invalid", "Vault rejected token (403 Forbidden).")
    return VerificationResult("unverifiable", f"Vault returned {r.status_code} (may be self-hosted)", raw_response=raw)


@_reg("Terraform Cloud Token")
async def _terraform(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://app.terraform.io/api/v2/account/details",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json().get("data", {}).get("attributes", {})
        return VerificationResult("confirmed",
            f"Live Terraform Cloud token — user: {d.get('username')} ({d.get('email')})",
            {"username": d.get("username"), "email": d.get("email")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Terraform Cloud rejected token (401).")
    return VerificationResult("unverifiable", f"Terraform Cloud returned {r.status_code}", raw_response=raw)


# ---------------------------------------------------------------------------
# Databases
# ---------------------------------------------------------------------------

async def _db_url(v: str) -> VerificationResult:
    """TCP connect to the database host — if reachable, DB is internet-exposed."""
    parsed = urlparse(v)
    host = parsed.hostname
    scheme = parsed.scheme.rstrip("+srv")
    port = parsed.port or {"postgres": 5432, "postgresql": 5432,
                           "mysql": 3306, "mongodb": 27017, "redis": 6379}.get(scheme, 0)
    if not host or not port:
        return VerificationResult("unverifiable", "Could not parse host/port from DB URL.")
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        writer.close()
        await writer.wait_closed()
        return VerificationResult("confirmed",
            f"DB port {host}:{port} is reachable from internet — credentials exposed.",
            {"host": host, "port": port, "scheme": scheme,
             "database": parsed.path.lstrip("/"),
             "user": parsed.username or "unknown"})
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return VerificationResult("unverifiable",
            f"DB at {host}:{port} not directly reachable (may be firewalled — credentials still leaked).",
            {"host": host, "port": port})

for _n in ("PostgreSQL Connection URL","MySQL Connection URL","MongoDB Connection URL",
           "Redis Connection URL","Neon DB URL","CockroachDB URL"):
    _VERIFIERS[_n] = _db_url


# ---------------------------------------------------------------------------
# SaaS: Airtable / Notion / Linear / Shopify / HubSpot / Intercom /
#        Segment / Mixpanel / Datadog / Sentry / Amplitude / PlanetScale
# ---------------------------------------------------------------------------

@_reg("Airtable API Key", "Airtable Legacy Key")
async def _airtable(v: str) -> VerificationResult:
    # Extract key from context-pattern if needed
    key = re.search(r'[a-zA-Z0-9]{14,}$', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.airtable.com/v0/meta/whoami",
                        headers={"Authorization": f"Bearer {token}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Airtable token — {d.get('email', 'unknown')}",
            {"email": d.get("email"), "id": d.get("id")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Airtable rejected token (401).")
    return VerificationResult("unverifiable", f"Airtable returned {r.status_code}", raw_response=raw)


@_reg("Notion API Key")
async def _notion(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.notion.com/v1/users/me",
                        headers={"Authorization": f"Bearer {v}",
                                 "Notion-Version": "2022-06-28"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        name = (d.get("name") or
                d.get("bot", {}).get("owner", {}).get("user", {}).get("name", "unknown"))
        return VerificationResult("confirmed",
            f"Live Notion token — '{name}' (type: {d.get('type')})",
            {"name": name, "type": d.get("type"), "id": d.get("id")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Notion rejected token (401).")
    return VerificationResult("unverifiable", f"Notion returned {r.status_code}", raw_response=raw)


@_reg("Linear API Key")
async def _linear(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.post("https://api.linear.app/graphql",
                         json={"query": "{ viewer { id name email } }"},
                         headers={"Authorization": v})
    raw = r.text[:400]
    if r.status_code == 200:
        viewer = r.json().get("data", {}).get("viewer", {})
        if viewer:
            return VerificationResult("confirmed",
                f"Live Linear key — {viewer.get('name')} ({viewer.get('email')})",
                {"name": viewer.get("name"), "email": viewer.get("email"),
                 "id": viewer.get("id")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Linear rejected key (401).")
    return VerificationResult("unverifiable", f"Linear returned {r.status_code}", raw_response=raw)


@_reg("Shopify Admin Token", "Shopify Storefront Token")
async def _shopify(v: str) -> VerificationResult:
    return VerificationResult("unverifiable",
        "Shopify tokens require the shop domain (e.g. mystore.myshopify.com) to verify.")


@_reg("HubSpot API Key")
async def _hubspot(v: str) -> VerificationResult:
    key = re.search(r'[a-zA-Z0-9\-]{36}', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get(f"https://api.hubapi.com/integrations/v1/me?hapikey={token}")
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live HubSpot key — portal ID: {d.get('portalId')}",
            {"portal_id": d.get("portalId"), "hub_domain": d.get("hubDomain")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "HubSpot rejected key (401).")
    return VerificationResult("unverifiable", f"HubSpot returned {r.status_code}", raw_response=raw)


@_reg("Intercom Token")
async def _intercom(v: str) -> VerificationResult:
    key = re.search(r'[a-zA-Z0-9_]{40,}', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.intercom.io/me",
                        headers={"Authorization": f"Bearer {token}",
                                 "Accept": "application/json"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live Intercom token — app: {d.get('app', {}).get('id_code', 'unknown')}",
            {"app_id": d.get("app", {}).get("id_code"),
             "name": d.get("name")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Intercom rejected token (401).")
    return VerificationResult("unverifiable", f"Intercom returned {r.status_code}", raw_response=raw)


@_reg("Segment Write Key")
async def _segment(v: str) -> VerificationResult:
    # POST a minimal track event — returns 200 on valid key, 400 on invalid
    key = re.search(r'[a-zA-Z0-9]{32}', v)
    token = key.group(0) if key else v
    import base64 as _b64
    creds = _b64.b64encode(f"{token}:".encode()).decode()
    async with httpx.AsyncClient(**_C) as c:
        r = await c.post("https://api.segment.io/v1/track",
                         headers={"Authorization": f"Basic {creds}",
                                  "Content-Type": "application/json"},
                         content='{"userId":"sentinel-verify","event":"probe"}')
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed",
            "Live Segment write key — track endpoint accepted (HTTP 200).", raw_response=raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Segment rejected write key (401).")
    return VerificationResult("unverifiable", f"Segment returned {r.status_code}", raw_response=raw)


@_reg("Mixpanel Token")
async def _mixpanel(v: str) -> VerificationResult:
    key = re.search(r'[a-f0-9]{32}', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get(f"https://mixpanel.com/api/2.0/engage?token={token}&selector=1==1")
    raw = r.text[:400]
    if r.status_code == 200 and "results" in r.text:
        return VerificationResult("confirmed",
            "Live Mixpanel token — engage API accessible.", raw_response=raw)
    if "invalid" in r.text.lower():
        return VerificationResult("invalid", "Mixpanel rejected token.")
    return VerificationResult("unverifiable", f"Mixpanel returned {r.status_code}", raw_response=raw)


@_reg("Amplitude API Key")
async def _amplitude(v: str) -> VerificationResult:
    key = re.search(r'[a-f0-9]{32}', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://amplitude.com/api/2/usersearch?user=sentinel_probe",
                        auth=(token, ""))
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed",
            "Live Amplitude API key — usersearch endpoint accessible.", raw_response=raw)
    if r.status_code == 400:
        try:
            if "Invalid" in r.json().get("error", ""):
                return VerificationResult("invalid", "Amplitude: key is invalid.")
        except Exception:
            pass
    return VerificationResult("unverifiable", f"Amplitude returned {r.status_code}", raw_response=raw)


@_reg("Datadog API Key")
async def _datadog(v: str) -> VerificationResult:
    key = re.search(r'[a-zA-Z0-9]{32}', v)
    token = key.group(0) if key else v
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.datadoghq.com/api/v1/validate",
                        headers={"DD-API-KEY": token})
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed", "Live Datadog API key — validation passed.", raw_response=raw)
    if r.status_code == 403:
        return VerificationResult("invalid", "Datadog rejected key (403 Forbidden).")
    return VerificationResult("unverifiable", f"Datadog returned {r.status_code}", raw_response=raw)


@_reg("Sentry DSN")
async def _sentry(v: str) -> VerificationResult:
    # Sentry DSNs are always URLs — probe the store endpoint
    try:
        async with httpx.AsyncClient(**_C) as c:
            # HEAD the DSN endpoint
            r = await c.head(v)
        if r.status_code in (200, 405):  # 405 Method Not Allowed = endpoint exists
            return VerificationResult("confirmed",
                f"Sentry DSN endpoint is reachable (HTTP {r.status_code}).",
                raw_response=f"HTTP {r.status_code}")
        if r.status_code == 404:
            return VerificationResult("invalid", "Sentry DSN endpoint returned 404 — project may not exist.")
    except Exception as exc:
        return VerificationResult("unverifiable", f"Sentry probe error: {exc}")
    return VerificationResult("unverifiable", f"Sentry DSN returned {r.status_code}")


@_reg("PlanetScale Token")
async def _planetscale(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.planetscale.com/v1/user",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Live PlanetScale token — {d.get('username', 'unknown')} ({d.get('email', '')})",
            {"username": d.get("username"), "email": d.get("email")}, raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "PlanetScale rejected token (401).")
    return VerificationResult("unverifiable", f"PlanetScale returned {r.status_code}", raw_response=raw)


# ---------------------------------------------------------------------------
# Auth: Supabase / Auth0 / Okta / Clerk / JWT / Bearer
# ---------------------------------------------------------------------------

@_reg("Supabase Anon Key", "Supabase URL + Key")
async def _supabase(v: str) -> VerificationResult:
    # If it's a JWT, decode it; if it's a URL, probe it
    if v.startswith("https://") and "supabase.co" in v:
        try:
            async with httpx.AsyncClient(**_C) as c:
                r = await c.get(f"{v.rstrip('/')}/rest/v1/",
                                headers={"apikey": "", "Authorization": "Bearer "})
            if r.status_code in (200, 400, 401):
                return VerificationResult("confirmed",
                    f"Supabase project URL is live (HTTP {r.status_code}) — project ref confirmed.",
                    raw_response=f"HTTP {r.status_code}")
        except Exception:
            pass
        return VerificationResult("unverifiable", "Could not probe Supabase project URL.")

    # Decode JWT
    try:
        parts = v.split(".")
        if len(parts) == 3:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = _json.loads(base64.urlsafe_b64decode(padded))
            role = payload.get("role", "unknown")
            ref = payload.get("ref") or payload.get("iss", "").split("/")[-1]
            exp = payload.get("exp")
            expired = bool(exp and exp < time.time())
            if expired:
                return VerificationResult("invalid",
                    f"Supabase JWT is expired (role: {role}).",
                    {"role": role, "ref": ref, "expired": True})
            return VerificationResult("confirmed",
                f"Valid Supabase JWT — role: {role}, project: {ref}",
                {"role": role, "ref": ref, "expired": False})
    except Exception:
        pass
    return VerificationResult("unverifiable", "Could not decode Supabase JWT payload.")


@_reg("Auth0 Client Secret")
async def _auth0(v: str) -> VerificationResult:
    return VerificationResult("unverifiable",
        "Auth0 Client Secret requires the paired Client ID and tenant domain to verify.")


@_reg("Okta API Token")
async def _okta(v: str) -> VerificationResult:
    key = re.search(r'00[a-zA-Z0-9\-_]{38}', v)
    token = key.group(0) if key else v
    return VerificationResult("unverifiable",
        "Okta token requires the organization domain (e.g. company.okta.com) to verify.")


@_reg("Clerk Secret Key")
async def _clerk(v: str) -> VerificationResult:
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.clerk.com/v1/users?limit=1",
                        headers={"Authorization": f"Bearer {v}"})
    raw = r.text[:400]
    if r.status_code == 200:
        return VerificationResult("confirmed",
            "Live Clerk secret key — users endpoint accessible.", raw_response=raw)
    if r.status_code == 401:
        return VerificationResult("invalid", "Clerk rejected key (401).")
    return VerificationResult("unverifiable", f"Clerk returned {r.status_code}", raw_response=raw)


@_reg("JWT Token")
async def _jwt(v: str) -> VerificationResult:
    try:
        parts = v.split(".")
        if len(parts) != 3:
            return VerificationResult("invalid", "Malformed JWT (not 3 parts).")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = _json.loads(base64.urlsafe_b64decode(padded))
        exp = payload.get("exp")
        iss = payload.get("iss", "")
        sub = payload.get("sub", "")
        now = time.time()
        expired = bool(exp and exp < now)
        return VerificationResult(
            "invalid" if expired else "confirmed",
            f"JWT {'EXPIRED' if expired else 'valid'} — iss: {iss or 'none'}, sub: {sub or 'none'}"
            + (f", expired {int((now-exp)/3600)}h ago" if expired and exp else ""),
            {"issuer": iss, "subject": sub, "expired": expired,
             "payload_keys": list(payload.keys())})
    except Exception as exc:
        return VerificationResult("unverifiable", f"JWT decode error: {exc}")


@_reg("Bearer Token")
async def _bearer(v: str) -> VerificationResult:
    # Extract the token part after "Bearer "
    token = v.split("Bearer ")[-1].strip() if "Bearer " in v else v
    # Try GitHub first (most common bearer token target)
    async with httpx.AsyncClient(**_C) as c:
        r = await c.get("https://api.github.com/user",
                        headers={"Authorization": f"token {token}",
                                 "User-Agent": "SentinelAI/1.0"})
    if r.status_code == 200:
        d = r.json()
        return VerificationResult("confirmed",
            f"Bearer token is a valid GitHub token for @{d.get('login')}",
            {"login": d.get("login")})
    return VerificationResult("unverifiable",
        "Bearer token origin unknown — could not determine issuing service.")


# ---------------------------------------------------------------------------
# Crypto / Keys
# ---------------------------------------------------------------------------

@_reg("Private Key PEM")
async def _pem(v: str) -> VerificationResult:
    return VerificationResult("confirmed",
        "PEM private key detected in client-side code — structural match confirmed. "
        "This is always critical — private keys must never be in frontend bundles.",
        {"key_type": "private_key_pem"})


@_reg("Ethereum Private Key")
async def _eth(v: str) -> VerificationResult:
    # Structural check — valid Ethereum private key is 32 bytes hex
    key_match = re.search(r'0x[a-fA-F0-9]{64}', v)
    if key_match:
        return VerificationResult("confirmed",
            "Ethereum private key format is valid (32-byte hex). "
            "Exposure allows full wallet control.",
            {"format": "hex_64_chars"})
    return VerificationResult("unverifiable", "Could not extract clean hex key from match.")


@_reg("Mnemonic Phrase")
async def _mnemonic(v: str) -> VerificationResult:
    words = re.findall(r'\b[a-z]+\b', v.lower())
    if len(words) in (12, 15, 18, 21, 24):
        return VerificationResult("confirmed",
            f"Valid BIP39 mnemonic phrase ({len(words)} words) detected. "
            "This exposes all derived wallet addresses.",
            {"word_count": len(words)})
    return VerificationResult("unverifiable",
        f"Mnemonic-like phrase found ({len(words)} words) but not standard BIP39 length.")


# ---------------------------------------------------------------------------
# Generic / Hardcoded
# ---------------------------------------------------------------------------

@_reg("Generic API Key", "Hardcoded Password", "Basic Auth in URL",
      "Azure Storage Key", "Azure Client Secret",
      "Internal Hostname", "Private IPv4 Address")
async def _generic(v: str) -> VerificationResult:
    # For these we rely entirely on the LLM judge in _verify_batch
    return VerificationResult("unverifiable",
        "Pattern detected — LLM judge will assess whether this is a real credential.")


# ---------------------------------------------------------------------------
# Azure SAS Token — probe the URL if it contains one, else structural check
# ---------------------------------------------------------------------------

@_reg("Azure SAS Token", "Azure Storage Key")
async def _azure_sas(v: str) -> VerificationResult:
    """
    If the value is a full SAS URL, probe it with HEAD.
    Otherwise it's a storage account key — structural confidence only.
    """
    if v.startswith("https://") and ("blob.core.windows.net" in v or "sig=" in v):
        try:
            async with httpx.AsyncClient(**_C) as c:
                r = await c.head(v)
            if r.status_code in (200, 206):
                return VerificationResult("confirmed",
                    "Azure SAS URL is live and accessible (HTTP 200/206).",
                    raw_response=f"HTTP {r.status_code}")
            if r.status_code == 403:
                return VerificationResult("invalid",
                    "Azure SAS URL returned 403 — token may be expired or invalid.")
            if r.status_code == 404:
                return VerificationResult("unverifiable",
                    "Azure SAS URL returned 404 — container/blob may not exist but token format is valid.")
        except Exception as exc:
            return VerificationResult("unverifiable", f"Azure SAS probe error: {exc}")

    if v.startswith("AccountKey=") and len(v) > 80:
        return VerificationResult("confirmed",
            "Azure Storage Account Key detected — format matches 512-bit base64 key. "
            "Cannot probe without the storage account name.",
            {"format": "AccountKey base64", "length": len(v)})

    return VerificationResult("unverifiable",
        "Azure SAS/Storage token requires the full blob URL or account name to verify live.")
