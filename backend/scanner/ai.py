"""
AI summary generation using OpenAI.

If no API key is configured, returns a deterministic rule-based summary
so the app still works without OpenAI.
"""

from __future__ import annotations

import json

from config import settings
from models import Finding, SecurityHeader, Severity


async def generate_ai_summary(
    target_url: str,
    findings: list[Finding],
    score: int,
    tech_stack: list[str],
    headers: list[SecurityHeader],
) -> tuple[str, list[str]]:
    """
    Returns (summary_paragraph, list_of_recommendations).
    Falls back to rule-based generation if no API key is set.
    """
    if not settings.openai_api_key:
        return _rule_based_summary(target_url, findings, score, tech_stack)

    try:
        return await _openai_summary(target_url, findings, score, tech_stack, headers)
    except Exception as exc:
        print(f"[AI] Generation failed: {exc} — using rule-based fallback")
        summary, recs = _rule_based_summary(target_url, findings, score, tech_stack)
        return summary, recs


async def _openai_summary(
    target_url: str,
    findings: list[Finding],
    score: int,
    tech_stack: list[str],
    headers: list[SecurityHeader],
) -> tuple[str, list[str]]:
    from openai import AsyncOpenAI

    client = AsyncOpenAI(
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url,
        default_headers={
            "HTTP-Referer": "https://sentinel.ai",
            "X-Title": "Sentinel AI Security Scanner",
        },
    )

    critical = [f for f in findings if f.severity == Severity.critical]
    high = [f for f in findings if f.severity == Severity.high]
    medium = [f for f in findings if f.severity == Severity.medium]

    findings_summary = json.dumps(
        [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description[:200],
                "recommendation": f.recommendation[:200],
            }
            for f in (critical + high + medium)[:15]
        ],
        indent=2,
    )

    prompt = f"""You are a senior application security engineer writing an executive summary of a security scan report.

Target: {target_url}
Security Score: {score}/100
Tech Stack: {', '.join(tech_stack) or 'Unknown'}
Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}

Top Findings (JSON):
{findings_summary}

Write:
1. A concise executive summary paragraph (3-5 sentences). Be specific about this target, its tech stack, and the actual issues found. Do not be generic.
2. A JSON array of exactly 5 prioritised, actionable recommendations (strings). Each should be specific and implementable.

Respond in this exact JSON format:
{{
  "summary": "...",
  "recommendations": ["...", "...", "...", "...", "..."]
}}"""

    response = await client.chat.completions.create(
        model=settings.openai_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=800,
    )

    content = response.choices[0].message.content or "{}"
    # Parse JSON from the response — handle both raw JSON and markdown-wrapped JSON
    content = content.strip()
    if content.startswith("```"):
        # Strip markdown code fences
        lines = content.split("\n")
        content = "\n".join(
            l for l in lines if not l.strip().startswith("```")
        ).strip()
    data = json.loads(content)
    summary = data.get("summary", "")
    recs = data.get("recommendations", [])
    return summary, recs[:5]


def _rule_based_summary(
    target_url: str,
    findings: list[Finding],
    score: int,
    tech_stack: list[str],
) -> tuple[str, list[str]]:
    """Deterministic fallback when OpenAI is not configured."""
    from models import FindingCategory

    critical = [f for f in findings if f.severity == Severity.critical]
    high = [f for f in findings if f.severity == Severity.high]
    medium = [f for f in findings if f.severity == Severity.medium]
    total = len(findings)

    stack_str = ", ".join(tech_stack) if tech_stack else "the detected stack"

    if score >= 85:
        posture = "strong security posture"
    elif score >= 70:
        posture = "moderate security posture with room for improvement"
    elif score >= 50:
        posture = "several significant security gaps"
    else:
        posture = "critical security issues requiring immediate attention"

    summary = (
        f"The security scan of {target_url} identified {total} finding(s) across {len(set(f.category for f in findings))} "
        f"categories, yielding a score of {score}/100 — indicating {posture}. "
    )

    if critical:
        summary += f"There are {len(critical)} critical issue(s) that need immediate remediation, including: {critical[0].title}. "
    if high:
        summary += f"{len(high)} high-severity issue(s) were found that could be exploited by an attacker with moderate effort. "
    if tech_stack:
        summary += f"The application runs on {stack_str}."

    # Build targeted recommendations from actual findings
    recs: list[str] = []
    seen_categories: set = set()

    priority_order = [Severity.critical, Severity.high, Severity.medium, Severity.low]
    sorted_findings = sorted(findings, key=lambda f: priority_order.index(f.severity))

    for f in sorted_findings:
        if f.category not in seen_categories and len(recs) < 5:
            seen_categories.add(f.category)
            recs.append(f.recommendation)

    # Pad to 5 if needed
    defaults = [
        "Enable HTTPS with a valid TLS certificate and configure HSTS.",
        "Audit and tighten your Content-Security-Policy header.",
        "Rotate all credentials detected in client-side code or storage.",
        "Replace localStorage token storage with HttpOnly, Secure cookies.",
        "Run this scan again after each deployment to catch regressions.",
    ]
    for d in defaults:
        if len(recs) >= 5:
            break
        if d not in recs:
            recs.append(d)

    return summary, recs[:5]


# ---------------------------------------------------------------------------
# LLM Secret Judge
# ---------------------------------------------------------------------------

from dataclasses import dataclass

@dataclass
class LLMJudgment:
    is_false_positive: bool
    reasoning: str
    confidence: float


async def llm_judge_secret(
    pattern_name: str,
    value_preview: str,
    location: str,
    context_snippet: str,
    api_response: str = "",
) -> LLMJudgment:
    """
    Ask the LLM: is this pattern match a real secret or junk?
    Used as a fallback for patterns that can't be verified via live API.
    
    Returns LLMJudgment with is_false_positive=True if LLM thinks it's noise.
    """
    if not settings.openai_api_key:
        # No LLM — default to keep (assume real)
        return LLMJudgment(
            is_false_positive=False,
            reasoning="No LLM configured — pattern match retained.",
            confidence=0.5,
        )

    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            default_headers={
                "HTTP-Referer": "https://sentinel.ai",
                "X-Title": "Sentinel AI Secret Judge",
            },
        )

        prompt = f"""You are a security analyst reviewing a potential secret exposure found in a web application scan.

**Pattern detected:** {pattern_name}
**Location:** {location}
**Value preview (redacted):** {value_preview}
**Code context:** {context_snippet[:150]}
**Live API probe result:** {api_response[:200] if api_response else "No probe response — service may require additional context to hit."}

**Task:** Is this a real credential or a false positive?

Real credentials: high entropy, correct format for the service, found in config/env/storage context, API probe shows service response.
False positives: all-zeros, test/mock/placeholder values, CSS class names, minified variable names, webpack chunk IDs, example values.

Respond ONLY in JSON:
{{"is_false_positive": true/false, "reasoning": "one sentence", "confidence": 0.0-1.0}}"""

        response = await client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=200,
        )

        content = response.choices[0].message.content or "{}"
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(l for l in lines if not l.strip().startswith("```")).strip()
        data = json.loads(content)

        return LLMJudgment(
            is_false_positive=bool(data.get("is_false_positive", False)),
            reasoning=str(data.get("reasoning", "")),
            confidence=float(data.get("confidence", 0.5)),
        )

    except Exception as exc:
        print(f"[LLM Judge] Error: {exc}")
        # On error, keep the finding (assume real)
        return LLMJudgment(
            is_false_positive=False,
            reasoning=f"LLM judge failed: {exc}",
            confidence=0.3,
        )
