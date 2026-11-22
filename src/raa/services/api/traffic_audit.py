"""Passive AI Traffic Inspector & PII Redaction Engine.

Inspired by burp-ai-agent: passively inspects captured HTTP requests and responses
for IDOR risk patterns, unauthenticated administrative endpoints, missing security
headers, and redacts sensitive credentials and PII before AI processing.
"""

from __future__ import annotations

import re
from typing import Any

# PII and Credential Regex Patterns
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+")
BEARER_PATTERN = re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
CCN_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
PASSWORD_FIELD_PATTERN = re.compile(
    r'("(?:password|secret|apiKey|access_token|private_key)"\s*:\s*")[^"]+(")',
    re.IGNORECASE,
)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]

IDOR_PARAMS = ["user_id", "userid", "account_id", "profile_id", "uid", "customer_id"]
ADMIN_PATHS = ["/admin", "/internal", "/actuator", "/debug", "/metrics", "/env"]


def redact_sensitive_traffic(text: str) -> tuple[str, int]:
    """Redact sensitive PII, JWTs, Bearer tokens, and secrets from text."""
    redacted = text
    count = 0

    if JWT_PATTERN.search(redacted):
        redacted, n = JWT_PATTERN.subn("[REDACTED_JWT]", redacted)
        count += n

    if BEARER_PATTERN.search(redacted):
        redacted, n = BEARER_PATTERN.subn(r"\1[REDACTED_TOKEN]", redacted)
        count += n

    if CCN_PATTERN.search(redacted):
        redacted, n = CCN_PATTERN.subn("[REDACTED_CCN]", redacted)
        count += n

    if EMAIL_PATTERN.search(redacted):
        redacted, n = EMAIL_PATTERN.subn("[REDACTED_EMAIL]", redacted)
        count += n

    if PASSWORD_FIELD_PATTERN.search(redacted):
        redacted, n = PASSWORD_FIELD_PATTERN.subn(r"\g<1>[REDACTED_SECRET]\g<2>", redacted)
        count += n

    return redacted, count


def audit_passive_traffic(
    requests: list[dict[str, Any]] | None = None,
    target_domain: str | None = None,
    redact_pii: bool = True,
) -> dict[str, Any]:
    """Passively analyze HTTP traffic flows for security flaws and PII leakage."""
    flows = requests or []
    findings: list[dict[str, Any]] = []
    total_redactions = 0
    sanitized_flows: list[dict[str, Any]] = []

    for idx, flow in enumerate(flows):
        url = flow.get("url", "")
        method = flow.get("method", "GET").upper()
        resp_headers = flow.get("response_headers", {})
        req_body = str(flow.get("body", ""))
        resp_body = str(flow.get("response_body", ""))

        flow_redactions = 0
        if redact_pii:
            url, r1 = redact_sensitive_traffic(url)
            req_body, r2 = redact_sensitive_traffic(req_body)
            resp_body, r3 = redact_sensitive_traffic(resp_body)
            flow_redactions = r1 + r2 + r3
            total_redactions += flow_redactions

        # 1. Missing Security Headers check
        resp_lower = [k.lower() for k in resp_headers]
        missing_sec = [h for h in SECURITY_HEADERS if h.lower() not in resp_lower]
        if missing_sec and resp_headers:
            findings.append(
                {
                    "flow_index": idx,
                    "url": url,
                    "category": "Missing Security Headers",
                    "severity": "Low",
                    "detail": f"Response lacks security headers: {', '.join(missing_sec)}",
                    "remediation": "Configure strict HSTS, CSP, and X-Content-Type headers.",
                }
            )

        # 2. Insecure Cookie Attributes
        cookie_header = resp_headers.get("Set-Cookie", "")
        if cookie_header:
            cookie_lower = cookie_header.lower()
            issues: list[str] = []
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")
            if issues:
                findings.append(
                    {
                        "flow_index": idx,
                        "url": url,
                        "category": "Insecure Cookie Attributes",
                        "severity": "Medium",
                        "detail": f"Set-Cookie header has flaws: {'; '.join(issues)}",
                        "remediation": "Add 'Secure; HttpOnly; SameSite=Strict' to cookies.",
                    }
                )

        # 3. IDOR / BOLA Risk Detection
        url_lower = url.lower()
        matched_idor = [param for param in IDOR_PARAMS if f"{param}=" in url_lower]
        if matched_idor:
            findings.append(
                {
                    "flow_index": idx,
                    "url": url,
                    "category": "IDOR / BOLA Parameter Exposure",
                    "severity": "High",
                    "detail": f"URL exposes direct object identifiers: {matched_idor}",
                    "remediation": "Implement server-side user session tenancy checks.",
                }
            )

        # 4. Sensitive Token in Query Parameters
        token_keywords = ["token=", "api_key=", "secret=", "password=", "auth="]
        if any(kw in url_lower for kw in token_keywords):
            findings.append(
                {
                    "flow_index": idx,
                    "url": url,
                    "category": "Credential in URL Query",
                    "severity": "High",
                    "detail": "Sensitive credential or token passed in cleartext URL parameter",
                    "remediation": "Pass authentication credentials in Authorization headers.",
                }
            )

        # 5. Administrative / Debug Endpoints Exposure
        if any(adm in url_lower for adm in ADMIN_PATHS):
            findings.append(
                {
                    "flow_index": idx,
                    "url": url,
                    "category": "Exposed Administrative Surface",
                    "severity": "Critical",
                    "detail": f"Endpoint accesses sensitive administrative or actuator path: {url}",
                    "remediation": (
                        "Enforce strict IP whitelisting or disable debug endpoints in prod."
                    ),
                }
            )

        sanitized_flows.append(
            {
                "index": idx,
                "method": method,
                "url": url,
                "redactions": flow_redactions,
            }
        )

    # Severity summary calculation
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "flows_analyzed": len(flows),
        "target_domain": target_domain,
        "pii_redaction_enabled": redact_pii,
        "total_pii_redactions": total_redactions,
        "findings_count": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
        "sanitized_flows": sanitized_flows,
    }
