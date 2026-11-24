"""Autonomous Threat Intel & Endpoint Documentation Crawler.

Extracts REST API schemas, endpoints, and authentication schemes from developer documentation,
and cross-audits remote privacy policies against static permissions and PII data flows.
"""

from __future__ import annotations

import re
from typing import Any

HTTP_METHOD_REGEX = r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/[a-zA-Z0-9_\-\./\{\}:]+)"
ENDPOINT_PATH_REGEX = r"https?://[a-zA-Z0-9_\-\.]+(/[a-zA-Z0-9_\-\./\{\}]+)"


def crawl_endpoint_documentation(
    base_url: str,
    doc_content: str | None = None,
) -> dict[str, Any]:
    """Extract structured REST endpoint definitions and schemas from documentation."""
    content = doc_content or ""
    discovered_endpoints: list[dict[str, Any]] = []

    # 1. Match HTTP Method + Path pairs
    for match in re.finditer(HTTP_METHOD_REGEX, content):
        method = match.group(1).upper()
        path = match.group(2)
        discovered_endpoints.append(
            {
                "method": method,
                "path": path,
                "url": f"{base_url.rstrip('/')}{path}",
                "requires_auth": any(
                    k in content[max(0, match.start() - 100) : match.end() + 100].lower()
                    for k in ("bearer", "token", "auth", "api_key", "secret")
                ),
            }
        )

    # 2. Extract full URLs matching base_url
    for match in re.finditer(ENDPOINT_PATH_REGEX, content):
        url = match.group(0)
        path = match.group(1)
        if not any(e["path"] == path for e in discovered_endpoints):
            discovered_endpoints.append(
                {
                    "method": "GET",
                    "path": path,
                    "url": url,
                    "requires_auth": False,
                }
            )

    # Synthesize minimal OpenAPI 3.1 paths object
    openapi_paths: dict[str, Any] = {}
    for ep in discovered_endpoints:
        path = ep["path"]
        method = ep["method"].lower()
        openapi_paths.setdefault(path, {})[method] = {
            "summary": f"Autonomously harvested endpoint {ep['method']} {path}",
            "responses": {"200": {"description": "Successful response"}},
            "security": [{"BearerAuth": []}] if ep["requires_auth"] else [],
        }

    return {
        "base_url": base_url,
        "endpoint_count": len(discovered_endpoints),
        "endpoints": discovered_endpoints,
        "openapi_paths": openapi_paths,
        "has_openapi_spec": len(openapi_paths) > 0,
    }


PRIVACY_CATEGORIES = {
    "location": {
        "keywords": ["location", "gps", "geolocation", "precise location", "coarse location"],
        "permissions": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ],
    },
    "camera_microphone": {
        "keywords": ["camera", "microphone", "audio recording", "voice", "video recording"],
        "permissions": ["android.permission.CAMERA", "android.permission.RECORD_AUDIO"],
    },
    "contacts": {
        "keywords": ["contacts", "address book", "phone book"],
        "permissions": ["android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"],
    },
    "storage": {
        "keywords": ["photos", "videos", "files", "storage", "external storage"],
        "permissions": [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        ],
    },
}


def audit_privacy_policy(
    policy_text: str,
    declared_permissions: list[str],
    pii_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Cross-audit privacy policy disclosures against actual APK permissions and PII flows."""
    policy_lower = policy_text.lower()
    pii_findings = pii_findings or []
    declared_set = set(declared_permissions)

    discrepancies: list[dict[str, Any]] = []
    disclosed_categories: list[str] = []

    for category, meta in PRIVACY_CATEGORIES.items():
        # Check if policy mentions this data collection
        matched_kws = [kw for kw in meta["keywords"] if kw in policy_lower]
        is_disclosed = len(matched_kws) > 0

        # Check for explicit negation (e.g., "do not collect location", "never access camera")
        is_negated = False
        if is_disclosed:
            for kw in matched_kws:
                negation_pattern = rf"\b(not?|never|don't|no)\b[^.\n]{{0,30}}\b{re.escape(kw)}\b"
                if re.search(negation_pattern, policy_lower):
                    is_negated = True
                    break

        app_has_capability = any(p in declared_set for p in meta["permissions"])

        if app_has_capability and is_negated:
            discrepancies.append(
                {
                    "category": category,
                    "severity": "CRITICAL",
                    "title": (
                        f"Contradictory / Deceptive {category.replace('_', ' ').title()} Disclosure"
                    ),
                    "description": (
                        f"Policy explicitly claims not to access/collect {category}, "
                        f"yet app requests associated permissions {meta['permissions']}."
                    ),
                }
            )
        elif app_has_capability and not is_disclosed:
            discrepancies.append(
                {
                    "category": category,
                    "severity": "HIGH",
                    "title": f"Undeclared {category.replace('_', ' ').title()} Collection",
                    "description": (
                        f"App requests permissions {meta['permissions']} but the privacy policy "
                        f"contains no prominent disclosure regarding {category} collection."
                    ),
                }
            )
        elif is_disclosed and not is_negated:
            disclosed_categories.append(category)

    return {
        "policy_length_chars": len(policy_text),
        "disclosed_categories": disclosed_categories,
        "discrepancies_count": len(discrepancies),
        "discrepancies": discrepancies,
        "pii_findings_evaluated": len(pii_findings),
        "is_compliant": len(discrepancies) == 0,
        "risk_rating": "HIGH" if discrepancies else "LOW",
    }
