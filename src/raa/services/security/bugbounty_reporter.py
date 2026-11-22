"""Bug Bounty Report Engine & HackerOne / Bugcrowd VRT Formatter.

Converts verified technical findings into standardized, submission-ready bug bounty reports
with official HackerOne Vulnerability Rating Taxonomy (VRT) and Bugcrowd VRT classifications,
CVSS v3.1 vector calculations, reproduction steps, and remediation guidance.
"""

from __future__ import annotations

from typing import Any

# HackerOne & Bugcrowd VRT mapping catalog
VRT_CATALOG = {
    "intent_redirection": {
        "h1_category": "Mobile Security Misconfiguration",
        "h1_subcategory": "Exported Components > Intent Redirection",
        "bugcrowd_vrt": "Mobile Security Flaws > Insecure IPC > Intent Redirection",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "priority": "P2 - HIGH",
    },
    "hardcoded_secret": {
        "h1_category": "Information Disclosure",
        "h1_subcategory": "Sensitive Data Exposure > Hardcoded API Credentials",
        "bugcrowd_vrt": "Sensitive Data Exposure > Credential / Key Exposure in Code",
        "default_cvss": 7.4,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "priority": "P2 - HIGH",
    },
    "broken_crypto": {
        "h1_category": "Cryptographic Issues",
        "h1_subcategory": "Weak Encryption Algorithm (ECB / DES / MD5)",
        "bugcrowd_vrt": "Cryptographic Issues > Insecure Cipher / Hash Mode",
        "default_cvss": 5.9,
        "default_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "priority": "P3 - MEDIUM",
    },
    "cleartext_traffic": {
        "h1_category": "Mobile Security Misconfiguration",
        "h1_subcategory": "Network Security > Cleartext HTTP Traffic Allowed",
        "bugcrowd_vrt": "Network Security Flaws > Cleartext Traffic Allowed",
        "default_cvss": 6.5,
        "default_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "priority": "P3 - MEDIUM",
    },
    "insecure_storage": {
        "h1_category": "Insecure Data Storage",
        "h1_subcategory": "Plaintext Credentials in SharedPreferences / SQLite",
        "bugcrowd_vrt": "Local Storage Flaws > Plaintext Sensitive Data Storage",
        "default_cvss": 6.2,
        "default_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "priority": "P3 - MEDIUM",
    },
    "sql_injection": {
        "h1_category": "Server-Side Injection",
        "h1_subcategory": "SQL Injection > Content Provider or API Parameter",
        "bugcrowd_vrt": "Server-Side Injection > SQL Injection",
        "default_cvss": 8.8,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "priority": "P1 - CRITICAL",
    },
    "idor": {
        "h1_category": "Broken Access Control",
        "h1_subcategory": "Insecure Direct Object Reference (IDOR)",
        "bugcrowd_vrt": "Broken Access Control > IDOR",
        "default_cvss": 8.1,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "priority": "P2 - HIGH",
    },
    "csrf": {
        "h1_category": "Cross-Site Request Forgery",
        "h1_subcategory": "CSRF on Critical Actions",
        "bugcrowd_vrt": "Cross-Site Request Forgery > Critical Action",
        "default_cvss": 7.5,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "priority": "P2 - HIGH",
    },
    "oauth": {
        "h1_category": "Authentication Flaws",
        "h1_subcategory": "OAuth Misconfiguration > Insecure Callback",
        "bugcrowd_vrt": "Authentication Flaws > OAuth Hijacking",
        "default_cvss": 9.0,
        "default_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "priority": "P1 - CRITICAL",
    },
}


def format_bugbounty_report(
    title: str,
    vulnerability_type: str | None = None,
    vuln_type: str | None = None,
    target: str | None = None,
    target_package: str | None = None,
    target_component: str | None = None,
    target_endpoint: str | None = None,
    severity: str | None = None,
    platform: str = "hackerone",
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    description: str | None = None,
    steps_to_reproduce: list[str] | str | None = None,
    reproduction_steps: list[str] | None = None,
    impact: str | None = None,
    impact_assessment: str | None = None,
    remediation: str | None = None,
    remediation_advice: str | None = None,
    poc_code: str | None = None,
) -> dict[str, Any]:
    """Format technical findings into a standardized HackerOne or Bugcrowd report."""
    actual_vuln_type = vulnerability_type or vuln_type or "Generic Security Flaw"
    actual_target = target_package or target or "com.example.app"
    actual_platform = platform.lower()

    vkey = actual_vuln_type.lower().replace(" ", "_")
    spec = VRT_CATALOG.get(
        vkey,
        {
            "h1_category": "Application Vulnerability",
            "h1_subcategory": f"Mobile Security Flaw (VRT:{actual_vuln_type})",
            "bugcrowd_vrt": f"Mobile Security Flaws > VRT:{actual_vuln_type}",
            "default_cvss": 7.5 if severity == "High" else (9.0 if severity == "Critical" else 5.0),
            "default_vector": cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "priority": f"P{2 if severity == 'High' else 3} - {severity or 'MEDIUM'}",
        },
    )

    score = cvss_score if cvss_score is not None else spec["default_cvss"]
    vector = cvss_vector or spec["default_vector"]
    priority = f"{spec['priority']}" if severity is None else severity

    # Steps to reproduce
    raw_steps = reproduction_steps or steps_to_reproduce
    if isinstance(raw_steps, list):
        steps_md = "\n".join(
            f"{i + 1}. {s}" if not s.startswith(str(i + 1)) else s for i, s in enumerate(raw_steps)
        )
    elif isinstance(raw_steps, str):
        steps_md = raw_steps
    else:
        steps_md = (
            f"1. Install the target Android application `{actual_target}` on a test device.\n"
            f"2. Inspect declared components and endpoints.\n"
            "3. Transmit the proof-of-concept payload.\n"
            "4. Observe unauthorized data exposure or state change."
        )

    act_impact = (
        impact
        or impact_assessment
        or (f"An attacker can exploit this flaw in `{actual_target}` to compromise data.")
    )
    act_remed = (
        remediation
        or remediation_advice
        or ("Enforce strict input validation and adhere to OWASP MASVS best practices.")
    )

    if actual_platform == "bugcrowd":
        vrt_label = f"{spec['bugcrowd_vrt']} (VRT:{actual_vuln_type})"
    else:
        vrt_label = f"{spec['h1_category']} > {spec['h1_subcategory']} (VRT:{actual_vuln_type})"

    target_asset = f"`{actual_target}`"
    if target_component:
        target_asset += f" (Component: `{target_component}`)"
    if target_endpoint:
        target_asset += f" (Endpoint: `{target_endpoint}`)"

    desc_text = description or (
        f"{title} was discovered in `{actual_target}`. The application does not adequately "
        "restrict or sanitize inputs, exposing an attack surface to unauthorized actors."
    )

    poc_block = f"\n\n### Proof of Concept Code\n```\n{poc_code}\n```" if poc_code else ""

    markdown_report = f"""# [Bug Report] {title}

## Summary
- **Target Asset:** {target_asset}
- **Vulnerability Type:** `{actual_vuln_type}`
- **Platform Taxonomy:** {vrt_label}
- **CVSS v3.1 Rating:** {score:.1f} ({vector})
- **Priority:** **{priority}**

---

## Technical Description
{desc_text}{poc_block}

## Steps to Reproduce
{steps_md}

## Impact
{act_impact}

## Suggested Remediation
```diff
- // Unsafe legacy configuration
+ // Hardened implementation following OWASP MASVS recommendations
```
{act_remed}

---
*Report generated automatically by RAA (Reverse Android Anything) Bug Bounty Engine.*
"""

    return {
        "status": "REPORT_GENERATED",
        "title": title,
        "platform": platform,
        "severity": severity or priority,
        "target": actual_target,
        "target_package": actual_target,
        "target_component": target_component,
        "target_endpoint": target_endpoint,
        "vrt_classification": vrt_label,
        "cvss_score": score,
        "cvss_vector": vector,
        "priority": priority,
        "markdown_report": markdown_report,
    }
