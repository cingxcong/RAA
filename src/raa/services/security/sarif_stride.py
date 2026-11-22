"""OASIS SARIF 2.1 Exporter, Mobile STRIDE Threat Modeler & PoC Generator.

Produces:
1. Standardized OASIS SARIF 2.1.0 format reports for GitHub Advanced Security / GitLab CI.
2. STRIDE threat model categorization mapped to MITRE ATT&CK for Mobile techniques.
3. Executable non-destructive Proof-of-Concept (PoC) exploit and verification commands.
"""

from __future__ import annotations

from typing import Any

MITRE_MOBILE_MAPPING: dict[str, dict[str, str]] = {
    "Spoofing": {
        "technique_id": "T1406",
        "name": "Exploit OS Vulnerability / Confused Deputy",
    },
    "Tampering": {
        "technique_id": "T1437",
        "name": "Application Manipulation / Dynamic Code Loading",
    },
    "Repudiation": {
        "technique_id": "T1401",
        "name": "Impaired Defense / Anti-Forensics",
    },
    "Information Disclosure": {
        "technique_id": "T1426",
        "name": "Credential Access / Insecure Data Storage",
    },
    "Denial of Service": {
        "technique_id": "T1404",
        "name": "Service Exhaustion / Watchdog Deadlock",
    },
    "Elevation of Privilege": {
        "technique_id": "T1575",
        "name": "Intent Hijacking / Access Token Manipulation",
    },
}


def export_sarif_v21(
    findings: list[dict[str, Any]],
    app_name: str = "RAA Analysis Target",
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Serialize security findings into standard OASIS SARIF v2.1.0 JSON format."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = f.get("rule_id", "RAA_VULN_001")
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.get("title", rule_id),
                "shortDescription": {"text": f.get("title", rule_id)},
                "fullDescription": {
                    "text": f.get("description", "Security finding identified by RAA.")
                },
                "help": {
                    "text": f.get(
                        "remediation", "Review and remediate according to MASVS guidelines."
                    )
                },
                "properties": {
                    "category": f.get("category", "Security"),
                    "cvss": f.get("cvss_score", 5.0),
                },
            }

        sev = f.get("severity", "MEDIUM").upper()
        if sev in ("CRITICAL", "HIGH"):
            sarif_level = "error"
        elif sev == "MEDIUM":
            sarif_level = "warning"
        else:
            sarif_level = "note"

        results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": f.get("description", f.get("title", rule_id))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.get("file_path", "AndroidManifest.xml"),
                            },
                            "region": {
                                "startLine": f.get("line_number", 1),
                            },
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
            "sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RAA — Reverse Android Anything",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/example/raa",
                        "rules": list(rules_dict.values()),
                    }
                },
                "artifacts": [
                    {"location": {"uri": "AndroidManifest.xml"}},
                ],
                "results": results,
            }
        ],
    }
    return sarif_doc


def model_stride_threats(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Categorize findings into STRIDE threat model mapped to MITRE ATT&CK for Mobile."""
    stride_categories: dict[str, list[dict[str, Any]]] = {
        "Spoofing": [],
        "Tampering": [],
        "Repudiation": [],
        "Information Disclosure": [],
        "Denial of Service": [],
        "Elevation of Privilege": [],
    }

    for f in findings:
        title = (f.get("title", "") + " " + f.get("category", "")).lower()
        if any(k in title for k in ("spoof", "trust", "hostname", "cert")):
            stride_categories["Spoofing"].append(f)
        elif any(k in title for k in ("dcl", "tamper", "cleartext", "overlay")):
            stride_categories["Tampering"].append(f)
        elif any(k in title for k in ("audit", "log")):
            stride_categories["Repudiation"].append(f)
        elif any(k in title for k in ("secret", "key", "token", "crypto", "hash", "ecb")):
            stride_categories["Information Disclosure"].append(f)
        elif any(k in title for k in ("deadlock", "anr", "dos", "hang")):
            stride_categories["Denial of Service"].append(f)
        else:
            stride_categories["Elevation of Privilege"].append(f)

    threat_model: list[dict[str, Any]] = []
    for domain, domain_findings in stride_categories.items():
        mitre_info = MITRE_MOBILE_MAPPING[domain]
        threat_model.append(
            {
                "stride_domain": domain,
                "mitre_technique_id": mitre_info["technique_id"],
                "mitre_technique_name": mitre_info["name"],
                "threat_count": len(domain_findings),
                "findings": domain_findings,
            }
        )

    return {
        "total_threats": sum(len(items) for items in stride_categories.values()),
        "stride_breakdown": threat_model,
    }


def generate_exploit_poc(
    finding_id: str,
    finding_title: str,
    target_package: str,
    target_component: str | None = None,
    parameter: str | None = None,
    component: str | None = None,
) -> dict[str, Any]:
    """Generate reproducible, non-destructive verification PoC commands."""
    comp = target_component or component or f"{target_package}/.MainActivity"
    param = parameter or "test_payload"

    adb_cmd = f'adb shell am start -n {comp} --es "{param}" "RAA_VALIDATION_TOKEN"'
    target_clean = comp.replace("/", ".")
    frida_script = (
        f"// Frida non-destructive verification snippet for {finding_id}\n"
        f"Java.perform(function() {{\n"
        f"    console.log('[*] Injecting probe for {finding_title} in {target_package}');\n"
        f"    var target = Java.use('{target_clean}');\n"
        f"    if (target) {{ console.log('[+] Target component resolved'); }}\n"
        f"}});\n"
    )
    curl_probe = (
        f'curl -k -i -X GET "https://example.com/api/v1/probe?'
        f'target={target_package}&vuln={finding_id}"'
    )

    return {
        "finding_id": finding_id,
        "title": finding_title,
        "target_package": target_package,
        "poc_type": "Intent / Frida / HTTP",
        "adb_command": adb_cmd,
        "frida_script": frida_script,
        "curl_probe": curl_probe,
        "safety_guarantee": "Non-destructive verification probe; does not alter state.",
    }
