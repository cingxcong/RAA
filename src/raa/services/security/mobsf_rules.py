"""MobSF-Grade Static Security Rule Engine & CVSS v3.1 Risk Scorecard.

Ports MobSF static security pattern heuristics for Dalvik bytecode, manifests,
and cryptographic operations, computing automated CVSS v3.1 risk scorecards.
"""

from __future__ import annotations

import re
from typing import Any

MOBSF_RULES: list[dict[str, Any]] = [
    {
        "id": "MOBSF_CRYPTO_ECB_MODE",
        "title": "Insecure Symmetric Cipher Mode (ECB)",
        "category": "Cryptography",
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-327",
        "pattern": (
            r"AES/ECB/PKCS5Padding|DES/ECB/PKCS5Padding|"
            r"Cipher\.getInstance\(\s*[\"'](AES/ECB|DES/ECB)"
        ),
        "description": "App uses ECB mode for encryption, leaking structural plaintext blocks.",
        "remediation": "Use AES in GCM mode or CBC with an unpredictable unique IV.",
    },
    {
        "id": "MOBSF_CRYPTO_WEAK_HASH",
        "title": "Weak or Broken Cryptographic Hash (MD5 / SHA-1)",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cwe": "CWE-328",
        "pattern": r"MessageDigest\.getInstance\(\s*[\"'](MD5|SHA-1|SHA1)[\"']",
        "description": "MD5 and SHA-1 have known collision attacks and must not be used.",
        "remediation": "Upgrade hashing algorithms to SHA-256, SHA-384, or SHA-512.",
    },
    {
        "id": "MOBSF_CRYPTO_STATIC_IV",
        "title": "Hardcoded or Static Initialization Vector (IV)",
        "category": "Cryptography",
        "severity": "HIGH",
        "cvss": 7.4,
        "cwe": "CWE-329",
        "pattern": (
            r"IvParameterSpec\(\s*new byte\[\]\s*\{[^}]*\}|"
            r"IvParameterSpec\(\s*\"[^\"]+\"\.getBytes"
        ),
        "description": "App initializes ciphers using static byte arrays as IVs.",
        "remediation": "Generate cryptographically secure random IVs using SecureRandom.",
    },
    {
        "id": "MOBSF_CRYPTO_WEAK_PRNG",
        "title": "Weak Pseudorandom Number Generator (PRNG)",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cwe": "CWE-338",
        "pattern": r"new\s+java\.util\.Random\(|Ljava/util/Random;",
        "description": "java.util.Random is deterministic and predictable. Avoid for tokens.",
        "remediation": "Use java.security.SecureRandom for cryptographic or authentication tokens.",
    },
    {
        "id": "MOBSF_NETWORK_TRUST_ALL_CERTS",
        "title": "Permissive or Disabled TLS TrustManager",
        "category": "Network Security",
        "severity": "CRITICAL",
        "cvss": 8.1,
        "cwe": "CWE-295",
        "pattern": (
            r"checkClientTrusted\(.*?\)\s*\{\s*\}|checkServerTrusted\(.*?\)\s*\{\s*\}|"
            r"TrustAllManager|ALLOW_ALL_HOSTNAME_VERIFIER"
        ),
        "description": "Custom TrustManager implements empty checkServerTrusted() method.",
        "remediation": "Do not override X509TrustManager with blank implementations.",
    },
    {
        "id": "MOBSF_STORAGE_CLEARTEXT_TRAFFIC",
        "title": "Cleartext HTTP Traffic Allowed",
        "category": "Network Security",
        "severity": "HIGH",
        "cvss": 6.5,
        "cwe": "CWE-319",
        "pattern": r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']",
        "description": "App permits cleartext HTTP communication, exposing traffic.",
        "remediation": "Set usesCleartextTraffic=false and enforce HTTPS via network config.",
    },
    {
        "id": "MOBSF_SECRET_HARDCODED_KEY",
        "title": "Hardcoded API Secret or Access Token",
        "category": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "cvss": 8.2,
        "cwe": "CWE-798",
        "pattern": (
            r"(AKIA[0-9A-Z]{16})|(AIza[0-9A-Za-z\\-_]{35})|"
            r"(sk_live_[0-9a-zA-Z]{24})|-----"
            r"BEGIN PRIVATE KEY-----"
        ),
        "description": "High-entropy cloud credential or private cryptographic key found.",
        "remediation": "Store cloud secrets securely on backend servers.",
    },
]


def scan_mobsf_rules(
    manifest_xml: str | None = None,
    source_texts: list[str] | None = None,
    dex_strings: list[str] | None = None,
) -> dict[str, Any]:
    """Scan input source files and manifest against the MobSF rule catalog."""
    manifest_xml = manifest_xml or ""
    source_texts = source_texts or []
    dex_strings = dex_strings or []

    combined_corpus = "\n".join([manifest_xml, *source_texts, *dex_strings])
    findings: list[dict[str, Any]] = []

    for rule in MOBSF_RULES:
        matches = list(re.finditer(rule["pattern"], combined_corpus, re.MULTILINE))
        if matches:
            first_match = matches[0]
            start = max(0, first_match.start() - 30)
            end = min(len(combined_corpus), first_match.end() + 30)
            snippet = combined_corpus[start:end].strip().replace("\n", " ")

            findings.append(
                {
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "cvss_score": rule["cvss"],
                    "cwe": rule["cwe"],
                    "match_count": len(matches),
                    "evidence_snippet": snippet[:100],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                }
            )

    max_cvss = max((f["cvss_score"] for f in findings), default=0.0)
    has_crit = any(f["severity"] == "CRITICAL" for f in findings)
    if max_cvss >= 9.0 or has_crit:
        risk_level = "CRITICAL"
    elif max_cvss >= 7.0:
        risk_level = "HIGH"
    elif max_cvss >= 4.0:
        risk_level = "MEDIUM"
    elif max_cvss > 0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    return {
        "rules_evaluated": len(MOBSF_RULES),
        "findings_count": len(findings),
        "max_cvss": max_cvss,
        "risk_level": risk_level,
        "findings": findings,
    }


def generate_cvss_scorecard(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate executive CVSS v3.1 risk scorecard and category breakdown."""
    if not findings:
        return {
            "overall_score": 0.0,
            "overall_rating": "NONE",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "category_scores": {},
            "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "executive_summary": "No security vulnerabilities identified in the analyzed assets.",
        }

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_scores: dict[str, list[float]] = {}

    for f in findings:
        sev = f.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("category", "General")
        category_scores.setdefault(cat, []).append(f.get("cvss_score", 5.0))

    avg_category_scores = {
        cat: round(sum(scores) / len(scores), 1) for cat, scores in category_scores.items()
    }

    max_score = max((f.get("cvss_score", 0.0) for f in findings), default=0.0)
    base_score = round(min(10.0, max(max_score, max_score * 0.8 + (len(findings) * 0.2))), 1)

    if base_score >= 9.0:
        rating = "CRITICAL"
    elif base_score >= 7.0:
        rating = "HIGH"
    elif base_score >= 4.0:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    conf = "H" if base_score >= 7.0 else "L"
    integ = "H" if base_score >= 8.0 else "L"
    vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{conf}/I:{integ}/A:N"

    return {
        "overall_score": base_score,
        "overall_rating": rating,
        "cvss_vector": vector,
        "category_scores": avg_category_scores,
        "findings_by_severity": severity_counts,
        "executive_summary": (
            f"Security audit evaluated {len(findings)} findings. Risk rating: {rating} "
            f"(CVSS {base_score})."
        ),
    }
