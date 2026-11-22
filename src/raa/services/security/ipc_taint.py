"""Deep Intent Redirection & IPC Confused-Deputy Taint Engine.

Identifies:
1. Untrusted Intent Redirection without IntentSanitizer allowlists.
2. Implicit Mutable PendingIntents susceptible to privilege escalation.
3. AIDL & Bound Service caller verification flaws.
"""

from __future__ import annotations

import re
from typing import Any

# Intent Redirection patterns in Smali/Java
INTENT_SOURCE_PATTERN = r"(getIntent\(\)|getParcelableExtra\(|getExtras\(\)|getIntentOld\()"
INTENT_SINK_PATTERN = r"(startActivity\(|startService\(|sendBroadcast\(|startForegroundService\()"
INTENT_SANITIZER_PATTERN = r"(IntentSanitizer|setComponent\(|setClass\(|getPackageName\(\)\.equals)"

# PendingIntent mutability patterns
PENDING_INTENT_PATTERN = (
    r"PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)\("
)
FLAG_IMMUTABLE_PATTERN = r"(FLAG_IMMUTABLE|0x4000000|67108864)"
FLAG_MUTABLE_PATTERN = r"(FLAG_MUTABLE|0x2000000|33554432)"

# AIDL / Bound Service authentication bypass patterns
AIDL_CALLER_AUTH_PATTERN = r"(getCallingUid\(\)|getCallingPid\(\)|enforceCallingPermission\()"
SPOOFABLE_PACKAGE_PATTERN = (
    r"getStringExtra\(\s*\"package\"\s*\)|getStringExtra\(\s*\"calling_package\"\s*\)"
)
VULNERABLE_CHECK_CALLING_PATTERN = r"checkCallingOrSelfPermission\("


def scan_intent_redirection(smali_texts: list[str]) -> list[dict[str, Any]]:
    """Scan Smali code for Intent Redirection vulnerabilities."""
    findings: list[dict[str, Any]] = []

    for idx, text in enumerate(smali_texts):
        has_source = bool(re.search(INTENT_SOURCE_PATTERN, text))
        has_sink = bool(re.search(INTENT_SINK_PATTERN, text))
        has_sanitizer = bool(re.search(INTENT_SANITIZER_PATTERN, text))

        if has_source and has_sink and not has_sanitizer:
            findings.append(
                {
                    "rule_id": "IPC_INTENT_REDIRECTION_VULNERABILITY",
                    "severity": "HIGH",
                    "cvss_score": 7.8,
                    "title": "Untrusted Intent Redirection without Sanitization",
                    "description": (
                        "App forwards received intent to startActivity/startService without "
                        "validating target component using IntentSanitizer or allowlist."
                    ),
                    "remediation": (
                        "Validate forwarded Intents using androidx.core.content.IntentSanitizer."
                    ),
                    "sample_index": idx,
                }
            )

    return findings


def scan_pending_intent_mutability(smali_texts: list[str]) -> list[dict[str, Any]]:
    """Scan Smali code for insecure mutable PendingIntents."""
    findings: list[dict[str, Any]] = []

    for idx, text in enumerate(smali_texts):
        pi_matches = list(re.finditer(PENDING_INTENT_PATTERN, text))
        if pi_matches:
            has_immutable = bool(re.search(FLAG_IMMUTABLE_PATTERN, text))
            has_explicit_mutable = bool(re.search(FLAG_MUTABLE_PATTERN, text))

            if not has_immutable or has_explicit_mutable:
                findings.append(
                    {
                        "rule_id": "IPC_MUTABLE_PENDING_INTENT",
                        "severity": "HIGH",
                        "cvss_score": 7.4,
                        "title": "Implicit Mutable PendingIntent Susceptible to Hijacking",
                        "description": (
                            "PendingIntent created without FLAG_IMMUTABLE. Intercepting apps can "
                            "modify internal intent extras and action parameters."
                        ),
                        "remediation": (
                            "Specify PendingIntent.FLAG_IMMUTABLE when creating PendingIntents."
                        ),
                        "sample_index": idx,
                    }
                )

    return findings


def scan_aidl_caller_auth(smali_texts: list[str]) -> list[dict[str, Any]]:
    """Audit Bound Services and AIDL implementations for spoofable package authentication."""
    findings: list[dict[str, Any]] = []

    for idx, text in enumerate(smali_texts):
        if "Stub" in text or "onTransact" in text or "onBind" in text:
            has_uid_check = bool(re.search(AIDL_CALLER_AUTH_PATTERN, text))
            has_spoofable_check = bool(re.search(SPOOFABLE_PACKAGE_PATTERN, text))
            has_vulnerable_check = bool(re.search(VULNERABLE_CHECK_CALLING_PATTERN, text))

            if has_spoofable_check or has_vulnerable_check or not has_uid_check:
                reasons = []
                if has_spoofable_check:
                    reasons.append("caller identity validated via spoofable string ('package')")
                if has_vulnerable_check:
                    reasons.append("uses checkCallingOrSelfPermission() which always succeeds")
                if not has_uid_check:
                    reasons.append("missing Binder.getCallingUid() caller UID verification")

                findings.append(
                    {
                        "rule_id": "IPC_AIDL_CONFUSED_DEPUTY",
                        "severity": "CRITICAL" if has_spoofable_check else "HIGH",
                        "cvss_score": 8.1 if has_spoofable_check else 7.2,
                        "title": "Bound Service / AIDL Insecure Caller Authentication",
                        "description": f"Bound service endpoint flaw: {', '.join(reasons)}",
                        "remediation": (
                            "Verify callers in AIDL/Stub using Binder.getCallingUid() "
                            "and signing certificate validation."
                        ),
                        "sample_index": idx,
                    }
                )

    return findings
