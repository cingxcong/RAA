"""Google Play Protect & App Defense Pre-Flight Compliance Engine.

Audits APK manifests, permissions, services, and bytecode against Google Play Protect
malware heuristics, Android 14+ platform constraints, and Google Play developer policies.
"""

from __future__ import annotations

import re
from typing import Any

from raa.domain.manifest import ManifestInfo

DANGEROUS_SMS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
}

DANGEROUS_CALL_PERMS = {
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
}

VALID_FOREGROUND_TYPES = {
    "camera",
    "connectedDevice",
    "dataSync",
    "health",
    "location",
    "mediaPlayback",
    "mediaProjection",
    "microphone",
    "phoneCall",
    "remoteMessaging",
    "shortService",
    "specialUse",
    "systemExempted",
}

DCL_PATTERNS = [
    r"Ldalvik/system/DexClassLoader;",
    r"Ldalvik/system/InMemoryDexClassLoader;",
    r"Ldalvik/system/PathClassLoader;",
    r"Ljava/lang/reflect/Method;->invoke",
    r"loadClass\(Ljava/lang/String;\)",
]


def audit_play_protect_compliance(
    manifest_info: ManifestInfo | dict[str, Any],
    dex_classes: list[str] | None = None,
    dex_strings: list[str] | None = None,
    smali_sources: list[str] | None = None,
) -> dict[str, Any]:
    """Execute pre-flight compliance audit against Play Protect & Play Policy rules."""
    if isinstance(manifest_info, ManifestInfo):
        package_name = manifest_info.package or "unknown"
        permissions = {p.name for p in manifest_info.requested_permissions}
        target_sdk = manifest_info.target_sdk or 34
        services = [
            {"name": c.name, "foreground_service_type": getattr(c, "foreground_service_type", None)}
            for c in manifest_info.components
            if c.component_type == "service"
        ]
    elif isinstance(manifest_info, dict):
        package_name = manifest_info.get("package") or manifest_info.get("package_name", "unknown")
        raw_perms = manifest_info.get("permissions") or manifest_info.get(
            "requested_permissions", []
        )
        permissions = {p if isinstance(p, str) else getattr(p, "name", str(p)) for p in raw_perms}
        target_sdk = manifest_info.get("target_sdk", 34)
        services = manifest_info.get("services", [])
    else:
        package_name = getattr(
            manifest_info, "package_name", getattr(manifest_info, "package", "unknown")
        )
        raw_perms = getattr(
            manifest_info,
            "permissions",
            getattr(manifest_info, "requested_permissions", []),
        )
        permissions = {p if isinstance(p, str) else getattr(p, "name", str(p)) for p in raw_perms}
        target_sdk = getattr(manifest_info, "target_sdk", 34)
        services = getattr(manifest_info, "services", getattr(manifest_info, "components", []))

    dex_classes = dex_classes or []
    dex_strings = dex_strings or []
    smali_sources = smali_sources or []

    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    # 1. Overlay + Accessibility Trojan Pattern
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
    has_accessibility = any("AccessibilityService" in str(s) for s in services) or (
        "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
    )
    if has_overlay and has_accessibility:
        violations.append(
            {
                "rule_id": "PLAY_PROTECT_OVERLAY_ACCESSIBILITY",
                "severity": "CRITICAL",
                "category": "Malware Heuristics",
                "title": "Dual Accessibility + System Alert Window Overlay Combination",
                "description": (
                    "App pairs SYSTEM_ALERT_WINDOW with BIND_ACCESSIBILITY_SERVICE. "
                    "Flagged by Google Play Protect as a banking trojan pattern."
                ),
                "remediation": "Do not combine background overlay with accessibility services.",
            }
        )

    # 2. SMS & Call Log Policy Violations
    used_sms = permissions.intersection(DANGEROUS_SMS_PERMS)
    if used_sms:
        warnings.append(
            {
                "rule_id": "PLAY_POLICY_SMS_RESTRICTION",
                "severity": "HIGH",
                "category": "Google Play Policy",
                "title": f"Restricted SMS Permissions Declared ({len(used_sms)} permissions)",
                "description": (
                    f"Permissions: {', '.join(sorted(used_sms))}. Play requires default SMS role."
                ),
                "remediation": "Use SMS Retriever API or SMS User Consent API instead.",
            }
        )

    used_call = permissions.intersection(DANGEROUS_CALL_PERMS)
    if used_call:
        warnings.append(
            {
                "rule_id": "PLAY_POLICY_CALL_LOG_RESTRICTION",
                "severity": "HIGH",
                "category": "Google Play Policy",
                "title": f"Restricted Call Log Permissions Declared ({len(used_call)} permissions)",
                "description": (
                    f"Permissions: {', '.join(sorted(used_call))}. Play requires dialer role."
                ),
                "remediation": "Remove Call Log permissions and use standard telecom intents.",
            }
        )

    # 3. All-Files Access (MANAGE_EXTERNAL_STORAGE)
    if "android.permission.MANAGE_EXTERNAL_STORAGE" in permissions:
        warnings.append(
            {
                "rule_id": "PLAY_POLICY_MANAGE_EXTERNAL_STORAGE",
                "severity": "MEDIUM",
                "category": "Scoped Storage",
                "title": "Broad All-Files Storage Access Requested",
                "description": "MANAGE_EXTERNAL_STORAGE without file manager justification.",
                "remediation": "Migrate to Scoped Storage (SAF or Photo Picker).",
            }
        )

    # 4. Foreground Service Type Missing (Android 14+ requirement)
    if target_sdk >= 34 and "android.permission.FOREGROUND_SERVICE" in permissions:
        for svc in services:
            svc_name = svc.get("name", "") if isinstance(svc, dict) else str(svc)
            fg_type = svc.get("foreground_service_type") if isinstance(svc, dict) else None
            if not fg_type or fg_type not in VALID_FOREGROUND_TYPES:
                violations.append(
                    {
                        "rule_id": "PLAY_POLICY_FGS_MISSING_TYPE",
                        "severity": "HIGH",
                        "category": "Android 14+ Platform Compliance",
                        "title": f"Foreground Service Missing Valid Type: {svc_name}",
                        "description": (
                            f"Service '{svc_name}' lacks a mandatory Android 14+ "
                            "android:foregroundServiceType attribute."
                        ),
                        "remediation": "Declare explicit android:foregroundServiceType attribute.",
                    }
                )

    # 5. Dynamic Code Loading (DCL)
    dcl_findings: list[str] = []
    combined_strings = " ".join(dex_strings)
    for pattern in DCL_PATTERNS:
        if re.search(pattern, combined_strings):
            dcl_findings.append(pattern)

    for smali in smali_sources:
        for pattern in DCL_PATTERNS:
            if re.search(pattern, smali) and pattern not in dcl_findings:
                dcl_findings.append(pattern)

    if dcl_findings:
        violations.append(
            {
                "rule_id": "PLAY_PROTECT_DYNAMIC_CODE_LOADING",
                "severity": "CRITICAL",
                "category": "Malware & DCL",
                "title": "Dynamic Code Loading (DCL) Detected",
                "description": (
                    f"Detected dynamic bytecode loading signatures: {', '.join(dcl_findings)}."
                ),
                "remediation": "Bundle all executable logic directly within the APK.",
            }
        )

    # 6. Account Deletion Compliance
    auth_strings = [
        s
        for s in dex_strings
        if any(k in s.lower() for k in ("login", "oauth", "auth_token", "jwt", "bearer"))
    ]
    deletion_strings = [
        s
        for s in dex_strings
        if any(
            k in s.lower()
            for k in ("delete_account", "account/delete", "deleteaccount", "erase_data")
        )
    ]
    if auth_strings and not deletion_strings:
        warnings.append(
            {
                "rule_id": "PLAY_POLICY_ACCOUNT_DELETION",
                "severity": "MEDIUM",
                "category": "Google Play Privacy Policy",
                "title": "Account Creation Present Without Detectable In-App Deletion Path",
                "description": "App contains auth endpoints but lacks account deletion path.",
                "remediation": "Provide an accessible pathway to request account deletion.",
            }
        )

    is_compliant = len(violations) == 0
    passed_rules = 6 - (len(violations) + len(warnings))
    has_crit = any(v["severity"] == "CRITICAL" for v in violations)
    if has_crit:
        risk_level = "CRITICAL"
    elif violations:
        risk_level = "HIGH"
    elif warnings:
        risk_level = "MEDIUM"
    else:
        risk_level = "PASS"

    fgs_clean = not any(v["rule_id"] == "PLAY_POLICY_FGS_MISSING_TYPE" for v in violations)
    return {
        "package_name": package_name,
        "target_sdk": target_sdk,
        "is_play_protect_compliant": is_compliant,
        "risk_level": risk_level,
        "violations_count": len(violations),
        "warnings_count": len(warnings),
        "violations": violations,
        "warnings": warnings,
        "audit_summary": {
            "total_rules_evaluated": 6,
            "passed_rules": max(0, passed_rules),
            "overlay_accessibility_clean": not (has_overlay and has_accessibility),
            "sms_policy_compliant": len(used_sms) == 0,
            "call_log_compliant": len(used_call) == 0,
            "fgs_compliant": fgs_clean,
            "dcl_clean": len(dcl_findings) == 0,
        },
    }
