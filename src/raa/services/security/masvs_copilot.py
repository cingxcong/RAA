"""Interactive AI Pentest Copilot & OWASP MASVS Checklist Orchestrator.

Maintains a dynamic verification checklist across all 7 OWASP MASVS v2.0 domains
and translates high-level analyst reversing queries into concrete tool sequences.
"""

from __future__ import annotations

import contextlib
import xml.etree.ElementTree as ET
from typing import Any

MASVS_CATEGORIES = {
    "MASVS-STORAGE": "Secure Data Storage & Privacy",
    "MASVS-CRYPTO": "Cryptographic Architecture & Key Management",
    "MASVS-AUTH": "Authentication & Session Management",
    "MASVS-NETWORK": "Network Communication & TLS Security",
    "MASVS-PLATFORM": "Android Platform Interaction & IPC",
    "MASVS-CODE": "Code Quality, Obfuscation & Build Settings",
    "MASVS-RESILIENCE": "Reverse Engineering Defense & Anti-Tampering",
}


def audit_masvs_compliance(
    findings: list[dict[str, Any]] | None = None,
    manifest_xml: str | None = None,
    is_debuggable: bool = False,
    uses_cleartext: bool = False,
    is_minified: bool = True,
    has_root_detection: bool = False,
) -> dict[str, Any]:
    """Evaluate application posture against the OWASP MASVS v2.0 verification standard."""
    findings_list = findings or []

    # Parse manifest if available to update flags
    if manifest_xml:
        with contextlib.suppress(Exception):
            root = ET.fromstring(manifest_xml)  # noqa: S314
            android_ns = "{http://schemas.android.com/apk/res/android}"
            app_elem = root.find("application")
            if app_elem is not None:
                if app_elem.attrib.get(f"{android_ns}debuggable", "").lower() == "true":
                    is_debuggable = True
                if app_elem.attrib.get(f"{android_ns}usesCleartextTraffic", "").lower() == "true":
                    uses_cleartext = True

    # Count issues per domain
    domain_issues: dict[str, list[dict[str, Any]]] = {k: [] for k in MASVS_CATEGORIES}
    for f in findings_list:
        cat = f.get("masvs_id") or f.get("category") or ""
        matched_cat = None
        for k in MASVS_CATEGORIES:
            if k.lower() in cat.lower():
                matched_cat = k
                break
        if not matched_cat:
            # Heuristic match based on title or rule
            rule_text = (f.get("rule_id", "") + " " + f.get("title", "")).lower()
            if any(w in rule_text for w in ("storage", "sharedpref", "database", "sqlite")):
                matched_cat = "MASVS-STORAGE"
            elif any(w in rule_text for w in ("crypto", "cipher", "ecb", "md5", "sha1", "key")):
                matched_cat = "MASVS-CRYPTO"
            elif any(w in rule_text for w in ("auth", "biometric", "login", "session")):
                matched_cat = "MASVS-AUTH"
            elif any(w in rule_text for w in ("network", "cleartext", "http", "tls", "pinning")):
                matched_cat = "MASVS-NETWORK"
            elif any(w in rule_text for w in ("exported", "intent", "provider", "receiver")):
                matched_cat = "MASVS-PLATFORM"
            elif any(w in rule_text for w in ("debug", "minif", "r8", "proguard", "reflection")):
                matched_cat = "MASVS-CODE"
            else:
                matched_cat = "MASVS-RESILIENCE"

        domain_issues[matched_cat].append(f)

    # Specific manifest-based deductions
    if is_debuggable:
        domain_issues["MASVS-CODE"].append(
            {
                "id": "MASVS-CODE-DEBUGGABLE",
                "title": "Application has android:debuggable enabled in production build",
                "severity": "HIGH",
            }
        )
    if uses_cleartext:
        domain_issues["MASVS-NETWORK"].append(
            {
                "id": "MASVS-NETWORK-CLEARTEXT",
                "title": "Application explicitly allows unencrypted cleartext HTTP traffic",
                "severity": "HIGH",
            }
        )
    if not is_minified:
        domain_issues["MASVS-CODE"].append(
            {
                "id": "MASVS-CODE-OBFUSCATION",
                "title": "Application lacks ProGuard / R8 bytecode symbol minification",
                "severity": "MEDIUM",
            }
        )
    if not has_root_detection:
        domain_issues["MASVS-RESILIENCE"].append(
            {
                "id": "MASVS-RESILIENCE-ROOT",
                "title": "No root or emulator detection heuristics identified",
                "severity": "LOW",
            }
        )

    checklist: list[dict[str, Any]] = []
    domain_scores: dict[str, float] = {}
    total_score = 0.0

    for cat_id, cat_name in MASVS_CATEGORIES.items():
        issues = domain_issues[cat_id]
        issue_count = len(issues)
        if issue_count == 0:
            status = "PASS"
            score = 100.0
        elif issue_count == 1:
            status = "WARNING"
            score = 75.0
        else:
            status = "FAIL"
            score = max(20.0, 100.0 - (issue_count * 25.0))

        domain_scores[cat_id] = round(score, 1)
        total_score += score

        checklist.append(
            {
                "category_id": cat_id,
                "category_name": cat_name,
                "status": status,
                "compliance_score": round(score, 1),
                "issues_count": issue_count,
                "issues": issues[:5],  # top 5
            }
        )

    overall_pct = round(total_score / len(MASVS_CATEGORIES), 1)
    passed_count = sum(1 for c in checklist if c["status"] == "PASS")
    failed_count = sum(1 for c in checklist if c["status"] in ("FAIL", "WARNING"))

    # Prioritized remediation roadmap
    roadmap: list[str] = []
    if domain_issues["MASVS-NETWORK"]:
        roadmap.append("1. Disable cleartext and configure NetworkSecurityConfig with pinning.")
    if domain_issues["MASVS-PLATFORM"]:
        roadmap.append("2. Audit all exported components and add android:permission guards.")
    if domain_issues["MASVS-CRYPTO"]:
        roadmap.append("3. Replace weak ciphers (ECB/DES/MD5) with AES-GCM via AndroidKeyStore.")
    if domain_issues["MASVS-CODE"]:
        roadmap.append("4. Set debuggable=false and enforce R8 full-mode minification.")
    if not roadmap:
        roadmap.append("All primary MASVS categories meet baseline compliance.")

    return {
        "overall_compliance_pct": overall_pct,
        "is_masvs_compliant": overall_pct >= 80.0,
        "passed_controls_count": passed_count,
        "failed_controls_count": failed_count,
        "domain_scores": domain_scores,
        "checklist": checklist,
        "remediation_roadmap": roadmap,
    }


def suggest_next_reversing_steps(
    user_goal: str,
    detected_frameworks: list[str] | None = None,
    manifest_summary: dict[str, Any] | None = None,
    findings_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recommend optimal RAA tools and chaining strategy for an analyst query."""
    goal_lower = user_goal.lower()
    frameworks = detected_frameworks or []

    # Default tool suggestions
    suggested_tools: list[str] = []
    recommended_args: dict[str, Any] = {}
    steps: list[str] = []
    frida_script: str | None = None
    rationale: str = ""

    if any(k in goal_lower for k in ("pinning", "ssl", "tls", "cert", "proxy")):
        goal_type = "NETWORK_SECURITY_BYPASS"
        if "flutter" in [f.lower() for f in frameworks]:
            suggested_tools = ["flutter_unpin", "dynamic_inject_gadget", "instrument_start"]
            rationale = "Target app is Flutter. Native BoringSSL TLS unpinning is required."
            frida_script = (
                "// Flutter BoringSSL hook\n"
                "var m = Process.findModuleByName('libflutter.so');\n"
                "if (m) console.log('Hooking libflutter SSL verification...');"
            )
        else:
            suggested_tools = ["rebuild_apk", "sec_play_protect_audit", "dynamic_inject_gadget"]
            rationale = "Android standard TLS. Patch network_security_config.xml and sign."
            frida_script = (
                "Java.perform(function() {\n"
                "    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
                "});"
            )
        recommended_args = {"bypass_network_security": True}
        steps = [
            "1. Inspect active NetworkSecurityConfig with 'android_get_network_security_config'.",
            "2. Inject Frida gadget or patch user certificate trust using 'rebuild_apk'.",
            "3. Lease test device and monitor intercepted traffic.",
        ]

    elif any(k in goal_lower for k in ("crypto", "key", "aes", "cipher", "decrypt", "encrypt")):
        goal_type = "CRYPTOGRAPHIC_KEY_EXTRACTION"
        suggested_tools = ["source_search_classes", "instrument_start", "runtime_get_events"]
        recommended_args = {"pattern": "Cipher.getInstance", "hooks": ["hook_crypto_ciphers"]}
        rationale = "Identify SecretKeySpec and Cipher initialization in Dalvik and native layers."
        frida_script = (
            "Java.perform(function() {\n"
            "    var Cipher = Java.use('javax.crypto.Cipher');\n"
            "    Cipher.init.overload('int', 'java.security.Key').implementation = "
            "function(op, k) {\n"
            "        console.log('[*] Cipher.init key: ' + k.getEncoded());\n"
            "        return this.init(op, k);\n"
            "    };\n"
            "});"
        )
        steps = [
            "1. Search classes for KeyStore / Cipher via 'source_search_classes'.",
            "2. Attach runtime crypto hooks via 'instrument_start'.",
            "3. Trigger encrypted operations on device to capture raw keys.",
        ]

    elif any(k in goal_lower for k in ("intent", "export", "deeplink", "deep-link", "inject")):
        goal_type = "EXPORTED_COMPONENT_EXPLOIT"
        suggested_tools = ["sec_intent_redirection_scan", "sec_poc_validate", "sec_poc_generate"]
        recommended_args = {"vuln_type": "intent_redirection"}
        rationale = "Scan for exported activities processing untrusted caller intents."
        steps = [
            "1. Run 'sec_intent_redirection_scan' to catalog vulnerable intent forwarding.",
            "2. Generate verified non-destructive ADB Intent with 'sec_poc_validate'.",
            "3. Execute test intent on leased device to verify unauthorized state access.",
        ]

    elif any(k in goal_lower for k in ("database", "sqlite", "prefs", "storage", "token", "leak")):
        goal_type = "LOCAL_STORAGE_AUDIT"
        suggested_tools = ["dynamic_dump_storage", "sec_leaked_secret_scan", "sec_masvs_audit"]
        recommended_args = {"target_type": "all"}
        rationale = "Extract internal SQLite databases and SharedPreferences to find credentials."
        steps = [
            "1. Run 'dynamic_dump_storage' on target package.",
            "2. Query extracted SQLite tables for unencrypted session tokens.",
            "3. Validate compliance against MASVS-STORAGE domain.",
        ]

    else:
        goal_type = "GENERAL_REVERSING_TRIAGE"
        suggested_tools = ["manifest_get", "framework_list_detected", "sec_masvs_audit"]
        recommended_args = {}
        rationale = "Perform baseline orientation across manifest, framework detection, and MASVS."
        steps = [
            "1. Audit exported activities and services using 'manifest_get'.",
            "2. Identify hybrid technologies with 'framework_list_detected'.",
            "3. Run 'sec_masvs_audit' to generate compliance matrix.",
        ]

    return {
        "user_goal": user_goal,
        "goal_classification": goal_type,
        "rationale": rationale,
        "suggested_tools": suggested_tools,
        "recommended_arguments": recommended_args,
        "recommended_frida_script": frida_script,
        "workflow_steps": steps,
        "frameworks_considered": frameworks,
    }
