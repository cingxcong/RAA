"""RASP (Runtime Application Self-Protection) and tamper detection signature scanner."""

from __future__ import annotations

import logging
import os
import re
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

KNOWN_FRAMEWORKS: dict[str, dict[str, Any]] = {
    "freeRASP": {
        "vendor": "Aheaditec / Talsec",
        "description": "freeRASP mobile in-app protection SDK",
        "class_patterns": [
            r"L?com/aheaditec/talsec",
            r"com\.aheaditec\.talsec",
            r"TalsecConfig",
            r"ThreatListener",
        ],
        "binary_patterns": [r"libtalsec\.so"],
    },
    "Promon": {
        "vendor": "Promon AS",
        "description": "Promon SHIELD app shielding and obfuscation",
        "class_patterns": [
            r"L?com/promon/shield",
            r"com\.promon\.shield",
            r"PromonShield",
        ],
        "binary_patterns": [r"libshield\.so", r"libpromon.*\.so"],
    },
    "DexGuard": {
        "vendor": "Guardsquare",
        "description": "DexGuard advanced Android hardening and obfuscation",
        "class_patterns": [
            r"L?com/guardsquare/dexguard",
            r"com\.guardsquare\.dexguard",
            r"DexGuard",
        ],
        "binary_patterns": [r"libdexguard\.so"],
    },
    "RootBeer": {
        "vendor": "Scottyab",
        "description": "Open-source root detection library for Android",
        "class_patterns": [
            r"L?com/scottyab/rootbeer",
            r"com\.scottyab\.rootbeer",
            r"RootBeer",
        ],
        "binary_patterns": [r"librootbeerx\.so"],
    },
    "Digital.ai (Arxan)": {
        "vendor": "Digital.ai",
        "description": "Arxan Application Protection",
        "class_patterns": [
            r"com\.arxan",
            r"ensureit",
        ],
        "binary_patterns": [r"libensureit\.so", r"libguardit\.so"],
    },
}

DETECTION_CATEGORIES: dict[str, list[tuple[str, str]]] = {
    "root_detection": [
        (r"/system/bin/su", "Su binary path check"),
        (r"/system/xbin/su", "Su binary path check"),
        (r"/sbin/su", "Su binary path check"),
        (r"Superuser\.apk", "Superuser APK presence check"),
        (r"magisk", "Magisk manager or binary check"),
        (r"daemonsu", "Daemon su check"),
        (r"test-keys", "Test-keys build tags check"),
    ],
    "debugger_detection": [
        (r"isDebuggerConnected", "android.os.Debug.isDebuggerConnected() check"),
        (r"waitingForDebugger", "android.os.Debug.waitingForDebugger() check"),
        (r"TracerPid", "/proc/self/status TracerPid inspection"),
        (r"ptrace", "Native ptrace attachment check"),
    ],
    "emulator_detection": [
        (r"goldfish", "QEMU/Goldfish emulator hardware string"),
        (r"ranchu", "QEMU Ranchu emulator kernel check"),
        (r"vbox86p", "Genymotion VirtualBox emulator check"),
        (r"google_sdk", "AOSP generic emulator build check"),
    ],
    "hooking_detection": [
        (r"frida", "Frida hooking framework detection"),
        (r"xposed", "Xposed framework detection"),
        (r"cydia", "Substrate / Cydia framework check"),
        (r"lsposed", "LSPosed framework check"),
        (r"gum-js-loop", "Frida GumJS runtime string"),
    ],
    "integrity_detection": [
        (r"PlayIntegrity", "Google Play Integrity API"),
        (r"SafetyNetClient", "Google SafetyNet attestation client"),
        (r"getPackageInfo.*64", "Package signature GET_SIGNATURES inspection"),
    ],
}


def scan_rasp_signatures(
    target_path: str,
    deep_native_scan: bool = True,
    frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Scan an APK or project directory for RASP and tamper detection signatures."""
    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    files_to_scan: list[tuple[str, bytes]] = []

    if target.is_file() and target.suffix.lower() in {".apk", ".zip"}:
        try:
            with zipfile.ZipFile(target, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex") or name.startswith("lib/") or name.endswith(".smali"):
                        data = zf.read(name)
                        files_to_scan.append((name, data))
        except Exception as err:
            raise ValueError(f"Failed to read archive {target_path}: {err}") from err
    elif target.is_dir():
        for root, _, filenames in os.walk(target):
            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext in {".dex", ".smali", ".java", ".kt", ".so", ".xml"}:
                    fpath = Path(root) / fname
                    rel_path = fpath.relative_to(target).as_posix()
                    try:
                        data = fpath.read_bytes()
                        files_to_scan.append((rel_path, data))
                    except Exception as err:
                        logger.debug("Failed reading %s: %s", fpath, err)
    else:
        raise ValueError(f"Target must be an APK archive or directory: {target_path}")

    detected_frameworks: list[dict[str, Any]] = []
    category_findings: dict[str, list[dict[str, Any]]] = {cat: [] for cat in DETECTION_CATEGORIES}
    total_signatures = 0

    active_frameworks = KNOWN_FRAMEWORKS
    if frameworks:
        lower_wanted = {f.lower() for f in frameworks}
        active_frameworks = {k: v for k, v in KNOWN_FRAMEWORKS.items() if k.lower() in lower_wanted}

    for name, data in files_to_scan:
        text_content = data.decode("utf-8", errors="ignore") if data else ""

        # Framework scan
        for fw_name, fw_meta in active_frameworks.items():
            matched_patterns: list[str] = []
            for pat in fw_meta["class_patterns"]:
                if re.search(pat, text_content):
                    matched_patterns.append(pat)
            if deep_native_scan:
                for bpat in fw_meta["binary_patterns"]:
                    if re.search(bpat, name) or (data and re.search(bpat.encode(), data)):
                        matched_patterns.append(bpat)

            if matched_patterns:
                existing = next((f for f in detected_frameworks if f["framework"] == fw_name), None)
                if existing:
                    existing["matched_signatures"].extend(matched_patterns)
                    existing["matched_signatures"] = sorted(set(existing["matched_signatures"]))
                    if name not in existing["file_locations"]:
                        existing["file_locations"].append(name)
                else:
                    detected_frameworks.append(
                        {
                            "framework": fw_name,
                            "vendor": fw_meta["vendor"],
                            "description": fw_meta["description"],
                            "confidence": "HIGH" if len(matched_patterns) > 1 else "MEDIUM",
                            "matched_signatures": sorted(set(matched_patterns)),
                            "file_locations": [name],
                        }
                    )
                total_signatures += len(matched_patterns)

        # Category scan
        for cat, rule_list in DETECTION_CATEGORIES.items():
            for regex_str, desc in rule_list:
                if re.search(regex_str, text_content, re.IGNORECASE):
                    category_findings[cat].append(
                        {
                            "rule": desc,
                            "pattern": regex_str,
                            "file": name,
                        }
                    )
                    total_signatures += 1

    # Deduplicate category findings
    for cat in category_findings:
        seen = set()
        deduped = []
        for finding in category_findings[cat]:
            key = (finding["rule"], finding["file"])
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        category_findings[cat] = deduped

    risk_level = "NONE"
    if detected_frameworks:
        risk_level = "CRITICAL"
    elif sum(len(v) for v in category_findings.values()) >= 5:
        risk_level = "HIGH"
    elif sum(len(v) for v in category_findings.values()) > 0:
        risk_level = "MEDIUM"

    recommendations: list[str] = []
    if detected_frameworks:
        for fw in detected_frameworks:
            recommendations.append(
                f"Deploy dyn_rasp_bypass_gen with '{fw['framework']}' to hook callbacks."
            )
    if category_findings["root_detection"]:
        recommendations.append("Apply RootBeer/su binary check bypass script or Magisk DenyList.")
    if category_findings["debugger_detection"]:
        recommendations.append("Hook android.os.Debug and /proc/self/status TracerPid using Frida.")
    if category_findings["emulator_detection"]:
        recommendations.append("Spoof android.os.Build properties to emulate physical device.")

    return {
        "target_path": str(target),
        "risk_level": risk_level,
        "total_signatures_found": total_signatures,
        "detected_frameworks": detected_frameworks,
        "detection_categories": category_findings,
        "files_scanned_count": len(files_to_scan),
        "recommendations": recommendations,
    }
