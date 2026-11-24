"""Packer, protector, obfuscator, and anti-analysis detection service."""

from __future__ import annotations

import contextlib
import math
import zipfile
from pathlib import Path
from typing import Any

from raa.domain.unpacking import (
    AntiAnalysisFinding,
    AntiAnalysisKind,
    PackerDetectionReport,
    PackerFinding,
)
from raa.utils.time import utc_now

# Known signature rules for Android packers and protectors
_PACKER_RULES: list[dict[str, Any]] = [
    {
        "name": "Qihoo 360 Jiagu",
        "category": "packer",
        "libs": ("libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so"),
        "assets": ("libjiagu.so", "0OO00l111l1l", "jiagu"),
        "classes": ("com.stub.StubApp", "com.qihoo.util.StubApp"),
    },
    {
        "name": "Tencent Legu",
        "category": "packer",
        "libs": ("libshell.so", "libshella.so", "libshellx.so", "libtup.so", "libtxnas.so"),
        "assets": ("tosversion", "01101100", "01101111"),
        "classes": ("com.tencent.StubShell.TxAppEntry", "com.tencent.stub.TxAppEntry"),
    },
    {
        "name": "Bangcle / Secneo",
        "category": "packer",
        "libs": ("libsecexe.so", "libsecmain.so", "libSecShell.so", "libDexHelper.so"),
        "assets": ("classes.jar", "bangcleplugin"),
        "classes": ("com.secneo.apkwrapper.ApplicationWrapper", "com.secneo.apkwrapper.AW"),
    },
    {
        "name": "Baidu Protect",
        "category": "packer",
        "libs": ("libbaiduprotect.so", "libbaiduprotect_x86.so", "libprotectClass.so"),
        "assets": ("baiduprotect.jar", "baiduprotect1.jar"),
        "classes": ("com.baidu.protect.StubApplication", "com.baidu.protect.A"),
    },
    {
        "name": "Ali / Alibaba",
        "category": "packer",
        "libs": ("libmobisec.so", "libmobisecy.so", "libfakejni.so"),
        "assets": ("aliprotect.dat", "classes.dex.dat"),
        "classes": ("com.ali.mobisecenhance.StubApplication",),
    },
    {
        "name": "Medusa",
        "category": "packer",
        "libs": ("libmedusa.so", "libmedusajni.so"),
        "assets": ("medusa.dat",),
        "classes": ("com.medusa.StubApp",),
    },
    {
        "name": "DexGuard",
        "category": "protector",
        "libs": ("libdexguard.so",),
        "assets": ("dexguard",),
        "classes": (),
    },
]

# Anti-analysis string indicators
_ANTI_ANALYSIS_PATTERNS: list[tuple[AntiAnalysisKind, str, str, str]] = [
    (
        AntiAnalysisKind.ROOT_DETECTION,
        "SU Binary Check",
        "Scans for su binary in standard PATH and system directories.",
        "/system/bin/su",
    ),
    (
        AntiAnalysisKind.ROOT_DETECTION,
        "SU Binary Check",
        "Scans for su binary in system xbin directory.",
        "/system/xbin/su",
    ),
    (
        AntiAnalysisKind.ROOT_DETECTION,
        "Magisk / Superuser Check",
        "Checks for Magisk or SuperSU installed packages.",
        "com.topjohnwu.magisk",
    ),
    (
        AntiAnalysisKind.EMULATOR_DETECTION,
        "QEMU Hardware Properties",
        "Checks build properties for QEMU, Goldfish, or VirtualBox drivers.",
        "ro.kernel.qemu",
    ),
    (
        AntiAnalysisKind.EMULATOR_DETECTION,
        "Generic Device Model",
        "Validates if device model or manufacturer is generic/sdk.",
        "goldfish",
    ),
    (
        AntiAnalysisKind.DEBUGGER_DETECTION,
        "TracerPid Inspection",
        "Checks /proc/self/status for active TracerPid or ptrace attaching.",
        "TracerPid",
    ),
    (
        AntiAnalysisKind.DEBUGGER_DETECTION,
        "Debugger Connected API",
        "Queries android.os.Debug.isDebuggerConnected().",
        "isDebuggerConnected",
    ),
    (
        AntiAnalysisKind.HOOK_DETECTION,
        "Frida Server / Memory Check",
        "Checks /proc/self/maps for frida-agent, gadget, or TCP port 27042.",
        "frida-gadget",
    ),
    (
        AntiAnalysisKind.HOOK_DETECTION,
        "Frida Server Binary Check",
        "Checks for running or packaged frida-server daemon.",
        "frida-server",
    ),
    (
        AntiAnalysisKind.HOOK_DETECTION,
        "Xposed Framework Check",
        "Detects presence of XposedBridge or LSPosed hooks.",
        "de.robv.android.xposed",
    ),
    (
        AntiAnalysisKind.INTEGRITY_CHECK,
        "APK Signature Validation",
        "Programmatically checks PackageManager signature hashes to detect repacking.",
        "GET_SIGNATURES",
    ),
    (
        AntiAnalysisKind.INTEGRITY_CHECK,
        "DEX CRC / Hash Check",
        "Validates CRC32 or SHA-256 of loaded classes.dex files.",
        "classes.dex",
    ),
]


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte slice (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def detect_packers_and_protectors(
    apk_path: Path,
    artifact_id: str = "art_default",
) -> PackerDetectionReport:
    """Analyze APK structure, manifest, native libraries, and assets for packers."""
    packers: list[PackerFinding] = []
    protectors: list[PackerFinding] = []
    obfuscators: list[PackerFinding] = []
    compilers: list[PackerFinding] = []
    anti_analysis: list[AntiAnalysisFinding] = []

    if not apk_path.is_file():
        return PackerDetectionReport(artifact_id=artifact_id, is_packed=False)

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            file_names = zf.namelist()

            # 1. Inspect native libraries and assets against packer rules
            for rule in _PACKER_RULES:
                indicators: list[str] = []
                for lib in rule.get("libs", ()):
                    for fn in file_names:
                        if fn.startswith("lib/") and fn.endswith(f"/{lib}"):
                            indicators.append(f"Native library match: {fn}")

                for asset in rule.get("assets", ()):
                    for fn in file_names:
                        if fn.startswith("assets/") and (asset in fn or fn.endswith(asset)):
                            indicators.append(f"Asset file match: {fn}")

                if indicators:
                    finding = PackerFinding(
                        category=rule["category"],
                        name=rule["name"],
                        confidence="exact" if len(indicators) > 1 else "high",
                        indicators=indicators,
                    )
                    if rule["category"] == "packer":
                        packers.append(finding)
                    else:
                        protectors.append(finding)

            # 2. Inspect classes.dex for compiler signatures & obfuscation patterns
            dex_names = [n for n in file_names if n.endswith(".dex")]
            max_entropy = 0.0

            for dex_name in dex_names:
                with contextlib.suppress(Exception):
                    data = zf.read(dex_name)
                    e = _shannon_entropy(data[:65536])
                    if e > max_entropy:
                        max_entropy = e

                    # Search for compiler tags in strings section
                    if b"D8" in data or b"d8" in data:
                        compilers.append(
                            PackerFinding(
                                category="compiler",
                                name="Android D8 / R8 Compiler",
                                confidence="high",
                                indicators=[f"D8 tag in {dex_name}"],
                            )
                        )
                    elif b"dx" in data:
                        compilers.append(
                            PackerFinding(
                                category="compiler",
                                name="Legacy Android DX Compiler",
                                confidence="medium",
                                indicators=[f"DX tag in {dex_name}"],
                            )
                        )

                    # Inspect byte patterns for anti-analysis strings
                    for kind, name, desc, pat in _ANTI_ANALYSIS_PATTERNS:
                        if pat.encode("utf-8") in data:
                            anti_analysis.append(
                                AntiAnalysisFinding(
                                    kind=kind,
                                    name=name,
                                    description=desc,
                                    location=dex_name,
                                )
                            )

            # 3. Check for high-entropy encrypted blobs in assets
            for fn in file_names:
                if fn.startswith("assets/") and not fn.endswith((".png", ".jpg", ".webp")):
                    with contextlib.suppress(Exception):
                        sample = zf.read(fn)[:32768]
                        if len(sample) > 512:
                            e = _shannon_entropy(sample)
                            if e > 7.6:
                                if e > max_entropy:
                                    max_entropy = e
                                packers.append(
                                    PackerFinding(
                                        category="packer",
                                        name="High-Entropy Encrypted Asset",
                                        confidence="heuristic",
                                        indicators=[
                                            f"Asset '{fn}' has high entropy ({e:.2f} bits/byte)"
                                        ],
                                    )
                                )

            # 4. Check for ProGuard / R8 single-letter short package obfuscation
            has_single_letter = False
            for fn in dex_names:
                with contextlib.suppress(Exception):
                    data = zf.read(fn)
                    if b"L/a;" in data or b"La/a;" in data or b"La/b/c;" in data:
                        has_single_letter = True
                        break

            if has_single_letter:
                obfuscators.append(
                    PackerFinding(
                        category="obfuscator",
                        name="ProGuard / R8 Renaming",
                        confidence="high",
                        indicators=["Detected single-letter class hierarchy (e.g. La/a;) in DEX"],
                    )
                )

    except Exception as exc:
        packers.append(
            PackerFinding(
                category="packer",
                name="Scan Error",
                confidence="low",
                indicators=[str(exc)],
            )
        )

    is_packed = len(packers) > 0 or len(protectors) > 0

    return PackerDetectionReport(
        artifact_id=artifact_id,
        is_packed=is_packed,
        packers=packers,
        protectors=protectors,
        obfuscators=obfuscators,
        compilers=compilers,
        anti_analysis=anti_analysis,
        entropy_score=round(max_entropy, 3),
        scanned_at=utc_now(),
    )
