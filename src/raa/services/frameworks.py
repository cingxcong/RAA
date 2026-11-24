"""Framework and packer detection from container markers.

This is deliberately a filename-level detector. It proves what a package
contains without claiming that code was decompiled. Engine-backed detectors
replace or corroborate these findings in later phases.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from raa.domain.models import Confidence, FrameworkFinding, PackerFinding

if TYPE_CHECKING:
    from raa.domain.manifest import ManifestInfo


@dataclass(frozen=True, slots=True)
class FrameworkRule:
    id: str
    name: str
    category: str
    any_patterns: tuple[str, ...] = ()
    all_patterns: tuple[str, ...] = ()
    notes: str | None = None


FRAMEWORK_RULES: tuple[FrameworkRule, ...] = (
    FrameworkRule(
        id="flutter",
        name="Flutter",
        category="cross_platform",
        any_patterns=("lib/*/libflutter.so", "assets/flutter_assets/*"),
    ),
    FrameworkRule(
        id="react_native",
        name="React Native",
        category="cross_platform",
        any_patterns=(
            "assets/index.android.bundle",
            "lib/*/libhermes.so",
            "lib/*/libhermes-executor*.so",
            "lib/*/libreactnativejni.so",
        ),
        notes="Hermes bytecode may be present; bundle inspection is a later phase.",
    ),
    FrameworkRule(
        id="unity",
        name="Unity",
        category="game_engine",
        any_patterns=(
            "lib/*/libunity.so",
            "assets/bin/Data/*",
            "lib/*/libil2cpp.so",
        ),
        notes="IL2CPP metadata recovery requires a dedicated adapter.",
    ),
    FrameworkRule(
        id="unreal",
        name="Unreal Engine",
        category="game_engine",
        any_patterns=("lib/*/libUE4.so", "lib/*/libUnreal.so"),
    ),
    FrameworkRule(
        id="godot",
        name="Godot",
        category="game_engine",
        any_patterns=("lib/*/libgodot*.so", "assets/*.pck", "assets/*.pck.remap"),
    ),
    FrameworkRule(
        id="xamarin",
        name="Xamarin / .NET MAUI",
        category="cross_platform",
        any_patterns=(
            "lib/*/libmonodroid.so",
            "lib/*/libxa-internal-api.so",
            "assemblies/*",
        ),
    ),
    FrameworkRule(
        id="cordova",
        name="Cordova / Ionic",
        category="hybrid",
        any_patterns=(
            "assets/www/cordova.js",
            "assets/www/cordova_plugins.js",
            "lib/*/libcordova.so",
        ),
    ),
    FrameworkRule(
        id="capacitor",
        name="Capacitor",
        category="hybrid",
        any_patterns=(
            "assets/public/capacitor.config.json",
            "assets/capacitor.config.json",
            "lib/*/libcapacitor*.so",
        ),
    ),
    FrameworkRule(
        id="native_android",
        name="Native Android",
        category="native",
        all_patterns=("androidmanifest.xml", "classes*.dex"),
        notes="Manifest and DEX presence only; source analysis is a later phase.",
    ),
)


@dataclass(frozen=True, slots=True)
class PackerRule:
    id: str
    name: str
    patterns: tuple[str, ...]
    notes: str = "Filename heuristic only; confirm with APKiD or a dynamic dump."


PACKER_RULES: tuple[PackerRule, ...] = (
    PackerRule("jiagu", "360 Jiagu", ("libjiagu", "libjiagu_art", "libjiagu_a64")),
    PackerRule("bangcle", "Bangcle", ("libsecexe", "libsecmain", "libdexhelper")),
    PackerRule("tencent", "Tencent Shell", ("libshella", "libshellx", "libtup")),
    PackerRule("baidu", "Baidu Protect", ("libbaiduprotect",)),
    PackerRule("ali", "Alibaba Protect", ("libmobisec", "libzuma")),
    PackerRule("netease", "NetEase Protect", ("libnesec",)),
    PackerRule("kiwisec", "KiwiSec", ("libkwscmm", "libkwscr", "libkwsgmain")),
    PackerRule("generic", "Generic protector", ("libprotect", "libshell", "libexec.so")),
)


_DEX_FRAMEWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "flutter": ("io.flutter", "FlutterActivity", "FlutterApplication"),
    "react_native": ("com.facebook.react", "ReactActivity", "ReactApplication"),
    "unity": ("com.unity3d.player", "UnityPlayerActivity", "UnityPlayer"),
    "unreal": ("com.epicgames.ue4",),
    "godot": ("org.godotengine.godot",),
    "xamarin": ("mono.android", "mono.MonoRuntimeProvider"),
    "cordova": ("org.apache.cordova",),
    "capacitor": ("com.getcapacitor",),
}


def detect_frameworks(
    names: list[str],
    manifest: ManifestInfo | None = None,
    dex_index: Any | None = None,
) -> list[FrameworkFinding]:
    lowered = [name.lower().replace("\\", "/") for name in names]
    findings: list[FrameworkFinding] = []

    # Gather dex class names and strings if available
    dex_classes: set[str] = set()
    if dex_index is not None:
        dex_classes = {klass.name for klass in dex_index.classes}

    for rule in FRAMEWORK_RULES:
        matched_any = [
            pattern
            for pattern in rule.any_patterns
            if any(fnmatchcase(name, pattern) for name in lowered)
        ]
        matched_all = [
            pattern
            for pattern in rule.all_patterns
            if any(fnmatchcase(name, pattern) for name in lowered)
        ]
        matched = matched_any or matched_all

        # Check DEX markers
        dex_markers: list[str] = []
        if rule.id in _DEX_FRAMEWORK_MARKERS and dex_classes:
            for marker in _DEX_FRAMEWORK_MARKERS[rule.id]:
                if any(marker in cls for cls in dex_classes):
                    dex_markers.append(f"dex:{marker}")

        if not matched and not dex_markers:
            continue
        if rule.any_patterns and not matched_any and not dex_markers:
            continue
        if rule.all_patterns and len(matched_all) != len(rule.all_patterns) and not dex_markers:
            continue

        all_markers = matched + dex_markers
        confidence = (
            Confidence.DERIVED
            if (matched and dex_markers)
            else (Confidence.OBSERVED if matched else Confidence.INFERRED)
        )

        findings.append(
            FrameworkFinding(
                id=rule.id,
                name=rule.name,
                category=rule.category,
                confidence=confidence,
                markers=all_markers[:10],
                notes=rule.notes,
            )
        )
    return findings


def detect_packers(names: list[str]) -> list[PackerFinding]:
    lowered = [name.lower().replace("\\", "/") for name in names]
    findings: list[PackerFinding] = []
    for rule in PACKER_RULES:
        markers = [pattern for pattern in rule.patterns if any(pattern in name for name in lowered)]
        if not markers:
            continue
        findings.append(
            PackerFinding(
                id=rule.id,
                name=rule.name,
                confidence=Confidence.INFERRED,
                markers=markers,
                notes=rule.notes,
            )
        )
    return findings
