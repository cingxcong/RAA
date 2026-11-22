"""Inspection services for Flutter, React Native, Unity, and .NET frameworks."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import TYPE_CHECKING

from raa.domain.frameworks import (
    DotnetAssembliesSummary,
    DotnetAssembly,
    FlutterAssetInfo,
    FlutterAssetsSummary,
    FlutterSymbolsSummary,
    FrameworkCapability,
    ReactNativeBundleInfo,
    ReactNativeModulesSummary,
    UnityAssetsSummary,
    UnityMetadataSummary,
)
from raa.services.android.elf import extract_elf_symbols
from raa.services.inspection import read_archive_member

if TYPE_CHECKING:
    from raa.services.android.dex import DexIndex

_HERMES_MAGIC = b"\xc6\x1f\xbc\x03"
_IL2CPP_METADATA_MAGIC = 0xFAB11BAF
_PE_MAGIC = b"MZ"
_CLI_METADATA_MAGIC = b"BSJB"


def get_framework_capabilities() -> list[FrameworkCapability]:
    """Return the authoritative list of supported framework capabilities and limits."""
    return [
        FrameworkCapability(
            id="flutter",
            name="Flutter",
            category="cross_platform",
            supported_operations=[
                "asset_manifest_inventory",
                "font_manifest_parsing",
                "dart_snapshot_detection",
                "engine_version_extraction",
                "blutter_aot_analysis",
            ],
            recovery_modes=["metadata", "assets", "native_symbols", "engine_decompile"],
            supported_engines=["blutter", "reflutter"],
            limitations=[
                "Widget trees cannot be fully reconstructed from AOT snapshots.",
                "Dart source code is compiled to machine code; decompilation produces pseudocode.",
            ],
            notes="Flutter applications package assets in assets/flutter_assets/.",
        ),
        FrameworkCapability(
            id="react_native",
            name="React Native",
            category="cross_platform",
            supported_operations=[
                "bundle_inspection",
                "hermes_bytecode_detection",
                "hermes_version_extraction",
                "native_modules_indexing",
                "turbo_modules_indexing",
                "hermes_bytecode_disassembly",
            ],
            recovery_modes=["metadata", "bundle_inspection", "hermes_disassembly"],
            supported_engines=["hermes-dec", "hbctool", "webcrack"],
            limitations=[
                "Hermes bytecode disassembly requires version-matched bytecode decoders.",
                "Minified JavaScript bundles require deobfuscation.",
            ],
            notes="React Native applications bundle JavaScript in assets/index.android.bundle.",
        ),
        FrameworkCapability(
            id="unity",
            name="Unity",
            category="game_engine",
            supported_operations=[
                "asset_inventory",
                "il2cpp_metadata_parsing",
                "type_definitions_count",
                "string_literals_count",
                "il2cpp_dumper_analysis",
            ],
            recovery_modes=["metadata", "il2cpp_header", "il2cpp_dump"],
            supported_engines=["il2cppdumper", "cpp2il", "assetripper"],
            limitations=[
                "IL2CPP compiled code requires libil2cpp.so and global-metadata.dat.",
                "Custom obfuscated metadata headers require key recovery.",
            ],
            notes="Unity IL2CPP apps store type metadata in global-metadata.dat.",
        ),
        FrameworkCapability(
            id="xamarin",
            name="Xamarin / .NET MAUI",
            category="cross_platform",
            supported_operations=[
                "managed_assembly_inventory",
                "pe_cli_header_verification",
                "managed_type_inspection",
                "ilspy_decompilation",
            ],
            recovery_modes=["metadata", "cil_inspection", "ilspy_csharp"],
            supported_engines=["ilspy"],
            limitations=[
                "Assemblies compressed in assemblies.blob or assemblies.zip require unpacking.",
            ],
            notes="Xamarin applications package .NET assemblies in assemblies/ or assets/.",
        ),
        FrameworkCapability(
            id="native_android",
            name="Native Android",
            category="native",
            supported_operations=[
                "manifest_inspection",
                "dex_indexing",
                "resource_decoding",
                "elf_symbol_extraction",
                "jni_method_mapping",
                "jadx_decompilation",
                "apktool_smali",
            ],
            recovery_modes=["metadata", "bytecode", "decompiled_source", "smali"],
            supported_engines=["jadx", "apktool", "androguard", "apkid"],
            limitations=[],
            notes="Core Android execution environment using Dalvik/ART and JNI.",
        ),
    ]


def inspect_flutter_assets(
    apk_path: Path,
    archive_names: list[str],
    *,
    max_assets: int = 1000,
) -> FlutterAssetsSummary:
    """Inspect assets bundled inside assets/flutter_assets/."""
    assets: list[FlutterAssetInfo] = []
    font_families: list[str] = []
    manifest_entries: list[str] = []
    has_asset_manifest = False
    has_font_manifest = False

    flutter_prefix = "assets/flutter_assets/"

    for name in archive_names:
        lower = name.lower().replace("\\", "/")
        if not lower.startswith(flutter_prefix):
            continue

        rel_name = name[len(flutter_prefix) :]
        if not rel_name:
            continue

        is_manifest = False
        asset_type = "asset"

        if rel_name in {"AssetManifest.json", "AssetManifest.bin"}:
            has_asset_manifest = True
            is_manifest = True
            asset_type = "manifest"
            if rel_name == "AssetManifest.json":
                try:
                    content = read_archive_member(apk_path, name, max_bytes=1024 * 1024)
                    parsed = json.loads(content.decode("utf-8", errors="replace"))
                    if isinstance(parsed, dict):
                        manifest_entries.extend(list(parsed.keys())[:200])
                except Exception:  # noqa: S110
                    pass
        elif rel_name == "FontManifest.json":
            has_font_manifest = True
            is_manifest = True
            asset_type = "manifest"
            try:
                content = read_archive_member(apk_path, name, max_bytes=1024 * 1024)
                fonts = json.loads(content.decode("utf-8", errors="replace"))
                if isinstance(fonts, list):
                    for entry in fonts:
                        if isinstance(entry, dict) and "family" in entry:
                            font_families.append(str(entry["family"]))
            except Exception:  # noqa: S110
                pass
        elif any(rel_name.endswith(ext) for ext in {".png", ".jpg", ".jpeg", ".webp", ".svg"}):
            asset_type = "image"
        elif any(rel_name.endswith(ext) for ext in {".ttf", ".otf", ".woff"}):
            asset_type = "font"
        elif rel_name.endswith(".json"):
            asset_type = "json"
        elif rel_name.endswith(".frag") or rel_name.endswith(".vert") or rel_name.endswith(".sksl"):
            asset_type = "shader"

        assets.append(
            FlutterAssetInfo(
                path=name,
                size_bytes=0,
                asset_type=asset_type,
                is_manifest=is_manifest,
            )
        )

    return FlutterAssetsSummary(
        assets=assets[:max_assets],
        total_count=len(assets),
        font_families=sorted(font_families),
        has_asset_manifest=has_asset_manifest,
        has_font_manifest=has_font_manifest,
        manifest_entries=manifest_entries,
    )


def get_flutter_symbols(
    apk_path: Path,
    archive_names: list[str],
) -> FlutterSymbolsSummary:
    """Inspect libflutter.so and libapp.so to extract Flutter and Dart symbols."""
    symbols: list[str] = []
    build_id: str | None = None
    engine_version: str | None = None
    snapshot_type: str | None = None
    limitations: list[str] = []

    target_libs = [
        name
        for name in archive_names
        if name.endswith("libflutter.so") or name.endswith("libapp.so")
    ]

    for lib_path in target_libs:
        try:
            content = read_archive_member(apk_path, lib_path, max_bytes=8 * 1024 * 1024)
            summary = extract_elf_symbols(content, library_name=lib_path)

            for sym in summary.exported_symbols:
                name = sym.name
                if "Dart" in name or "Snapshot" in name or "Flutter" in name:
                    symbols.append(name)
                    if "VmSnapshot" in name:
                        snapshot_type = "AOT (VM Snapshot)"
                    elif "IsolateSnapshot" in name and not snapshot_type:
                        snapshot_type = "AOT (Isolate Snapshot)"

            # Scan strings for build-id or flutter engine commit hash (40-char hex)
            if not engine_version:
                import re

                match = re.search(rb"[0-9a-f]{40}", content)
                if match:
                    engine_version = match.group(0).decode("ascii")
        except Exception as exc:
            limitations.append(f"Failed to inspect {lib_path}: {exc}")

    return FlutterSymbolsSummary(
        engine_version=engine_version,
        snapshot_type=snapshot_type or ("AOT" if target_libs else None),
        build_id=build_id,
        symbols=sorted(set(symbols))[:500],
        total_count=len(symbols),
        recovery_mode="native_symbols_and_elf_strings",
        limitations=limitations,
    )


def inspect_react_native_bundle(
    apk_path: Path,
    archive_names: list[str],
) -> ReactNativeBundleInfo | None:
    """Inspect assets/index.android.bundle or custom bundle paths for Hermes or JS code."""
    bundle_name = None
    for candidate in (
        "assets/index.android.bundle",
        "assets/index.bundle",
        "assets/main.jsbundle",
    ):
        for name in archive_names:
            if name.lower().replace("\\", "/") == candidate:
                bundle_name = name
                break
        if bundle_name:
            break

    if not bundle_name:
        return None

    try:
        content = read_archive_member(apk_path, bundle_name, max_bytes=1024 * 1024)
    except Exception as exc:
        return ReactNativeBundleInfo(
            bundle_path=bundle_name,
            size_bytes=0,
            is_hermes=False,
            notes=[f"Failed to read bundle: {exc}"],
        )

    size = len(content)
    is_hermes = content.startswith(_HERMES_MAGIC)
    hermes_version = None

    if is_hermes and len(content) >= 8:
        hermes_version = struct.unpack_from("<I", content, 4)[0]

    has_source_map = b"sourceMappingURL=" in content
    minified = is_hermes or b"\n" not in content[:500] or len(content) > 10000

    sample = None
    if not is_hermes:
        sample = content[:300].decode("utf-8", errors="replace").strip()

    return ReactNativeBundleInfo(
        bundle_path=bundle_name,
        size_bytes=size,
        is_hermes=is_hermes,
        hermes_version=hermes_version,
        minified=minified,
        has_source_map=has_source_map,
        sample_text=sample,
        notes=[
            f"Hermes bytecode version: {hermes_version}"
            if is_hermes
            else "Standard JavaScript bundle."
        ],
    )


def list_react_native_modules(dex_index: DexIndex | None) -> ReactNativeModulesSummary:
    """Identify NativeModules, TurboModules, and ReactPackages in DEX classes."""
    if dex_index is None:
        return ReactNativeModulesSummary()

    components: set[str] = set()
    turbo_modules: set[str] = set()
    react_packages: set[str] = set()
    bridge_modules: set[str] = set()

    for klass in dex_index.classes:
        name = klass.name
        supers = klass.superclass or ""
        interfaces = klass.interfaces

        if "com.facebook.react.bridge.NativeModule" in interfaces or "NativeModule" in supers:
            bridge_modules.add(name)
        if "com.facebook.react.turbomodule.core.interfaces.TurboModule" in interfaces:
            turbo_modules.add(name)
        if "com.facebook.react.ReactPackage" in interfaces or "ReactPackage" in supers:
            react_packages.add(name)
        if "com.facebook.react.uimanager.ViewManager" in supers:
            components.add(name)

    total = len(components) + len(turbo_modules) + len(react_packages) + len(bridge_modules)

    return ReactNativeModulesSummary(
        components=sorted(components),
        turbo_modules=sorted(turbo_modules),
        react_packages=sorted(react_packages),
        bridge_modules=sorted(bridge_modules),
        total_count=total,
    )


def inspect_unity_assets(
    apk_path: Path,
    archive_names: list[str],
) -> UnityAssetsSummary:
    """List Unity assets, scene files, and global metadata."""
    data_files: list[str] = []
    streaming_assets: list[str] = []
    has_metadata = False

    for name in archive_names:
        lower = name.lower().replace("\\", "/")
        if "assets/bin/data/" in lower:
            data_files.append(name)
            if "global-metadata.dat" in lower:
                has_metadata = True
        elif "assets/streamingassets/" in lower:
            streaming_assets.append(name)

    total = len(data_files) + len(streaming_assets)
    return UnityAssetsSummary(
        data_files=data_files[:500],
        streaming_assets=streaming_assets[:500],
        has_global_metadata=has_metadata,
        total_count=total,
    )


def get_unity_metadata(apk_path: Path, archive_names: list[str]) -> UnityMetadataSummary:
    """Parse header of Unity global-metadata.dat if present."""
    metadata_path = None
    for name in archive_names:
        if (
            name.lower()
            .replace("\\", "/")
            .endswith("assets/bin/data/managed/metadata/global-metadata.dat")
        ):
            metadata_path = name
            break

    if not metadata_path:
        return UnityMetadataSummary(notes=["global-metadata.dat was not found in the APK."])

    try:
        content = read_archive_member(apk_path, metadata_path, max_bytes=1024 * 1024)
        if len(content) < 32:
            return UnityMetadataSummary(notes=["global-metadata.dat is too small."])

        magic, version = struct.unpack_from("<II", content, 0)
        if magic != _IL2CPP_METADATA_MAGIC:
            return UnityMetadataSummary(
                notes=[f"Invalid IL2CPP metadata magic: 0x{magic:08x} (expected 0xFAB11BAF)."]
            )

        string_literal_count = struct.unpack_from("<I", content, 12)[0] if len(content) >= 16 else 0
        type_definitions_count = (
            struct.unpack_from("<I", content, 100)[0] if len(content) >= 104 else 0
        )

        return UnityMetadataSummary(
            format_version=version,
            is_valid=True,
            string_literal_count=string_literal_count,
            type_definitions_count=type_definitions_count,
            notes=[f"Valid IL2CPP metadata format version {version}."],
        )
    except Exception as exc:
        return UnityMetadataSummary(notes=[f"Failed to parse global-metadata.dat: {exc}"])


def list_dotnet_assemblies(
    apk_path: Path,
    archive_names: list[str],
) -> DotnetAssembliesSummary:
    """List managed assemblies (.dll) bundled in Xamarin or .NET MAUI applications."""
    assemblies: list[DotnetAssembly] = []
    notes: list[str] = []

    for name in archive_names:
        lower = name.lower().replace("\\", "/")
        if lower.endswith(".dll") or "assemblies/" in lower:
            # Check for PE / CIL header
            is_pe = False
            is_cil = False
            try:
                header = read_archive_member(apk_path, name, max_bytes=512)
                if header.startswith(_PE_MAGIC):
                    is_pe = True
                if _CLI_METADATA_MAGIC in header:
                    is_cil = True
            except Exception:  # noqa: S110
                pass

            assemblies.append(
                DotnetAssembly(
                    name=name,
                    size_bytes=0,
                    is_pe=is_pe,
                    is_cil=is_cil,
                )
            )

    if not assemblies:
        notes.append("No managed .NET assemblies found.")

    return DotnetAssembliesSummary(
        assemblies=assemblies[:500],
        total_count=len(assemblies),
        runtime="xamarin_or_dotnet_maui",
        notes=notes,
    )
