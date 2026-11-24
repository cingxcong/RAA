"""Huawei HarmonyOS and OpenHarmony HAP container and ArkTS ABC bytecode inspector."""

from __future__ import annotations

import json
import logging
import struct
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ArkTS Panda / ABC Bytecode Magic
PANDA_MAGIC = b"PANDA\x00\x00\x00"
ABC_MAGIC_QZBC = b"\x71\x7a\x62\x63"  # qzbc


def disassemble_harmony_abc(
    abc_path_or_bytes: str | Path | bytes,
) -> dict[str, Any]:
    """Parse and disassemble Huawei ArkTS classes.abc Panda bytecode file."""
    raw_data: bytes
    if isinstance(abc_path_or_bytes, (str, Path)):
        p = Path(abc_path_or_bytes)
        if not p.exists():
            raise FileNotFoundError(f"ABC bytecode file not found: {p}")
        raw_data = p.read_bytes()
    else:
        raw_data = abc_path_or_bytes

    if len(raw_data) < 16:
        raise ValueError("File too small for ArkTS ABC bytecode")

    magic = raw_data[:4]
    is_panda = raw_data.startswith(b"PANDA")
    is_qzbc = magic == ABC_MAGIC_QZBC

    version_str = "unknown"
    checksum = 0
    file_size = len(raw_data)

    if is_panda and len(raw_data) >= 20:
        checksum = struct.unpack("<I", raw_data[8:12])[0]
        version_bytes = raw_data[12:16]
        version_str = ".".join(str(b) for b in version_bytes)
    elif is_qzbc and len(raw_data) >= 16:
        checksum = struct.unpack("<I", raw_data[4:8])[0]
        version_str = "qzbc-v1"

    # Scan for common ArkTS / OpenHarmony UI decorators and components in string pool
    arkts_decorators = [
        "@Component",
        "@Entry",
        "@State",
        "@Prop",
        "@Link",
        "@Provide",
        "@Consume",
        "@Observed",
        "@Builder",
    ]
    detected_decorators: list[str] = []
    text_sample = raw_data.decode("utf-8", errors="ignore")

    for dec in arkts_decorators:
        if dec in text_sample:
            detected_decorators.append(dec)

    # Scan for common ArkUI components (Column, Row, Text, Button, Image, List, NavDestination)
    arkui_components = [
        "Column",
        "Row",
        "Stack",
        "Flex",
        "Text",
        "Button",
        "Image",
        "List",
        "ListItem",
        "Grid",
        "Tabs",
        "NavDestination",
        "Navigation",
    ]
    detected_components: list[str] = []
    for comp in arkui_components:
        if f'"{comp}"' in text_sample or f" {comp}(" in text_sample or comp in text_sample:
            detected_components.append(comp)

    # Estimate methods and classes count from Panda tables or pattern heuristics
    num_classes = text_sample.count("class ") + len(detected_decorators)
    num_methods = text_sample.count("function ") + text_sample.count("build()")

    return {
        "format": "ArkTS_ABC" if (is_panda or is_qzbc) else "Panda_Bytecode",
        "bytecode_size_bytes": file_size,
        "version": version_str,
        "checksum": f"0x{checksum:08X}",
        "detected_decorators": detected_decorators,
        "detected_components": detected_components[:15],
        "estimated_classes_count": max(1, num_classes),
        "estimated_methods_count": max(1, num_methods),
        "has_arkui_declarations": len(detected_decorators) > 0 or len(detected_components) > 0,
    }


def inspect_harmony_hap(hap_path: str | Path) -> dict[str, Any]:
    """Inspect Huawei HarmonyOS / OpenHarmony .hap application package."""
    p = Path(hap_path)
    if not p.exists():
        raise FileNotFoundError(f"HAP package not found: {p}")

    manifest_data: dict[str, Any] = {}
    is_stage_model = False
    abc_files: list[str] = []
    all_files: list[str] = []
    abc_summary: dict[str, Any] | None = None

    with zipfile.ZipFile(p, "r") as zf:
        all_files = zf.namelist()

        # Check for Stage Model: module.json
        if "module.json" in all_files:
            is_stage_model = True
            raw = zf.read("module.json").decode("utf-8", errors="ignore")
            try:
                manifest_data = json.loads(raw)
            except Exception as err:
                logger.debug("Failed parsing module.json: %s", err)

        # Check for FA Model: config.json
        elif "config.json" in all_files:
            is_stage_model = False
            raw = zf.read("config.json").decode("utf-8", errors="ignore")
            try:
                manifest_data = json.loads(raw)
            except Exception as err:
                logger.debug("Failed parsing config.json: %s", err)

        # Collect ABC bytecode files
        for fname in all_files:
            if fname.endswith(".abc"):
                abc_files.append(fname)

        if abc_files:
            try:
                first_abc_data = zf.read(abc_files[0])
                abc_summary = disassemble_harmony_abc(first_abc_data)
            except Exception as err:
                abc_summary = {"error": str(err)}

    # Extract app & module metadata
    bundle_name = None
    version_code = None
    version_name = None
    min_api_version = None
    device_types: list[str] = []
    abilities: list[dict[str, Any]] = []
    request_permissions: list[dict[str, Any]] = []

    if is_stage_model:
        app_sec = manifest_data.get("app", {})
        bundle_name = app_sec.get("bundleName")
        version_code = app_sec.get("versionCode")
        version_name = app_sec.get("versionName")
        min_api_version = app_sec.get("minAPIVersion")

        module_sec = manifest_data.get("module", {})
        device_types = module_sec.get("deviceTypes", [])
        raw_abilities = module_sec.get("abilities", [])
        if isinstance(raw_abilities, list):
            for ab in raw_abilities:
                if isinstance(ab, dict):
                    abilities.append(
                        {
                            "name": ab.get("name"),
                            "srcEntry": ab.get("srcEntry"),
                            "launchType": ab.get("launchType", "standard"),
                        }
                    )
        raw_perms = module_sec.get("requestPermissions", [])
        if isinstance(raw_perms, list):
            for rp in raw_perms:
                if isinstance(rp, dict):
                    request_permissions.append(
                        {
                            "name": rp.get("name"),
                            "reason": rp.get("reason"),
                            "usedScene": rp.get("usedScene", {}),
                        }
                    )
    else:  # FA Model config.json
        app_sec = manifest_data.get("app", {})
        bundle_name = app_sec.get("bundleName")
        version_sec = app_sec.get("version", {})
        if isinstance(version_sec, dict):
            version_code = version_sec.get("code")
            version_name = version_sec.get("name")

        device_config = manifest_data.get("deviceConfig", {})
        device_types = list(device_config.keys()) if isinstance(device_config, dict) else []
        module_sec = manifest_data.get("module", {})
        raw_abilities = module_sec.get("abilities", [])
        if isinstance(raw_abilities, list):
            for ab in raw_abilities:
                if isinstance(ab, dict):
                    abilities.append(
                        {
                            "name": ab.get("name"),
                            "type": ab.get("type"),
                        }
                    )
        raw_perms = module_sec.get("reqPermissions", [])
        if isinstance(raw_perms, list):
            for rp in raw_perms:
                if isinstance(rp, dict):
                    request_permissions.append({"name": rp.get("name")})

    return {
        "hap_path": str(p),
        "harmony_model": "Stage" if is_stage_model else "FA",
        "bundle_name": bundle_name,
        "version_code": version_code,
        "version_name": version_name,
        "min_api_version": min_api_version,
        "device_types": list(device_types),
        "abilities_count": len(abilities),
        "abilities": abilities,
        "permissions_count": len(request_permissions),
        "request_permissions": request_permissions,
        "abc_files": abc_files,
        "abc_summary": abc_summary,
        "total_files": len(all_files),
    }
