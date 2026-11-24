"""Apple iOS IPA and Mach-O binary reverse engineering and inspection engine."""

from __future__ import annotations

import logging
import plistlib
import struct
import zipfile
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

# Mach-O Magic constants
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# Load Command constants
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_RPATH = 0x1C | 0x80000000
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

CPU_TYPES = {
    0x0100000C: "ARM64",
    0x01000007: "x86_64",
    12: "ARM",
    7: "i386",
}


def parse_embedded_mobileprovision(prov_bytes: bytes) -> dict[str, Any]:
    """Extract embedded XML entitlement dictionary from signed mobileprovision profile."""
    start_tag = b"<?xml"
    end_tag = b"</plist>"
    start_idx = prov_bytes.find(start_tag)
    end_idx = prov_bytes.find(end_tag)

    if start_idx != -1 and end_idx != -1:
        xml_slice = prov_bytes[start_idx : end_idx + len(end_tag)]
        try:
            res = plistlib.loads(xml_slice)
            if isinstance(res, dict):
                return cast(dict[str, Any], res)
        except Exception as err:
            logger.debug("Failed parsing mobileprovision plist: %s", err)

    return {}


def disassemble_macho(
    binary_path_or_bytes: str | Path | bytes,
    deep_symbols: bool = True,
) -> dict[str, Any]:
    """Parse Mach-O 64-bit headers, load commands, encryption info, and linked dylibs."""
    raw_data: bytes
    if isinstance(binary_path_or_bytes, (str, Path)):
        p = Path(binary_path_or_bytes)
        if not p.exists():
            raise FileNotFoundError(f"Mach-O binary not found: {p}")
        raw_data = p.read_bytes()
    else:
        raw_data = binary_path_or_bytes

    if len(raw_data) < 32:
        raise ValueError("Binary data too short for Mach-O header")

    magic = struct.unpack(">I", raw_data[:4])[0]
    is_little = False
    is_64 = False

    if magic in {MH_MAGIC_64, MH_CIGAM_64}:
        is_64 = True
        is_little = magic == MH_CIGAM_64
    elif magic in {MH_MAGIC, MH_CIGAM}:
        is_64 = False
        is_little = magic == MH_CIGAM
    elif magic in {FAT_MAGIC, FAT_CIGAM}:
        # Handle FAT universal binary header: inspect first architecture
        nfat_arch = struct.unpack(">I", raw_data[4:8])[0]
        if nfat_arch > 0:
            offset = struct.unpack(">I", raw_data[16:20])[0]
            size = struct.unpack(">I", raw_data[20:24])[0]
            return disassemble_macho(raw_data[offset : offset + size], deep_symbols=deep_symbols)
        raise ValueError("Invalid FAT universal Mach-O header")
    else:
        raise ValueError(f"Unrecognized Mach-O magic: 0x{magic:08X}")

    fmt_prefix = "<" if is_little else ">"
    cputype, _, _, ncmds, _, _ = struct.unpack(
        f"{fmt_prefix}IIIIII",
        raw_data[4:28],
    )

    header_size = 32 if is_64 else 28
    cursor = header_size

    dylibs: list[str] = []
    segments: list[dict[str, Any]] = []
    encryption_info: dict[str, Any] = {"encrypted": False, "cryptid": 0}
    has_code_signature = False

    for _ in range(ncmds):
        if cursor + 8 > len(raw_data):
            break
        cmd, cmdsize = struct.unpack(f"{fmt_prefix}II", raw_data[cursor : cursor + 8])
        cmd_data = raw_data[cursor : cursor + cmdsize]

        if cmd in {LC_SEGMENT_64, LC_SEGMENT}:
            segname = cmd_data[8:24].rstrip(b"\x00").decode("utf-8", errors="ignore")
            segments.append({"segment": segname, "size": cmdsize})

        elif cmd == LC_LOAD_DYLIB:
            offset = struct.unpack(f"{fmt_prefix}I", cmd_data[8:12])[0]
            dylib_name = cmd_data[offset:].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
            dylibs.append(dylib_name)

        elif cmd in {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64}:
            cryptoff, cryptsize, cryptid = struct.unpack(
                f"{fmt_prefix}III",
                cmd_data[8:20],
            )
            encryption_info = {
                "encrypted": cryptid != 0,
                "cryptoff": cryptoff,
                "cryptsize": cryptsize,
                "cryptid": cryptid,
            }

        elif cmd == LC_CODE_SIGNATURE:
            has_code_signature = True

        cursor += cmdsize

    # Scan for common Swift / Objective-C class indicators
    detected_frameworks: list[str] = []
    for dlib in dylibs:
        base = dlib.split("/")[-1].replace(".framework", "")
        detected_frameworks.append(base)

    is_swift = False
    if deep_symbols:
        is_swift = b"libswiftCore" in raw_data or b"$s" in raw_data or b"_$s" in raw_data

    return {
        "architecture": CPU_TYPES.get(cputype, f"Unknown ({cputype})"),
        "cpu_type": cputype,
        "is_64bit": is_64,
        "load_commands_count": ncmds,
        "linked_dylibs_count": len(dylibs),
        "linked_dylibs": dylibs[:30],
        "frameworks_detected": detected_frameworks[:20],
        "segments": segments,
        "encryption_info": encryption_info,
        "has_code_signature": has_code_signature,
        "is_swift": is_swift,
    }


def inspect_ios_ipa(
    ipa_path: str | Path,
    extract_entitlements: bool = True,
) -> dict[str, Any]:
    """Parse iOS .ipa application container, Info.plist, and Mach-O binary."""
    p = Path(ipa_path)
    if not p.exists():
        raise FileNotFoundError(f"IPA file not found: {p}")

    app_name = None
    info_plist_dict: dict[str, Any] = {}
    mobileprovision_dict: dict[str, Any] = {}
    macho_summary: dict[str, Any] = {}
    file_list: list[str] = []

    with zipfile.ZipFile(p, "r") as zf:
        file_list = zf.namelist()

        # Identify app bundle path
        for name in file_list:
            if name.startswith("Payload/") and ".app/" in name:
                parts = name.split(".app/")[0].split("/")
                app_name = parts[-1] + ".app"
                break

        # Parse Info.plist
        info_plist_candidates = [
            n for n in file_list if n.startswith("Payload/") and n.endswith(".app/Info.plist")
        ]
        if info_plist_candidates:
            plist_bytes = zf.read(info_plist_candidates[0])
            try:
                info_plist_dict = plistlib.loads(plist_bytes)
            except Exception as err:
                logger.debug("Info.plist parsing exception: %s", err)

        # Parse embedded.mobileprovision
        if extract_entitlements:
            prov_candidates = [
                n
                for n in file_list
                if n.startswith("Payload/") and n.endswith(".app/embedded.mobileprovision")
            ]
            if prov_candidates:
                prov_bytes = zf.read(prov_candidates[0])
                mobileprovision_dict = parse_embedded_mobileprovision(prov_bytes)

        # Disassemble main Mach-O executable
        executable_name = info_plist_dict.get("CFBundleExecutable")
        if executable_name:
            binary_candidates = [
                n
                for n in file_list
                if n.startswith("Payload/") and n.endswith(f".app/{executable_name}")
            ]
            if binary_candidates:
                try:
                    bin_data = zf.read(binary_candidates[0])
                    macho_summary = disassemble_macho(bin_data)
                except Exception as err:
                    macho_summary = {"error": str(err)}

    # Security & privacy permissions
    permissions: dict[str, str] = {}
    for k, v in info_plist_dict.items():
        if k.startswith("NS") and ("UsageDescription" in k or "Permission" in k):
            permissions[k] = str(v)

    ats_dict = info_plist_dict.get("NSAppTransportSecurity", {})
    allows_arbitrary_loads = bool(
        ats_dict.get("NSAllowsArbitraryLoads") if isinstance(ats_dict, dict) else False
    )

    url_schemes: list[str] = []
    url_types = info_plist_dict.get("CFBundleURLTypes", [])
    if isinstance(url_types, list):
        for entry in url_types:
            if isinstance(entry, dict) and "CFBundleURLSchemes" in entry:
                schemes = entry["CFBundleURLSchemes"]
                if isinstance(schemes, list):
                    url_schemes.extend(schemes)

    entitlements = mobileprovision_dict.get("Entitlements", {})

    return {
        "ipa_path": str(p),
        "app_bundle_name": app_name,
        "bundle_id": info_plist_dict.get("CFBundleIdentifier"),
        "bundle_version": info_plist_dict.get("CFBundleShortVersionString")
        or info_plist_dict.get("CFBundleVersion"),
        "minimum_os_version": info_plist_dict.get("MinimumOSVersion"),
        "executable_name": executable_name,
        "url_schemes": sorted(set(url_schemes)),
        "permissions_count": len(permissions),
        "permissions": permissions,
        "app_transport_security": {
            "allows_arbitrary_loads": allows_arbitrary_loads,
            "ats_config": ats_dict,
        },
        "entitlements": entitlements,
        "macho_summary": macho_summary,
        "total_files_in_container": len(file_list),
    }
