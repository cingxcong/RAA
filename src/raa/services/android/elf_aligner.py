"""Android 15 16KB Page Alignment Inspector and Auto-Patcher.

Audits ELF 32/64-bit shared objects (.so) inside APK archives to verify compliance
with Android 15's mandatory 16KB memory page size (p_align = 0x4000 = 16384 bytes).
Provides automated program header inspection and ELF segment alignment patching.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PAGE_SIZE_4KB = 4096  # 0x1000
PAGE_SIZE_16KB = 16384  # 0x4000


def inspect_elf_alignment(elf_bytes: bytes) -> dict[str, Any]:
    """Inspect ELF binary program headers for 16KB page alignment."""
    if len(elf_bytes) < 52 or not elf_bytes.startswith(ELF_MAGIC):
        return {
            "valid_elf": False,
            "error": "Not a valid ELF binary",
            "is_16kb_aligned": False,
        }

    ei_class = elf_bytes[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = elf_bytes[5]  # 1 = Little-endian, 2 = Big-endian
    endian = "<" if ei_data == 1 else ">"

    is_64bit = ei_class == 2

    if is_64bit:
        if len(elf_bytes) < 64:
            return {
                "valid_elf": False,
                "error": "Truncated 64-bit ELF header",
                "is_16kb_aligned": False,
            }
        e_phoff = struct.unpack(f"{endian}Q", elf_bytes[32:40])[0]
        e_phentsize = struct.unpack(f"{endian}H", elf_bytes[54:56])[0]
        e_phnum = struct.unpack(f"{endian}H", elf_bytes[56:58])[0]
    else:
        e_phoff = struct.unpack(f"{endian}I", elf_bytes[28:32])[0]
        e_phentsize = struct.unpack(f"{endian}H", elf_bytes[42:44])[0]
        e_phnum = struct.unpack(f"{endian}H", elf_bytes[44:46])[0]

    segments: list[dict[str, Any]] = []
    max_align = 0
    all_load_aligned = True

    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + e_phentsize > len(elf_bytes):
            break

        if is_64bit:
            p_type, _p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack(
                f"{endian}IIQQQQQQ", elf_bytes[off : off + 56]
            )
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, _p_flags, p_align = struct.unpack(
                f"{endian}IIIIIIII", elf_bytes[off : off + 32]
            )

        if p_type == PT_LOAD:
            is_aligned = p_align >= PAGE_SIZE_16KB
            if not is_aligned:
                all_load_aligned = False
            max_align = max(max_align, p_align)
            segments.append(
                {
                    "segment_index": i,
                    "type": "PT_LOAD",
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "file_size": p_filesz,
                    "mem_size": p_memsz,
                    "alignment": p_align,
                    "is_16kb_aligned": is_aligned,
                }
            )

    return {
        "valid_elf": True,
        "is_64bit": is_64bit,
        "endian": "little" if ei_data == 1 else "big",
        "segment_count": len(segments),
        "pt_load_segments": segments,
        "max_alignment": max_align,
        "is_16kb_aligned": all_load_aligned and (len(segments) > 0),
        "android_15_compatible": all_load_aligned and (len(segments) > 0),
    }


def patch_elf_16kb_alignment(elf_bytes: bytes) -> bytes:
    """Patch ELF program headers to declare 16KB (0x4000) alignment for PT_LOAD segments."""
    mutable = bytearray(elf_bytes)
    if len(mutable) < 52 or not mutable.startswith(ELF_MAGIC):
        return elf_bytes

    ei_class = mutable[4]
    ei_data = mutable[5]
    endian = "<" if ei_data == 1 else ">"
    is_64bit = ei_class == 2

    if is_64bit:
        if len(mutable) < 64:
            return elf_bytes
        e_phoff = struct.unpack(f"{endian}Q", mutable[32:40])[0]
        e_phentsize = struct.unpack(f"{endian}H", mutable[54:56])[0]
        e_phnum = struct.unpack(f"{endian}H", mutable[56:58])[0]
    else:
        e_phoff = struct.unpack(f"{endian}I", mutable[28:32])[0]
        e_phentsize = struct.unpack(f"{endian}H", mutable[42:44])[0]
        e_phnum = struct.unpack(f"{endian}H", mutable[44:46])[0]

    for i in range(e_phnum):
        off = e_phoff + (i * e_phentsize)
        if off + e_phentsize > len(mutable):
            break

        if is_64bit:
            p_type = struct.unpack(f"{endian}I", mutable[off : off + 4])[0]
            if p_type == PT_LOAD:
                struct.pack_into(f"{endian}Q", mutable, off + 48, PAGE_SIZE_16KB)
        else:
            p_type = struct.unpack(f"{endian}I", mutable[off : off + 4])[0]
            if p_type == PT_LOAD:
                struct.pack_into(f"{endian}I", mutable, off + 28, PAGE_SIZE_16KB)

    return bytes(mutable)


def audit_apk_16kb_alignment(apk_path: str | Path) -> dict[str, Any]:
    """Audit all native shared objects (.so) inside an APK for Android 15 16KB compatibility."""
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK file not found: {path}")

    results: list[dict[str, Any]] = []
    total_so_files = 0
    non_compliant_count = 0

    with zipfile.ZipFile(path, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                total_so_files += 1
                so_data = zf.read(name)
                report = inspect_elf_alignment(so_data)
                report["file_path"] = name
                report["file_size"] = len(so_data)
                if not report.get("is_16kb_aligned", False):
                    non_compliant_count += 1
                results.append(report)

    compliant = non_compliant_count == 0

    return {
        "apk_path": str(path),
        "total_native_libraries": total_so_files,
        "compliant_libraries": total_so_files - non_compliant_count,
        "non_compliant_libraries": non_compliant_count,
        "android_15_ready": compliant,
        "libraries": results,
    }
