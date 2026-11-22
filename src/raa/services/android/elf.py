"""Bounded, dependency-free ELF metadata and symbol inspection for Android native libraries."""

from __future__ import annotations

import re
import struct

from raa.domain.native import ElfHeaderInfo, NativeSymbol, NativeSymbolsSummary

ELF_MAGIC = b"\x7fELF"

# Bitness
ELFCLASS32 = 1
ELFCLASS64 = 2

# Endianness
ELFDATA2LSB = 1
ELFDATA2MSB = 2

# Object file type
ET_EXEC = 2
ET_DYN = 3

# Machine architecture
EM_386 = 0x03
EM_ARM = 0x28
EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7
EM_RISCV = 0xF3

_MACHINE_NAMES: dict[int, str] = {
    EM_386: "x86",
    EM_ARM: "ARM",
    EM_X86_64: "x86_64",
    EM_AARCH64: "AArch64",
    EM_RISCV: "RISC-V",
}

_ABI_NAMES: dict[int, str] = {
    EM_386: "x86",
    EM_ARM: "armeabi-v7a",
    EM_X86_64: "x86_64",
    EM_AARCH64: "arm64-v8a",
    EM_RISCV: "riscv64",
}

_SYMBOL_BINDINGS: dict[int, str] = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
}

_SYMBOL_TYPES: dict[int, str] = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
}

_JNI_PREFIX = "Java_"
_JNI_PATTERN = re.compile(r"^Java_([a-zA-Z0-9_]+)$")


def demangle_jni(name: str) -> str:
    """Demangle a JNI exported function name into a Java class.method representation.

    According to the JNI specification:
    - _1 escapes to '_'
    - _2 escapes to ';'
    - _3 escapes to '['
    - Single '_' separates package segments and method name
    """
    if not name.startswith(_JNI_PREFIX):
        return name

    body = name[len(_JNI_PREFIX) :]
    # Replace JNI escape sequences with temporary placeholders
    body = body.replace("_1", "\x01").replace("_2", "\x02").replace("_3", "\x03")

    # The last unescaped '_' separates class and method
    parts = body.split("_")
    # Restore escape sequences in parts
    restored = [p.replace("\x01", "_").replace("\x02", ";").replace("\x03", "[") for p in parts]

    if len(restored) >= 2:
        package_class = ".".join(restored[:-1])
        method = restored[-1]
        return f"{package_class}.{method}"
    return ".".join(restored)


def parse_elf_header(data: bytes, path: str = "") -> ElfHeaderInfo | None:
    """Parse ELF identification and standard header fields from raw bytes."""
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        return None

    bitness_code = data[4]
    endian_code = data[5]

    bitness = 64 if bitness_code == ELFCLASS64 else 32
    endian_prefix = "<" if endian_code == ELFDATA2LSB else ">"
    endian_label = "little" if endian_code == ELFDATA2LSB else "big"

    # Elf32_Ehdr / Elf64_Ehdr
    e_type, e_machine = struct.unpack_from(f"{endian_prefix}HH", data, 16)
    is_shared = e_type == ET_DYN

    if bitness == 32:
        entry_point = struct.unpack_from(f"{endian_prefix}I", data, 24)[0]
    else:
        entry_point = struct.unpack_from(f"{endian_prefix}Q", data, 24)[0]

    machine = _MACHINE_NAMES.get(e_machine, f"Unknown (0x{e_machine:x})")
    abi = _ABI_NAMES.get(e_machine, "unknown")

    return ElfHeaderInfo(
        path=path,
        abi=abi,
        bitness=bitness,
        endianness=endian_label,
        machine=machine,
        entry_point=entry_point,
        is_shared_library=is_shared,
        sections=[],
    )


def extract_elf_symbols(
    data: bytes,
    library_name: str = "",
    *,
    max_symbols: int = 5000,
) -> NativeSymbolsSummary:
    """Extract exported, imported, and JNI symbols from an ELF shared library.

    Supports both section-header based symbol tables and string-scan fallbacks
    for stripped binaries.
    """
    header = parse_elf_header(data, library_name)
    if header is None:
        return NativeSymbolsSummary(
            library=library_name,
            abi="unknown",
            total_count=0,
        )

    endian_prefix = "<" if header.endianness == "little" else ">"
    is_64 = header.bitness == 64

    exported: list[NativeSymbol] = []
    imported: list[NativeSymbol] = []
    jni_symbols: list[NativeSymbol] = []
    has_jni_on_load = False

    # Attempt section-based parsing
    try:
        if is_64 and len(data) >= 64:
            e_shoff = struct.unpack_from(f"{endian_prefix}Q", data, 40)[0]
            e_shentsize = struct.unpack_from(f"{endian_prefix}H", data, 58)[0]
            e_shnum = struct.unpack_from(f"{endian_prefix}H", data, 60)[0]
            e_shstrndx = struct.unpack_from(f"{endian_prefix}H", data, 62)[0]
        elif not is_64 and len(data) >= 52:
            e_shoff = struct.unpack_from(f"{endian_prefix}I", data, 32)[0]
            e_shentsize = struct.unpack_from(f"{endian_prefix}H", data, 46)[0]
            e_shnum = struct.unpack_from(f"{endian_prefix}H", data, 48)[0]
            e_shstrndx = struct.unpack_from(f"{endian_prefix}H", data, 50)[0]
        else:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = 0, 0, 0, 0

        if e_shoff > 0 and e_shnum > 0 and e_shoff + e_shentsize * e_shnum <= len(data):
            # Read section names
            sh_entries = []
            for i in range(min(e_shnum, 128)):
                offset = e_shoff + i * e_shentsize
                if is_64:
                    sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link = (
                        struct.unpack_from(f"{endian_prefix}IIQQQQI", data, offset)
                    )
                else:
                    sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link = (
                        struct.unpack_from(f"{endian_prefix}IIIIIII", data, offset)
                    )
                sh_entries.append(
                    {
                        "name_idx": sh_name,
                        "type": sh_type,
                        "offset": sh_offset,
                        "size": sh_size,
                        "link": sh_link,
                    }
                )

            # String table for section names
            if e_shstrndx < len(sh_entries):
                shstr = sh_entries[e_shstrndx]
                shstr_data = data[shstr["offset"] : shstr["offset"] + shstr["size"]]
            else:
                shstr_data = b""

            for entry in sh_entries:
                idx = entry["name_idx"]
                end = shstr_data.find(b"\x00", idx)
                name = shstr_data[idx:end].decode("ascii", errors="replace") if end != -1 else ""
                entry["name"] = name
                if name:
                    header.sections.append(name)

            # Look for .dynsym (SHT_DYNSYM = 11) and .symtab (SHT_SYMTAB = 2)
            for entry in sh_entries:
                if entry["type"] in {2, 11} and entry["link"] < len(sh_entries):
                    strtab_entry = sh_entries[entry["link"]]
                    strtab_data = data[
                        strtab_entry["offset"] : strtab_entry["offset"] + strtab_entry["size"]
                    ]
                    sym_offset = entry["offset"]
                    sym_size = entry["size"]
                    sym_count = sym_size // (24 if is_64 else 16)

                    for s in range(min(sym_count, max_symbols)):
                        s_pos = sym_offset + s * (24 if is_64 else 16)
                        if is_64:
                            st_name, st_info, _st_other, st_shndx, st_value, _st_size = (
                                struct.unpack_from(f"{endian_prefix}IBBHQQ", data, s_pos)
                            )
                        else:
                            st_name, st_value, _st_size, st_info, _st_other, st_shndx = (
                                struct.unpack_from(f"{endian_prefix}IIIBBH", data, s_pos)
                            )

                        if st_name == 0 or st_name >= len(strtab_data):
                            continue
                        s_end = strtab_data.find(b"\x00", st_name)
                        sym_name = (
                            strtab_data[st_name:s_end].decode("utf-8", errors="replace")
                            if s_end != -1
                            else ""
                        )
                        if not sym_name:
                            continue

                        binding_id = st_info >> 4
                        type_id = st_info & 0xF
                        binding = _SYMBOL_BINDINGS.get(binding_id, f"0x{binding_id:x}")
                        sym_type = _SYMBOL_TYPES.get(type_id, f"0x{type_id:x}")
                        is_exp = st_shndx != 0  # SHN_UNDEF == 0
                        is_jni = sym_name.startswith(_JNI_PREFIX)
                        demangled = demangle_jni(sym_name) if is_jni else None

                        if sym_name == "JNI_OnLoad":
                            has_jni_on_load = True

                        native_sym = NativeSymbol(
                            name=sym_name,
                            symbol_type=sym_type,
                            binding=binding,
                            is_exported=is_exp,
                            is_jni=is_jni,
                            demangled_jni=demangled,
                            address=st_value if is_exp else None,
                        )

                        if is_jni:
                            jni_symbols.append(native_sym)
                        if is_exp:
                            exported.append(native_sym)
                        else:
                            imported.append(native_sym)
    except Exception:  # noqa: S110
        pass

    # Fallback heuristic: If section headers were stripped or empty, scan strings for JNI symbols
    if not exported and not jni_symbols:
        # Regex search for null-terminated strings
        for match in re.finditer(rb"(?:Java_[a-zA-Z0-9_]+|JNI_OnLoad)\x00", data):
            raw = match.group(0)[:-1].decode("utf-8", errors="replace")
            if raw == "JNI_OnLoad":
                has_jni_on_load = True
                exported.append(
                    NativeSymbol(
                        name="JNI_OnLoad",
                        symbol_type="FUNC",
                        binding="GLOBAL",
                        is_exported=True,
                    )
                )
            elif raw.startswith(_JNI_PREFIX):
                demangled = demangle_jni(raw)
                sym = NativeSymbol(
                    name=raw,
                    symbol_type="FUNC",
                    binding="GLOBAL",
                    is_exported=True,
                    is_jni=True,
                    demangled_jni=demangled,
                )
                jni_symbols.append(sym)
                exported.append(sym)

    total = len(exported) + len(imported)

    return NativeSymbolsSummary(
        library=library_name,
        abi=header.abi,
        exported_symbols=exported[:max_symbols],
        imported_symbols=imported[:max_symbols],
        jni_symbols=jni_symbols,
        total_count=total,
        has_jni_on_load=has_jni_on_load,
    )
