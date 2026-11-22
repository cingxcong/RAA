"""Unit and integration tests for Phase 3 framework adapters and native inspection."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from raa.domain.models import Confidence
from raa.errors import NotFoundError
from raa.runtime import Runtime
from raa.services.android.elf import demangle_jni, extract_elf_symbols, parse_elf_header
from raa.services.frameworks import detect_frameworks
from tests.conftest import make_apk


def _build_test_elf_64(symbols: list[str]) -> bytes:
    """Build a minimal valid 64-bit ELF binary containing dynamic symbols."""
    # Build strtab
    strtab = bytearray(b"\x00")
    sym_records = []
    for sym in symbols:
        name_offset = len(strtab)
        strtab.extend(sym.encode("utf-8") + b"\x00")
        sym_records.append((name_offset, 0x12, 1, 0x1000))  # STB_GLOBAL, STT_FUNC, SHN=1

    # Header is 64 bytes
    ehdr_size = 64
    shent_size = 64
    shnum = 4  # 0: NULL, 1: .text, 2: .dynstr, 3: .dynsym
    shstrndx = 2

    # Layout offsets
    text_off = ehdr_size
    text_size = 16
    strtab_off = text_off + text_size
    strtab_size = len(strtab)
    symtab_off = (strtab_off + strtab_size + 7) & ~7

    # Symtab entries (24 bytes each)
    symtab_data = bytearray(24)  # entry 0 is NULL
    for name_off, info, shndx, value in sym_records:
        symtab_data.extend(struct.pack("<IBBHQQ", name_off, info, 0, shndx, value, 32))
    symtab_size = len(symtab_data)

    shoff = (symtab_off + symtab_size + 7) & ~7

    # Section headers
    shdrs = bytearray(shent_size)  # Section 0: NULL
    # Section 1: .text (PROGBITS = 1)
    shdrs.extend(struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x1000, text_off, text_size, 0, 0, 16, 0))
    # Section 2: .dynstr (STRTAB = 3)
    shdrs.extend(struct.pack("<IIQQQQIIQQ", 7, 3, 2, 0, strtab_off, strtab_size, 0, 0, 1, 0))
    # Section 3: .dynsym (DYNSYM = 11, link=2)
    shdrs.extend(struct.pack("<IIQQQQIIQQ", 15, 11, 2, 0, symtab_off, symtab_size, 2, 1, 8, 24))

    # Construct complete ELF
    elf = bytearray(shoff + len(shdrs))
    # ELF header
    elf[:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # Little endian
    elf[6] = 1  # Version
    struct.pack_into("<HH", elf, 16, 3, 0xB7)  # ET_DYN, EM_AARCH64
    struct.pack_into("<Q", elf, 24, 0x1000)  # entry
    struct.pack_into("<Q", elf, 40, shoff)  # e_shoff
    struct.pack_into("<HHHHHH", elf, 52, ehdr_size, 0, 0, shent_size, shnum, shstrndx)

    # Insert contents
    elf[text_off : text_off + text_size] = b"\x00" * text_size
    elf[strtab_off : strtab_off + strtab_size] = strtab
    elf[symtab_off : symtab_off + symtab_size] = symtab_data
    elf[shoff : shoff + len(shdrs)] = shdrs

    return bytes(elf)


async def _project_and_artifact(runtime: Runtime, apk_path: Path) -> tuple[str, str]:
    proj = await runtime.invoke("project_create", {"name": "Phase 3 Test"})
    project_id = proj.data["id"]
    ingest = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(apk_path)},
    )
    return project_id, ingest.data["id"]


async def _run_analysis(runtime: Runtime, project_id: str, artifact_id: str) -> str:
    started = await runtime.invoke(
        "analysis_start",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    assert job.status.value == "completed"
    return str(job.id)


def test_jni_demangling() -> None:
    assert demangle_jni("Java_com_example_app_MainActivity_stringFromJNI") == (
        "com.example.app.MainActivity.stringFromJNI"
    )
    assert demangle_jni("Java_com_example_app_Utils_calculate_1hash") == (
        "com.example.app.Utils.calculate_hash"
    )


def test_elf_header_parsing() -> None:
    elf_data = _build_test_elf_64(["Java_com_demo_MainActivity_nativeFunc", "JNI_OnLoad"])
    header = parse_elf_header(elf_data, "libdemo.so")
    assert header is not None
    assert header.bitness == 64
    assert header.endianness == "little"
    assert header.machine == "AArch64"
    assert header.abi == "arm64-v8a"
    assert header.is_shared_library is True


def test_elf_symbol_extraction() -> None:
    elf_data = _build_test_elf_64(["Java_com_demo_MainActivity_nativeFunc", "JNI_OnLoad"])
    summary = extract_elf_symbols(elf_data, "libdemo.so")
    assert summary.has_jni_on_load is True
    assert len(summary.jni_symbols) == 1
    assert summary.jni_symbols[0].name == "Java_com_demo_MainActivity_nativeFunc"
    assert summary.jni_symbols[0].demangled_jni == "com.demo.MainActivity.nativeFunc"


async def test_framework_get_capabilities(runtime: Runtime) -> None:
    res = await runtime.invoke("framework_get_capabilities", {})
    caps = res.data["capabilities"]
    assert len(caps) >= 5
    ids = {c["id"] for c in caps}
    assert {"flutter", "react_native", "unity", "xamarin", "native_android"} <= ids

    single = await runtime.invoke("framework_get_capabilities", {"framework_id": "flutter"})
    assert len(single.data["capabilities"]) == 1
    assert single.data["capabilities"][0]["id"] == "flutter"

    with pytest.raises(NotFoundError):
        await runtime.invoke("framework_get_capabilities", {"framework_id": "nonexistent"})


async def test_flutter_assets_and_symbols(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    res = await runtime.invoke(
        "flutter_list_assets",
        {"project_id": project_id, "job_id": job_id},
    )
    data = res.data
    assert data["has_asset_manifest"] is True
    assert data["total_count"] >= 2
    types = {a["asset_type"] for a in data["assets"]}
    assert "manifest" in types or "font" in types

    symbols = await runtime.invoke(
        "flutter_get_symbols",
        {"project_id": project_id, "job_id": job_id},
    )
    assert symbols.data["snapshot_type"] is not None


async def test_react_native_bundle_inspection(runtime: Runtime, tmp_path: Path) -> None:
    # 1. Hermes bundle: magic 0x03BC1FC6, version 90 (0x5A)
    hermes_payload = b"\xc6\x1f\xbc\x03" + struct.pack("<I", 90) + b"\x00" * 32
    apk = make_apk(
        tmp_path / "hermes.apk",
        entries={
            "assets/index.android.bundle": hermes_payload,
            "lib/arm64-v8a/libhermes.so": b"\x7fELF" + b"\x00" * 32,
        },
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    bundle_res = await runtime.invoke(
        "react_native_inspect_bundle",
        {"project_id": project_id, "job_id": job_id},
    )
    data = bundle_res.data
    assert data["is_hermes"] is True
    assert data["hermes_version"] == 90

    modules = await runtime.invoke(
        "react_native_list_modules",
        {"project_id": project_id, "job_id": job_id},
    )
    assert "components" in modules.data


async def test_unity_assets_and_metadata(runtime: Runtime, tmp_path: Path) -> None:
    # IL2CPP metadata: magic 0xFAB11BAF, version 27
    meta_header = struct.pack("<II", 0xFAB11BAF, 27) + b"\x00" * 200
    apk = make_apk(
        tmp_path / "unity.apk",
        entries={
            "assets/bin/Data/Managed/Metadata/global-metadata.dat": meta_header,
            "assets/bin/Data/data.unity3d": b"UnityFS" + b"\x00" * 16,
            "lib/arm64-v8a/libunity.so": b"\x7fELF" + b"\x00" * 32,
            "lib/arm64-v8a/libil2cpp.so": b"\x7fELF" + b"\x00" * 32,
        },
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    unity_meta = await runtime.invoke(
        "unity_get_metadata",
        {"project_id": project_id, "job_id": job_id},
    )
    assert unity_meta.data["is_valid"] is True
    assert unity_meta.data["format_version"] == 27

    unity_assets = await runtime.invoke(
        "unity_list_assets",
        {"project_id": project_id, "job_id": job_id},
    )
    assert unity_assets.data["has_global_metadata"] is True
    assert unity_assets.data["total_count"] >= 2


async def test_dotnet_assemblies(runtime: Runtime, tmp_path: Path) -> None:
    pe_dll = b"MZ" + b"\x00" * 30 + b"BSJB" + b"\x00" * 32
    apk = make_apk(
        tmp_path / "dotnet.apk",
        entries={
            "assemblies/MyCustomApp.dll": pe_dll,
            "lib/arm64-v8a/libmonodroid.so": b"\x7fELF" + b"\x00" * 32,
        },
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    res = await runtime.invoke(
        "dotnet_list_assemblies",
        {"project_id": project_id, "job_id": job_id},
    )
    assert res.data["total_count"] >= 1
    assert res.data["assemblies"][0]["is_pe"] is True
    assert res.data["assemblies"][0]["is_cil"] is True

    type_info = await runtime.invoke(
        "dotnet_get_type",
        {"project_id": project_id, "job_id": job_id, "assembly_name": "MyCustomApp.dll"},
    )
    assert type_info.data["assembly_name"] == "MyCustomApp.dll"


async def test_native_library_and_jni_mapping(runtime: Runtime, tmp_path: Path) -> None:
    symbols = ["Java_com_example_demo_MainActivity_stringFromJNI", "JNI_OnLoad"]
    elf_data = _build_test_elf_64(symbols)
    apk = make_apk(
        tmp_path / "native.apk",
        entries={
            "lib/arm64-v8a/libnative.so": elf_data,
        },
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    analyzed = await runtime.invoke(
        "native_analyze_library",
        {"project_id": project_id, "job_id": job_id, "library_path": "lib/arm64-v8a/libnative.so"},
    )
    assert analyzed.data["bitness"] == 64
    assert analyzed.data["machine"] == "AArch64"

    symbols = await runtime.invoke(
        "native_get_symbols",
        {
            "project_id": project_id,
            "job_id": job_id,
            "library_path": "lib/arm64-v8a/libnative.so",
            "kind": "jni",
        },
    )
    assert symbols.data["count"] == 1
    assert symbols.data["symbols"][0]["name"] == "Java_com_example_demo_MainActivity_stringFromJNI"
    assert symbols.data["has_jni_on_load"] is True

    jni = await runtime.invoke(
        "jni_map",
        {"project_id": project_id, "job_id": job_id},
    )
    assert "total_native_methods" in jni.data


def test_multi_label_framework_detection() -> None:
    files = [
        "lib/arm64-v8a/libflutter.so",
        "assets/flutter_assets/AssetManifest.json",
        "assets/index.android.bundle",
        "lib/arm64-v8a/libhermes.so",
    ]
    detected = detect_frameworks(files)
    ids = {d.id for d in detected}
    assert "flutter" in ids
    assert "react_native" in ids
    for d in detected:
        assert d.confidence in {Confidence.OBSERVED, Confidence.DERIVED}
