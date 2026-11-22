"""Phase 8 Obfuscation, Native, and Unpacking tests.

Verifies:
1. Packer and protector detection (commercial signatures, anti-analysis, and entropy scoring).
2. Static payload carving (embedded DEX, XOR-obfuscated DEX, and nested ZIP archives).
3. Dump completeness verification (Adler32, SHA-1, class header data, stub vs complete).
4. Automated re-analysis ingestion into project artifact catalog on dump verification.
5. Deobfuscator transformations (reflection resolution, string decryption, dead code pruning)
   with mandatory provenance warning header.
6. ProGuard/R8 retrace engine (mapping syntax, stack trace line mapping, coverage calculation).
7. Native library inventory across ABIs (ELF architecture, bitness, endianness, dependencies).
8. Native adapter fallbacks (Ghidra, Rizin, and ELF parser).
9. Full integration through Runtime.invoke across all Phase 8 tools.
10. Typer CLI subcommands under `raa unpack` and `raa native libraries`.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from raa.cli.main import app
from raa.domain.unpacking import (
    AntiAnalysisKind,
    CompletenessStatus,
)
from raa.runtime import Runtime
from raa.services.android.deobfuscator import deobfuscate_source
from raa.services.android.dump_verifier import verify_dex_dump
from raa.services.android.native_adapters import (
    GhidraNativeAdapter,
    RizinNativeAdapter,
    inventory_native_libraries,
)
from raa.services.android.packer_detector import (
    _shannon_entropy,
    detect_packers_and_protectors,
)
from raa.services.android.payload_extractor import extract_static_payloads
from raa.services.android.retracer import (
    execute_retrace,
    parse_mapping_file,
    retrace_stack_trace,
)
from tests.axml_builder import build_sample_manifest
from tests.conftest import make_apk
from tests.dex_builder import build_sample_dex

runner = CliRunner()


# --- Helper: Create Stub DEX with class_data_off == 0 ---


def _make_stub_dex() -> bytes:
    """Build a DEX byte array where class_data_off == 0 (packer shell stub)."""
    raw = bytearray(build_sample_dex())
    class_defs_size, class_defs_off = struct.unpack_from("<II", raw, 96)
    for i in range(class_defs_size):
        off = class_defs_off + (i * 32)
        # class_data_off is at offset + 24
        struct.pack_into("<I", raw, off + 24, 0)

    # Recalculate SHA-1 (bytes 32..EOF stored at 12..32)
    sig = hashlib.sha1(raw[32:]).digest()  # noqa: S324
    raw[12:32] = sig

    # Recalculate Adler32 (bytes 12..EOF stored at 8..12)
    checksum = zlib.adler32(raw[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", raw, 8, checksum)

    return bytes(raw)


# --- Tests: Packer & Anti-Analysis Detection ---


def test_packer_detector_clean(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "clean.apk")
    report = detect_packers_and_protectors(apk)
    assert report.is_packed is False
    assert len(report.packers) == 0
    assert len(report.anti_analysis) == 0


def test_packer_detector_signatures(tmp_path: Path) -> None:
    # Build APK with Qihoo 360 Jiagu packer + anti-analysis indicators
    packed_apk = tmp_path / "packed.apk"
    jiagu_elf = b"\x7fELF" + b"\x00" * 200
    dex_with_indicators = (
        b"dex\n035\x00"
        + b"\x00" * 30
        + b"/system/xbin/su\x00"
        + b"ro.kernel.qemu\x00"
        + b"/proc/self/status\x00TracerPid\x00"
        + b"frida-server\x00"
        + b"classes.dex\x00"
    )
    entries = {
        "lib/arm64-v8a/libjiagu.so": jiagu_elf,
        "assets/libjiagu.so": jiagu_elf,
        "classes.dex": dex_with_indicators,
        "AndroidManifest.xml": build_sample_manifest(),
    }
    make_apk(packed_apk, entries=entries, include_dex=False)

    report = detect_packers_and_protectors(packed_apk)
    assert report.is_packed is True
    assert any("Jiagu" in p.name for p in report.packers)

    anti_kinds = {a.kind for a in report.anti_analysis}
    assert AntiAnalysisKind.ROOT_DETECTION in anti_kinds
    assert AntiAnalysisKind.EMULATOR_DETECTION in anti_kinds
    assert AntiAnalysisKind.DEBUGGER_DETECTION in anti_kinds
    assert AntiAnalysisKind.HOOK_DETECTION in anti_kinds


def test_shannon_entropy() -> None:
    uniform_data = bytes(range(256)) * 4
    high_entropy = _shannon_entropy(uniform_data)
    assert high_entropy > 7.9

    constant_data = b"\x00" * 1024
    zero_entropy = _shannon_entropy(constant_data)
    assert zero_entropy == 0.0


# --- Tests: Payload Extraction ---


def test_payload_extractor(tmp_path: Path) -> None:
    apk_path = tmp_path / "with_payloads.apk"
    valid_dex = build_sample_dex()

    # Create XOR-obfuscated DEX (key = 0x5A)
    xor_dex = bytes(b ^ 0x5A for b in valid_dex[:256])

    # Create nested ZIP
    inner_zip_bytes = b"PK\x03\x04" + b"\x00" * 50

    entries = {
        "assets/embedded.dex": valid_dex,
        "res/raw/encrypted.bin": xor_dex,
        "assets/nested.zip": inner_zip_bytes,
    }
    make_apk(apk_path, entries=entries)

    out_dir = tmp_path / "extracted_payloads"
    report = extract_static_payloads(apk_path, output_dir=out_dir)

    assert report.total_payloads_found >= 2
    assert out_dir.is_dir()
    for p in report.payloads:
        assert Path(p.output_path).exists()
        assert len(p.sha256) == 64


# --- Tests: Dump Completeness Verification ---


def test_dump_verifier_complete(tmp_path: Path) -> None:
    dex_path = tmp_path / "valid.dex"
    valid_dex = build_sample_dex()
    dex_path.write_bytes(valid_dex)

    report = verify_dex_dump(dex_path)
    assert report.status == CompletenessStatus.COMPLETE
    assert report.checksum_valid is True
    assert report.signature_valid is True
    assert report.class_count > 0
    assert report.stub_classes == 0
    assert report.real_code_classes > 0


def test_dump_verifier_stub(tmp_path: Path) -> None:
    stub_path = tmp_path / "stub.dex"
    stub_dex = _make_stub_dex()
    stub_path.write_bytes(stub_dex)

    report = verify_dex_dump(stub_path)
    assert report.status == CompletenessStatus.STUB_ONLY
    assert report.checksum_valid is True
    assert report.signature_valid is True
    assert report.stub_classes > 0


def test_dump_verifier_corrupted(tmp_path: Path) -> None:
    corrupt_path = tmp_path / "corrupted.dex"
    corrupt_path.write_bytes(b"not_a_dex_file_content_at_all")

    report = verify_dex_dump(corrupt_path)
    assert report.status == CompletenessStatus.CORRUPTED
    assert report.checksum_valid is False


# --- Tests: Deobfuscator Engine & Provenance ---


def test_deobfuscator_reflection_resolve() -> None:
    code = (
        'Class<?> clazz = Class.forName("com.example.secret.AuthService");\n'
        'Method m = clazz.getMethod("authenticate", String.class);\n'
        'm.invoke(null, "token");\n'
    )
    result = deobfuscate_source(
        source_code=code,
        target_name="com.example.secret.AuthService",
        strategy="reflection_resolve",
    )
    assert result.transformed is True
    assert "AuthService.authenticate" in (result.transformed_code or "")
    assert result.provenance_warning is not None
    assert "Never present this output as original source code" in (result.transformed_code or "")


def test_deobfuscator_string_decrypt() -> None:
    # "aHR0cHM6Ly9hcGkucHJpdmF0ZS5jb20=" decodes to "https://api.private.com"
    code = 'String endpoint = "aHR0cHM6Ly9hcGkucHJpdmF0ZS5jb20=";\n'
    result = deobfuscate_source(
        source_code=code,
        target_name="com.example.Config",
        strategy="string_decrypt",
    )
    assert result.transformed is True
    assert "https://api.private.com" in (result.transformed_code or "")
    assert result.provenance_warning is not None


def test_deobfuscator_dead_code_prune() -> None:
    code = "if (1 == 0) {\n    triggerCrash();\n}\nif-eqz v0, :dead_block\n"
    result = deobfuscate_source(
        source_code=code,
        target_name="com.example.Logic",
        strategy="dead_code_prune",
    )
    assert result.transformed is True
    assert "nop" in (result.transformed_code or "")
    assert result.provenance_warning is not None


def test_deobfuscator_simplify_pipeline() -> None:
    code = (
        'String host = "aHR0cHM6Ly9lbmRwb2ludC5jb20=";\n'
        'Method m = Class.forName("com.example.API").getMethod("call");\n'
        "if (0 == 1) { return; }\n"
    )
    result = deobfuscate_source(
        source_code=code,
        target_name="com.example.API",
        strategy="simplify",
    )
    assert result.transformed is True
    assert "https://endpoint.com" in (result.transformed_code or "")
    assert "API.call" in (result.transformed_code or "")
    assert result.provenance_warning is not None


# --- Tests: Retrace Engine ---


def test_retracer_mapping_and_stack_trace(tmp_path: Path) -> None:
    mapping_text = (
        "com.example.auth.TokenManager -> a.b.c:\n"
        "    java.lang.String sessionSecret -> a\n"
        "    void <init>() -> <init>\n"
        "    10:15:void validateToken(java.lang.String) -> a\n"
        "com.example.net.HttpClient -> d.e.f:\n"
        "    20:25:byte[] send(java.lang.String,int) -> b\n"
    )
    mapping_file = tmp_path / "mapping.txt"
    mapping_file.write_text(mapping_text, encoding="utf-8")

    mapping = parse_mapping_file(mapping_file)
    assert "a.b.c" in mapping.classes
    assert mapping.classes["a.b.c"] == "com.example.auth.TokenManager"
    assert "d.e.f" in mapping.classes

    stack_trace = (
        "java.lang.NullPointerException\n"
        "    at a.b.c.a(SourceFile:12)\n"
        "    at d.e.f.b(SourceFile:22)\n"
    )

    retraced_text, mapped, unmapped = retrace_stack_trace(mapping, stack_trace)
    assert mapped == 2
    assert unmapped == 0
    assert "com.example.auth.TokenManager.validateToken" in retraced_text
    assert "com.example.net.HttpClient.send" in retraced_text

    report = execute_retrace(mapping_file, stack_trace)
    assert report.retrace_coverage_percent == 100.0


# --- Tests: Native Library Inventory & Adapters ---


def test_native_library_inventory(tmp_path: Path) -> None:
    apk_path = tmp_path / "native_app.apk"
    arm64_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
    x86_elf = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100

    entries = {
        "lib/arm64-v8a/libnative-core.so": arm64_elf,
        "lib/x86/libnative-core.so": x86_elf,
    }
    make_apk(apk_path, entries=entries)

    report = inventory_native_libraries(apk_path)
    assert report.total_libraries >= 2
    abis = {lib.abi for lib in report.libraries}
    assert "arm64-v8a" in abis
    assert "x86" in abis


def test_native_adapters_fallback(tmp_path: Path) -> None:
    so_file = tmp_path / "libtest.so"
    so_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)

    ghidra = GhidraNativeAdapter()
    g_res = ghidra.analyze_library(so_file)
    assert g_res["library"] == "libtest.so"
    assert g_res["engine"] == "built_in_elf"
    assert g_res["ok"] is True

    rizin = RizinNativeAdapter()
    r_res = rizin.disassemble_function(so_file, "Java_com_example_Core_init")
    assert r_res["symbol"] == "Java_com_example_Core_init"
    assert r_res["ok"] is True


# --- Tests: Runtime.invoke Integration Across Phase 8 Tools ---


async def test_runtime_unpacking_tools_integration(runtime: Runtime, tmp_path: Path) -> None:
    apk_path = tmp_path / "runtime_test.apk"
    valid_dex = build_sample_dex()
    entries = {
        "assets/payload.dex": valid_dex,
        "lib/arm64-v8a/libcore.so": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64,
    }
    make_apk(apk_path, entries=entries)

    # 1. Project creation and artifact ingestion
    p_res = await runtime.invoke("project_create", {"name": "UnpackProject"})
    project_id = p_res.data["id"]

    a_res = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(apk_path)},
    )
    artifact_id = a_res.data["id"]

    # 2. packer_detect
    pd_res = await runtime.invoke(
        "packer_detect",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    assert pd_res.data["project_id"] == project_id
    assert "packers" in pd_res.data
    assert "anti_analysis" in pd_res.data

    # 3. unpack_extract
    ue_res = await runtime.invoke(
        "unpack_extract",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    assert ue_res.data["project_id"] == project_id
    assert ue_res.data["total_payloads_found"] >= 1

    # 4. unpack_verify (with automated re-analysis artifact ingestion)
    dex_file = tmp_path / "dump.dex"
    dex_file.write_bytes(valid_dex)
    uv_res = await runtime.invoke(
        "unpack_verify",
        {"project_id": project_id, "file_path": str(dex_file), "reanalyze": True},
    )
    assert uv_res.data["status"] == "complete"
    assert uv_res.data["reanalyzed_artifact_id"] is not None

    # Check that verified DEX was added to artifact repository
    art_list = runtime.artifacts.list(project_id)
    assert any(a.id == uv_res.data["reanalyzed_artifact_id"] for a in art_list)

    # 5. deobfuscate
    deob_res = await runtime.invoke(
        "deobfuscate",
        {
            "project_id": project_id,
            "target": "com.example.Target",
            "strategy": "simplify",
            "source_text": 'String url = "aHR0cHM6Ly9iYW5rLmNvbQ==";\n',
        },
    )
    assert deob_res.data["transformed"] is True
    assert "https://bank.com" in deob_res.data["transformed_code"]

    # 6. retrace
    mapping_file = tmp_path / "runtime_mapping.txt"
    mapping_file.write_text(
        "com.example.auth.Service -> a.b.c:\n    1:5:void check() -> a\n",
        encoding="utf-8",
    )
    ret_res = await runtime.invoke(
        "retrace",
        {
            "project_id": project_id,
            "mapping_file": str(mapping_file),
            "stack_trace": "at a.b.c.a(SourceFile:2)",
        },
    )
    assert "com.example.auth.Service.check" in ret_res.data["retraced_text"]

    # 7. native_list_libraries
    nl_res = await runtime.invoke(
        "native_list_libraries",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    assert nl_res.data["total_libraries"] >= 1
    assert any("libcore.so" in lib["library_name"] for lib in nl_res.data["libraries"])


# --- Tests: Typer CLI Subcommands ---


def test_cli_unpack_and_native_commands(runtime: Runtime, tmp_path: Path) -> None:
    apk_path = tmp_path / "cli_test.apk"
    valid_dex = build_sample_dex()
    make_apk(
        apk_path,
        entries={
            "assets/sub.dex": valid_dex,
            "lib/arm64-v8a/libclitest.so": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64,
        },
    )

    workspace = str(runtime.workspace.root)
    # 1. Project create & artifact ingest via CLI
    p_run = runner.invoke(app, ["-w", workspace, "--json", "project", "create", "CliUnpack"])
    assert p_run.exit_code == 0
    p_data = json_output(p_run.output)
    project_id = p_data["data"]["id"]

    a_run = runner.invoke(
        app, ["-w", workspace, "--json", "artifact", "ingest", project_id, str(apk_path)]
    )
    assert a_run.exit_code == 0

    # 2. raa unpack detect
    det_run = runner.invoke(app, ["-w", workspace, "--json", "unpack", "detect", project_id])
    assert det_run.exit_code == 0
    det_data = json_output(det_run.output)
    assert "packers" in det_data["data"]

    # 3. raa unpack extract
    ext_run = runner.invoke(app, ["-w", workspace, "--json", "unpack", "extract", project_id])
    assert ext_run.exit_code == 0
    ext_data = json_output(ext_run.output)
    assert ext_data["data"]["total_payloads_found"] >= 1

    # 4. raa unpack verify
    dex_path = tmp_path / "cli_dump.dex"
    dex_path.write_bytes(valid_dex)
    ver_run = runner.invoke(
        app, ["-w", workspace, "--json", "unpack", "verify", project_id, str(dex_path)]
    )
    assert ver_run.exit_code == 0
    ver_data = json_output(ver_run.output)
    assert ver_data["data"]["status"] == "complete"

    # 5. raa unpack deobfuscate
    deob_run = runner.invoke(
        app,
        [
            "-w",
            workspace,
            "--json",
            "unpack",
            "deobfuscate",
            project_id,
            "com.example.CliClass",
            "--source",
            'String s = "aHR0cHM6Ly9leGFtcGxlLmNvbQ==";',
        ],
    )
    assert deob_run.exit_code == 0
    deob_data = json_output(deob_run.output)
    assert deob_data["data"]["transformed"] is True

    # 6. raa unpack retrace
    mapping_file = tmp_path / "cli_mapping.txt"
    mapping_file.write_text(
        "com.example.Main -> a.a:\n    1:1:void run() -> a\n",
        encoding="utf-8",
    )
    ret_run = runner.invoke(
        app,
        [
            "-w",
            workspace,
            "--json",
            "unpack",
            "retrace",
            project_id,
            str(mapping_file),
            "--stacktrace",
            "at a.a.a(SourceFile:1)",
        ],
    )
    assert ret_run.exit_code == 0
    ret_data = json_output(ret_run.output)
    assert "com.example.Main.run" in ret_data["data"]["retraced_text"]

    # 7. raa native libraries
    nat_run = runner.invoke(app, ["-w", workspace, "--json", "native", "libraries", project_id])
    assert nat_run.exit_code == 0
    nat_data = json_output(nat_run.output)
    assert nat_data["data"]["total_libraries"] >= 1


def json_output(output: str) -> dict[str, Any]:
    return json.loads(output)  # type: ignore[no-any-return]
