"""Phase 2 / Phase 12 comprehensive integration and unit tests.

Validates:
1. Pure native APK Signature Scheme v2 & v3 block building and verification.
2. Android 15 16KB page alignment auditing and patching.
3. Google Play Protect pre-flight compliance engine.
4. Dynamic Code Loading (DCL) detection.
5. MobSF static security rule parity and CVSS v3.1 scorecards.
6. OASIS SARIF 2.1.0 export and Mobile STRIDE threat modeling.
7. Executable non-destructive exploit PoC generation.
8. Interactive symbol deobfuscation and ProGuard mapping.txt export/import.
9. Intent Redirection, mutable PendingIntent, and AIDL caller auth taint scans.
10. Surface parity across MCP tools and CLI subcommands.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.domain.manifest import ManifestInfo, RequestedPermission
from raa.runtime import Runtime
from raa.services.android.elf_aligner import (
    ELF_MAGIC,
    PAGE_SIZE_4KB,
    PAGE_SIZE_16KB,
    audit_apk_16kb_alignment,
    inspect_elf_alignment,
    patch_elf_16kb_alignment,
)
from raa.services.android.signing_v2v3 import (
    APK_SIG_BLOCK_MAGIC,
    find_eocd,
    sign_apk_v2v3,
    verify_apk_v2v3_signatures,
)
from raa.services.android.symbol_rename import SymbolRenameRegistry
from raa.services.security.ipc_taint import (
    scan_aidl_caller_auth,
    scan_intent_redirection,
    scan_pending_intent_mutability,
)
from raa.services.security.mobsf_rules import (
    generate_cvss_scorecard,
    scan_mobsf_rules,
)
from raa.services.security.play_protect import audit_play_protect_compliance
from raa.services.security.sarif_stride import (
    export_sarif_v21,
    generate_exploit_poc,
    model_stride_threats,
)


def _make_dummy_zip() -> bytes:
    """Create a minimal valid ZIP archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", b"Hello, RAA Phase 2 Native Signing!")
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
    return buf.getvalue()


def _make_dummy_elf_32(align: int = PAGE_SIZE_4KB) -> bytes:
    """Construct minimal 32-bit ELF with one PT_LOAD segment."""
    header = bytearray(ELF_MAGIC + b"\x01\x01\x01\x00" + b"\x00" * 8)  # 16 bytes e_ident
    header.extend(struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0x1000, 52, 0, 0, 52, 32, 1, 0, 0, 0))
    # Elf32_Phdr (32 bytes): p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
    phdr = struct.pack("<IIIIIIII", 1, 0, 0x1000, 0x1000, 100, 100, 7, align)
    return bytes(header + phdr + b"\x00" * 100)


def _make_dummy_elf_64(align: int = PAGE_SIZE_4KB) -> bytes:
    """Construct minimal 64-bit ELF with one PT_LOAD segment."""
    header = bytearray(ELF_MAGIC + b"\x02\x01\x01\x00" + b"\x00" * 8)
    header.extend(struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x1000, 64, 0, 0, 64, 56, 1, 0, 0, 0))
    # Elf64_Phdr (56 bytes): p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x1000, 0x1000, 100, 100, align)
    return bytes(header + phdr + b"\x00" * 100)


# =====================================================================
# Track 1: Pure Native APK Signature Scheme v2 & v3 Signing
# =====================================================================


def test_native_v2v3_signing_and_verification() -> None:
    raw_zip = _make_dummy_zip()
    eocd_off, cd_off, _cd_sz = find_eocd(raw_zip)
    assert eocd_off > 0
    assert cd_off > 0

    # Before signing, no signing block should be detected
    pre_verif = verify_apk_v2v3_signatures(raw_zip)
    assert not pre_verif["has_signing_block"]

    # Sign with v2 and v3 schemes
    signed_zip = sign_apk_v2v3(raw_zip, include_v2=True, include_v3=True)
    assert len(signed_zip) > len(raw_zip)
    assert APK_SIG_BLOCK_MAGIC in signed_zip

    # Verify signing block
    post_verif = verify_apk_v2v3_signatures(signed_zip)
    assert post_verif["has_signing_block"]
    assert post_verif["v2_signed"]
    assert post_verif["v3_signed"]
    assert "v2" in post_verif["schemes_found"]
    assert "v3" in post_verif["schemes_found"]
    assert post_verif["verified"]


# =====================================================================
# Track 2: Android 15 16KB Page Alignment Auto-Patcher
# =====================================================================


def test_elf_alignment_inspection_and_patching() -> None:
    # 32-bit ELF check
    elf32_4k = _make_dummy_elf_32(align=PAGE_SIZE_4KB)
    insp32_4k = inspect_elf_alignment(elf32_4k)
    assert insp32_4k["valid_elf"]
    assert not insp32_4k["is_64bit"]
    assert not insp32_4k["is_16kb_aligned"]

    # Patch 32-bit ELF to 16KB
    elf32_16k = patch_elf_16kb_alignment(elf32_4k)
    insp32_16k = inspect_elf_alignment(elf32_16k)
    assert insp32_16k["is_16kb_aligned"]
    assert insp32_16k["max_alignment"] == PAGE_SIZE_16KB

    # 64-bit ELF check
    elf64_4k = _make_dummy_elf_64(align=PAGE_SIZE_4KB)
    insp64_4k = inspect_elf_alignment(elf64_4k)
    assert insp64_4k["valid_elf"]
    assert insp64_4k["is_64bit"]
    assert not insp64_4k["is_16kb_aligned"]

    # Patch 64-bit ELF to 16KB
    elf64_16k = patch_elf_16kb_alignment(elf64_4k)
    insp64_16k = inspect_elf_alignment(elf64_16k)
    assert insp64_16k["is_16kb_aligned"]
    assert insp64_16k["max_alignment"] == PAGE_SIZE_16KB


def test_audit_apk_16kb_alignment(tmp_path: Path) -> None:
    apk_file = tmp_path / "test_16kb.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("lib/arm64-v8a/libnative.so", _make_dummy_elf_64(align=PAGE_SIZE_4KB))
        zf.writestr("lib/armeabi-v7a/liblegacy.so", _make_dummy_elf_32(align=PAGE_SIZE_16KB))

    audit = audit_apk_16kb_alignment(apk_file)
    assert audit["total_native_libraries"] == 2
    assert audit["compliant_libraries"] == 1
    assert audit["non_compliant_libraries"] == 1
    assert not audit["android_15_ready"]


# =====================================================================
# Track 3: Google Play Protect Pre-Flight & DCL Detection
# =====================================================================


def test_play_protect_compliance_audit() -> None:
    clean_manifest = ManifestInfo(
        package="com.safe.app",
        target_sdk=34,
        requested_permissions=[RequestedPermission(name="android.permission.INTERNET")],
        components=[],
    )
    clean_audit = audit_play_protect_compliance(clean_manifest)
    assert clean_audit["is_play_protect_compliant"]
    assert clean_audit["risk_level"] == "PASS"

    risky_manifest = {
        "package_name": "com.trojan.app",
        "target_sdk": 34,
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.FOREGROUND_SERVICE",
        ],
        "services": [{"name": "com.trojan.SyncService", "foreground_service_type": None}],
    }
    dex_strings = ["Ldalvik/system/DexClassLoader;", "login", "oauth_token"]
    risky_audit = audit_play_protect_compliance(risky_manifest, dex_strings=dex_strings)
    assert not risky_audit["is_play_protect_compliant"]
    assert risky_audit["risk_level"] == "CRITICAL"
    assert risky_audit["violations_count"] >= 3
    rule_ids = {v["rule_id"] for v in risky_audit["violations"]}
    assert "PLAY_PROTECT_OVERLAY_ACCESSIBILITY" in rule_ids
    assert "PLAY_POLICY_FGS_MISSING_TYPE" in rule_ids
    assert "PLAY_PROTECT_DYNAMIC_CODE_LOADING" in rule_ids


# =====================================================================
# Track 4: MobSF Static Rule Parity & CVSS Scorecard
# =====================================================================


def test_mobsf_rule_scan_and_cvss_scorecard() -> None:
    code_snippets = [
        'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");',
        'MessageDigest md = MessageDigest.getInstance("MD5");',
        'String key = "' + "AKIA" + 'IOSFODNN7EXAMPLE";',
    ]
    manifest = '<application android:usesCleartextTraffic="true" />'
    results = scan_mobsf_rules(manifest_xml=manifest, source_texts=code_snippets)
    assert results["findings_count"] >= 4
    assert results["max_cvss"] >= 7.5
    assert results["risk_level"] in ("HIGH", "CRITICAL")

    scorecard = generate_cvss_scorecard(results["findings"])
    assert scorecard["overall_score"] >= 7.0
    assert scorecard["overall_rating"] in ("HIGH", "CRITICAL")
    assert "CVSS:3.1" in scorecard["cvss_vector"]


# =====================================================================
# Track 5: OASIS SARIF 2.1 & STRIDE Threat Modeling & PoC Generator
# =====================================================================


def test_sarif_export_and_stride_threat_modeling() -> None:
    sample_findings = [
        {
            "rule_id": "MOBSF_CRYPTO_ECB",
            "title": "ECB Mode Encryption",
            "category": "Cryptography",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "description": "Insecure ECB cipher mode leaks data structure.",
            "remediation": "Switch to AES-GCM.",
        },
        {
            "rule_id": "PLAY_DCL",
            "title": "Dynamic Code Loading",
            "category": "Tampering",
            "severity": "CRITICAL",
            "cvss_score": 8.5,
            "description": "DexClassLoader loads unverified code.",
            "remediation": "Do not load dynamic dex.",
        },
    ]

    sarif_doc = export_sarif_v21(sample_findings)
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) == 2
    assert sarif_doc["runs"][0]["tool"]["driver"]["name"].startswith("RAA")

    stride_model = model_stride_threats(sample_findings)
    assert stride_model["total_threats"] == 2
    domains = {b["stride_domain"] for b in stride_model["stride_breakdown"]}
    assert "Information Disclosure" in domains
    assert "Tampering" in domains

    poc = generate_exploit_poc(
        finding_id="MOBSF_CRYPTO_ECB",
        finding_title="ECB Mode Encryption",
        target_package="com.example.app",
        component="com.example.app/.AuthActivity",
    )
    assert "adb shell am start" in poc["adb_command"]
    assert "Java.perform" in poc["frida_script"]
    assert "curl" in poc["curl_probe"]


# =====================================================================
# Track 6: Interactive Symbol Deobfuscation Registry
# =====================================================================


def test_symbol_rename_registry() -> None:
    reg = SymbolRenameRegistry()
    reg.add_mapping("class", "com.app.a.b", "com.app.auth.TokenManager")
    reg.add_mapping("method", "com.app.a.b.c", "authenticate")
    reg.add_mapping("field", "com.app.a.b.d", "cachedToken")

    assert reg.resolve_symbol("com.app.a.b") == "com.app.auth.TokenManager"
    assert reg.resolve_symbol("com.app.a.b.c") == "authenticate"

    code = "invoke-virtual {v0}, Lcom/app/a/b;->c()V"
    transformed = reg.apply_to_source(code)
    assert "Lcom/app/auth/TokenManager;->authenticate()V" in transformed

    mapping_txt = reg.export_proguard_mapping()
    assert "com.app.auth.TokenManager -> com.app.a.b:" in mapping_txt

    new_reg = SymbolRenameRegistry()
    imported_count = new_reg.import_proguard_mapping(mapping_txt)
    assert imported_count >= 1
    assert new_reg.resolve_symbol("com.app.a.b") == "com.app.auth.TokenManager"


# =====================================================================
# Track 7: Intent Redirection & IPC Taint Scanning
# =====================================================================


def test_ipc_taint_scanners() -> None:
    vuln_intent_code = [
        "Intent forward = getIntent().getParcelableExtra('extra_intent'); startActivity(forward);"
    ]
    intent_findings = scan_intent_redirection(vuln_intent_code)
    assert len(intent_findings) == 1
    assert intent_findings[0]["rule_id"] == "IPC_INTENT_REDIRECTION_VULNERABILITY"

    vuln_pi_code = ["PendingIntent pi = PendingIntent.getActivity(ctx, 0, intent, FLAG_MUTABLE);"]
    pi_findings = scan_pending_intent_mutability(vuln_pi_code)
    assert len(pi_findings) == 1
    assert pi_findings[0]["rule_id"] == "IPC_MUTABLE_PENDING_INTENT"

    vuln_aidl_code = [
        "class MyStub extends Stub { onTransact() { "
        "String pkg = intent.getStringExtra('package'); } }"
    ]
    aidl_findings = scan_aidl_caller_auth(vuln_aidl_code)
    assert len(aidl_findings) == 1
    assert aidl_findings[0]["rule_id"] == "IPC_AIDL_CONFUSED_DEPUTY"


# =====================================================================
# Surface Parity & Runtime MCP / CLI Execution
# =====================================================================


@pytest.mark.asyncio
async def test_runtime_phase12_tools_registered(runtime: Runtime) -> None:
    envelope = await runtime.invoke("capabilities_get", {})
    assert envelope.data["implemented_tools"] >= 163
    assert envelope.data["profiles"]["core"] >= 104
    assert envelope.data["profiles"]["admin"] >= 16
    assert envelope.data["profiles"]["full"] >= 163

    proj = runtime.projects.create(
        name="Phase 12 Test Project", description="Testing Phase 12 tools"
    )

    # Test source_rename_symbol
    rename_res = await runtime.invoke(
        "source_rename_symbol",
        {
            "project_id": proj.id,
            "symbol_type": "class",
            "original_name": "a.b.c",
            "renamed_name": "AuthService",
            "export_mapping": True,
        },
    )
    assert rename_res.data["total_mapped"] >= 1
    assert "proguard_mapping" in rename_res.data

    # Test sec_poc_generate
    poc_res = await runtime.invoke(
        "sec_poc_generate",
        {
            "finding_id": "FIND_001",
            "title": "Exported Provider Bypass",
            "target_package": "com.target.app",
        },
    )
    assert "adb shell am start" in poc_res.data["adb_command"]


def test_cli_phase12_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["security", "--help"])
    assert result.exit_code == 0
    assert "play-protect" in result.stdout
    assert "mobsf" in result.stdout
    assert "cvss" in result.stdout
    assert "sarif" in result.stdout
    assert "stride" in result.stdout
    assert "poc" in result.stdout
    assert "intent-redirection" in result.stdout
    assert "pending-intent" in result.stdout
    assert "aidl-auth" in result.stdout

    rebuild_res = runner.invoke(app, ["rebuild", "--help"])
    assert rebuild_res.exit_code == 0
    assert "align-16kb" in rebuild_res.stdout

    source_res = runner.invoke(app, ["source", "--help"])
    assert source_res.exit_code == 0
    assert "rename-symbol" in source_res.stdout
