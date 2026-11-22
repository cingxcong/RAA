"""Tests for Phase 14 (v2.0.0): Universal Platform Expansion & Advanced Engines.

Covers:
- Apple iOS (.ipa inspection, Mach-O disassembly, Info.plist, provisioning profiles)
- Huawei HarmonyOS (.hap inspection, ArkTS Panda ABC bytecode disassembly)
- Standalone PRoot Linux Container Engine (workspace provisioning, exec, script gen)
- Warp Block Interactive Terminal Sessions (structured blocks, session lifecycle, export)
- Cross-Platform Parity Compare (Android APK vs iOS IPA vs HarmonyOS HAP)
- Profile target counts:
  minimal: 12, core: 135, dynamic: 169, api: 139, ui: 140, admin: 19, full: 244
- CLI subcommands under `raa platform`:
  ios-inspect, macho-disassemble, harmony-inspect, harmony-disassemble,
  proot, warp-session, cross-compare
"""

from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.platform.cross_target_compare import compare_cross_targets
from raa.services.platform.harmony_inspector import (
    disassemble_harmony_abc,
    inspect_harmony_hap,
)
from raa.services.platform.ios_inspector import (
    disassemble_macho,
    inspect_ios_ipa,
)
from raa.services.platform.proot_engine import manage_proot_workspace
from raa.services.platform.warp_session import manage_warp_block_session


def _create_synthetic_ipa(path: Path) -> Path:
    # Build Mach-O 64-bit slice
    # Header: magic(0xFEEDFACF), cputype(0x0100000C ARM64), cpusubtype(0), filetype(2 MH_EXECUTE),
    # ncmds(2), sizeofcmds, flags(0), reserved(0)
    magic = 0xFEEDFACF
    cputype = 0x0100000C
    cpusubtype = 0
    filetype = 2
    ncmds = 2
    flags = 0x00200085
    reserved = 0

    # Command 1: LC_SEGMENT_64 (0x19)
    cmd1 = 0x19
    cmd1_size = 72
    segname = b"__PAGEZERO".ljust(16, b"\x00")
    vmaddr = 0
    vmsize = 0x100000000
    fileoff = 0
    filesize = 0
    maxprot = 0
    initprot = 0
    nsects = 0
    seg_flags = 0
    cmd1_data = struct.pack(
        "<II16sQQQQIIII",
        cmd1,
        cmd1_size,
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        seg_flags,
    )

    # Command 2: LC_ENCRYPTION_INFO_64 (0x2C)
    cmd2 = 0x2C
    cmd2_size = 24
    cryptoff = 4096
    cryptsize = 8192
    cryptid = 0  # Decrypted
    pad = 0
    cmd2_data = struct.pack("<IIIIII", cmd2, cmd2_size, cryptoff, cryptsize, cryptid, pad)

    sizeofcmds = len(cmd1_data) + len(cmd2_data)
    hdr_data = struct.pack(
        "<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    )
    macho_bytes = hdr_data + cmd1_data + cmd2_data + b"\x90" * 64

    # Plist XML
    plist_xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        b'<plist version="1.0">\n'
        b"<dict>\n"
        b"  <key>CFBundleIdentifier</key>\n"
        b"  <string>com.example.demoiOS</string>\n"
        b"  <key>CFBundleShortVersionString</key>\n"
        b"  <string>2.4.0</string>\n"
        b"  <key>CFBundleVersion</key>\n"
        b"  <string>240</string>\n"
        b"  <key>CFBundleExecutable</key>\n"
        b"  <string>DemoApp</string>\n"
        b"  <key>MinimumOSVersion</key>\n"
        b"  <string>16.0</string>\n"
        b"</dict>\n"
        b"</plist>\n"
    )

    # Synthetic mobileprovision containing XML
    prov_content = (
        b'PKCS7_HEADER\x00\x00\x00<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<plist version="1.0"><dict>\n'
        b"<key>Name</key><string>iOS Team Provisioning Profile</string>\n"
        b"<key>TeamIdentifier</key><array><string>ABCD1234EF</string></array>\n"
        b"<key>Entitlements</key><dict>\n"
        b"<key>get-task-allow</key><true/>\n"
        b"</dict>\n"
        b"</dict></plist>\x00\x00PKCS7_TRAILER"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/DemoApp.app/Info.plist", plist_xml)
        zf.writestr("Payload/DemoApp.app/DemoApp", macho_bytes)
        zf.writestr("Payload/DemoApp.app/embedded.mobileprovision", prov_content)

    return path


def _create_synthetic_hap(path: Path) -> Path:
    # Synthetic HarmonyOS Stage model module.json
    module_json = {
        "app": {
            "bundleName": "com.example.harmonyapp",
            "versionCode": 100,
            "versionName": "1.0.0",
        },
        "module": {
            "name": "entry",
            "type": "entry",
            "deviceTypes": ["phone", "tablet"],
            "mainElement": "EntryAbility",
            "requestPermissions": [
                {"name": "ohos.permission.INTERNET"},
                {"name": "ohos.permission.GET_NETWORK_INFO"},
            ],
            "abilities": [
                {
                    "name": "EntryAbility",
                    "srcEntry": "./ets/entryability/EntryAbility.ets",
                    "skills": [
                        {"entities": ["entity.system.home"], "actions": ["action.system.home"]}
                    ],
                }
            ],
        },
    }

    # Synthetic Panda ABC bytecode
    # Magic: 'PANDA\x00\x00\x00', checksum: 4 bytes, version: 4 bytes, file_size: 4 bytes,
    # num_classes: 2
    abc_header = b"PANDA\x00\x00\x00" + struct.pack("<III", 0x12345678, 0x00010000, 256)
    abc_body = (
        struct.pack("<I", 2)
        + b"Lcom/example/harmonyapp/EntryAbility;"
        + b"\x00"
        + b"Lcom/example/harmonyapp/NetworkService;"
        + b"\x00"
        + b"\x00" * 64
    )
    abc_bytes = abc_header + abc_body

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", json.dumps(module_json).encode("utf-8"))
        zf.writestr("ets/modules.abc", abc_bytes)

    return path


def test_ios_inspector_service(tmp_path: Path) -> None:
    ipa_path = _create_synthetic_ipa(tmp_path / "test.ipa")
    result = inspect_ios_ipa(str(ipa_path))

    assert result["bundle_id"] == "com.example.demoiOS"
    assert result["bundle_version"] == "2.4.0"
    assert result["minimum_os_version"] == "16.0"
    assert result["executable_name"] == "DemoApp"
    assert result["entitlements"].get("get-task-allow") is True
    assert result["macho_summary"]["architecture"] == "ARM64"
    assert result["macho_summary"]["is_64bit"] is True


def test_macho_disassemble_service(tmp_path: Path) -> None:
    # Standalone Mach-O binary
    magic = 0xFEEDFACF
    cputype = 0x0100000C
    cpusubtype = 0
    filetype = 2
    ncmds = 1
    flags = 0
    reserved = 0
    cmd1_data = struct.pack(
        "<II16sQQQQIIII",
        0x19,
        72,
        b"__TEXT".ljust(16, b"\x00"),
        0x10000,
        0x4000,
        0,
        0x4000,
        7,
        5,
        0,
        0,
    )
    sizeofcmds = len(cmd1_data)
    hdr_data = struct.pack(
        "<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    )
    macho_path = tmp_path / "sample_macho"
    macho_path.write_bytes(hdr_data + cmd1_data + b"\x55\x48\x89\xe5")

    result = disassemble_macho(str(macho_path), deep_symbols=True)
    assert result["architecture"] == "ARM64"
    assert result["is_64bit"] is True
    assert len(result["segments"]) >= 1
    assert result["segments"][0]["segment"] == "__TEXT"


def test_harmony_inspector_service(tmp_path: Path) -> None:
    hap_path = _create_synthetic_hap(tmp_path / "test.hap")
    result = inspect_harmony_hap(str(hap_path))

    assert result["bundle_name"] == "com.example.harmonyapp"
    assert result["version_name"] == "1.0.0"
    assert result["version_code"] == 100
    assert result["harmony_model"] == "Stage"
    assert any(p["name"] == "ohos.permission.INTERNET" for p in result["request_permissions"])
    assert len(result["abilities"]) == 1
    assert result["abilities"][0]["name"] == "EntryAbility"
    assert len(result["abc_files"]) == 1
    assert result["abc_summary"] is not None


def test_harmony_abc_disassemble_service(tmp_path: Path) -> None:
    abc_header = b"PANDA\x00\x00\x00" + struct.pack("<III", 0x12345678, 0x00010000, 128)
    abc_body = (
        struct.pack("<I", 1) + b"Lcom/example/MyPage;" + b"\x00" + b"\x00\x1a\x02\x4f\x60\x28"
    )
    abc_file = tmp_path / "classes.abc"
    abc_file.write_bytes(abc_header + abc_body)

    result = disassemble_harmony_abc(str(abc_file))
    assert result["format"] == "ArkTS_ABC"
    assert result["checksum"] == "0x12345678"
    assert result["estimated_classes_count"] >= 1


def test_proot_engine_service(tmp_path: Path) -> None:
    # Test init
    init_res = manage_proot_workspace(
        action="init", distro="debian", workspace_dir=str(tmp_path / "proot")
    )
    assert init_res["action"] == "init"
    assert init_res["status"] == "initialized"

    # Test exec
    res_exec = manage_proot_workspace(
        action="exec",
        command="uname -a",
        workspace_dir=str(tmp_path / "proot"),
    )
    assert res_exec["action"] == "exec"
    assert "command" in res_exec

    # Test status & purge
    res_status = manage_proot_workspace(action="status", workspace_dir=str(tmp_path / "proot"))
    assert res_status["action"] == "status"

    res_purge = manage_proot_workspace(action="purge", workspace_dir=str(tmp_path / "proot"))
    assert res_purge["action"] == "purge"
    assert res_purge["status"] == "purged"


def test_warp_session_service() -> None:
    # Record block
    rec = manage_warp_block_session(
        action="record_block",
        session_id="warp_test_1",
        command="export APP_ENV=staging",
        output="Environment set to staging",
        exit_code=0,
        tags=["config", "env"],
    )
    assert rec["action"] == "record_block"
    assert rec["session_id"] == "warp_test_1"
    assert rec["total_blocks"] >= 1
    block_id = rec["block"]["block_id"]

    # Bookmark block
    bmark = manage_warp_block_session(
        action="bookmark_block",
        session_id="warp_test_1",
        block_id=block_id,
    )
    assert bmark["action"] == "bookmark_block"
    assert bmark["bookmarked"] is True

    # Get session
    sess = manage_warp_block_session(
        action="get_session",
        session_id="warp_test_1",
    )
    assert sess["action"] == "get_session"
    assert sess["bookmarked_count"] >= 1

    # Export runbook
    exp = manage_warp_block_session(
        action="export_runbook",
        session_id="warp_test_1",
    )
    assert exp["action"] == "export_runbook"
    assert "RAA Terminal Audit Runbook" in exp["runbook_markdown"]

    # Clear
    clr = manage_warp_block_session(
        action="clear",
        session_id="warp_test_1",
    )
    assert clr["action"] == "clear"
    assert clr["status"] == "cleared"


def test_cross_target_compare_service(tmp_path: Path) -> None:
    ipa_path = _create_synthetic_ipa(tmp_path / "test.ipa")
    hap_path = _create_synthetic_hap(tmp_path / "test.hap")

    result = compare_cross_targets(
        android_apk_path=None,
        ios_ipa_path=str(ipa_path),
        harmony_hap_path=str(hap_path),
    )

    assert "ios" in result["platforms_compared"]
    assert "harmonyos" in result["platforms_compared"]
    assert result["parity_score"] > 0
    assert "permission_parity_matrix" in result


@pytest.mark.asyncio
async def test_phase14_runtime_mcp_invocation(runtime: Runtime, tmp_path: Path) -> None:
    ipa_path = _create_synthetic_ipa(tmp_path / "mcp_test.ipa")
    hap_path = _create_synthetic_hap(tmp_path / "mcp_test.hap")

    # 1. ios_ipa_inspect
    res_ipa = await runtime.invoke("ios_ipa_inspect", {"ipa_path": str(ipa_path)})
    assert res_ipa.data["bundle_id"] == "com.example.demoiOS"

    # 2. ios_macho_disassemble
    with zipfile.ZipFile(ipa_path) as zf:
        macho_bytes = zf.read("Payload/DemoApp.app/DemoApp")
    macho_file = tmp_path / "DemoApp"
    macho_file.write_bytes(macho_bytes)
    res_macho = await runtime.invoke("ios_macho_disassemble", {"binary_path": str(macho_file)})
    assert res_macho.data["architecture"] == "ARM64"

    # 3. harmony_hap_inspect
    res_hap = await runtime.invoke("harmony_hap_inspect", {"hap_path": str(hap_path)})
    assert res_hap.data["bundle_name"] == "com.example.harmonyapp"

    # 4. harmony_abc_disassemble
    with zipfile.ZipFile(hap_path) as zf:
        abc_bytes = zf.read("ets/modules.abc")
    abc_file = tmp_path / "modules.abc"
    abc_file.write_bytes(abc_bytes)
    res_abc = await runtime.invoke("harmony_abc_disassemble", {"abc_path": str(abc_file)})
    assert res_abc.data["format"] == "ArkTS_ABC"

    # 5. termux_proot_workspace_manage
    res_proot = await runtime.invoke("termux_proot_workspace_manage", {"action": "status"})
    assert res_proot.data["action"] == "status"

    # 6. warp_block_session_manage
    res_warp = await runtime.invoke(
        "warp_block_session_manage",
        {"action": "record_block", "session_id": "warp_mcp_test", "command": "whoami"},
    )
    assert res_warp.data["action"] == "record_block"

    # 7. platform_cross_target_compare
    res_comp = await runtime.invoke(
        "platform_cross_target_compare",
        {"ios_ipa_path": str(ipa_path), "harmony_hap_path": str(hap_path)},
    )
    assert "ios" in res_comp.data["platforms_compared"]


@pytest.mark.asyncio
async def test_phase14_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] == 244
    assert data["planned_tools"] == 244

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] == 135
    assert profiles["dynamic"] == 169
    assert profiles["api"] == 139
    assert profiles["ui"] == 140
    assert profiles["admin"] == 19
    assert profiles["full"] == 244


def test_phase14_cli_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    ipa_path = _create_synthetic_ipa(tmp_path / "cli_test.ipa")
    hap_path = _create_synthetic_hap(tmp_path / "cli_test.hap")
    with zipfile.ZipFile(ipa_path) as zf:
        macho_bytes = zf.read("Payload/DemoApp.app/DemoApp")
    macho_file = tmp_path / "DemoApp_cli"
    macho_file.write_bytes(macho_bytes)
    with zipfile.ZipFile(hap_path) as zf:
        abc_bytes = zf.read("ets/modules.abc")
    abc_file = tmp_path / "modules_cli.abc"
    abc_file.write_bytes(abc_bytes)

    # 1. ios-inspect
    res1 = runner.invoke(app, ["platform", "ios-inspect", str(ipa_path)])
    assert res1.exit_code == 0
    assert "com.example.demoiOS" in res1.stdout

    # 2. macho-disassemble
    res2 = runner.invoke(app, ["platform", "macho-disassemble", str(macho_file)])
    assert res2.exit_code == 0
    assert "ARM64" in res2.stdout

    # 3. harmony-inspect
    res3 = runner.invoke(app, ["platform", "harmony-inspect", str(hap_path)])
    assert res3.exit_code == 0
    assert "com.example.harmonyapp" in res3.stdout

    # 4. harmony-disassemble
    res4 = runner.invoke(app, ["platform", "harmony-disassemble", str(abc_file)])
    assert res4.exit_code == 0
    assert "ArkTS_ABC" in res4.stdout

    # 5. proot
    res5 = runner.invoke(app, ["platform", "proot", "--action", "status"])
    assert res5.exit_code == 0
    assert "status" in res5.stdout

    # 6. warp-session
    res6 = runner.invoke(app, ["platform", "warp-session", "--action", "get_session"])
    assert res6.exit_code == 0
    assert "get_session" in res6.stdout

    # 7. cross-compare
    res7 = runner.invoke(
        app,
        [
            "platform",
            "cross-compare",
            "--ios",
            str(ipa_path),
            "--harmony",
            str(hap_path),
        ],
    )
    assert res7.exit_code == 0
    assert "parity_score" in res7.stdout
