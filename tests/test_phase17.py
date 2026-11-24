"""Tests for Phase 17 (v2.3.0): Next-Gen Binary Decompilation, Advanced Apple Analysis & Hardware Controls.

Covers:
- Kuna Fast Rust Native Decompiler (kuna_rust_decompile)
- RetDec Native Decompilation Engine (retdec_native_decompile)
- Malimite Mach-O Symbol Demangler & Header Parser (malimite_macho_demangle)
- Mach-O Swift Reflection Section Parser (macho_swift_section_parse)
- Objective-C Interface Reconstruction & class-dump Header Generator (objc_helper_macho_reconstruct)
- Native GDB/MI Machine Interface Interactive Debugger Session (native_gdb_mi_session)
- Native Objdump & DWARF Debug Information Inspector (native_objdump_dwarf_inspect)
- Rizin / Cutter Headless Analysis Engine Bridge (engine_rizin_cutter_bridge)
- Ghidra Headless Decompilation Bridge (engine_ghidra_headless_bridge)
- IoT Companion Firmware & BLE Key Extractor (iot_firmware_partition_extract)
- ADB Screen Lock & Keyguard Clear (device_lock_bypass_adb)
- ADB Automated Lockscreen PIN Brute-force (device_lock_bruteforce_adb)
- USB Rubber Ducky / BadUSB Keystroke Script Generator (device_hid_ducky_payload_gen)
- Android Gatekeeper / Locksettings Credential Clear (device_gatekeeper_credential_clear)
- LSPosed / Xposed Keyguard Hook Injector (xposed_unlock_hook_inject)
- Nanobot Autonomous Background Daemon Controller (nanobot_daemon_ctl)
- Nanobot Multi-Platform Chat Alert Dispatcher (nanobot_notify_dispatch)
- Lastbook Air-Gapped Offline Knowledge Base (airgap_lastbook_query)
- CLI subcommands under `raa binary`:
  kuna-decompile, retdec-decompile, macho-demangle, swift-sections, objc-reconstruct,
  gdb-session, objdump-dwarf, rizin-bridge, ghidra-bridge, iot-extract, lock-bypass,
  lock-bruteforce, ducky-payload, gatekeeper-clear, xposed-hook, nanobot-daemon,
  nanobot-notify, lastbook
- Registry profile totals:
  minimal: 13, core: 155, dynamic: 190, api: 155, ui: 155, admin: 28, swarm: 124, full: 280
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime

runner = CliRunner()


# 1. Native Decompilation Tools
@pytest.mark.asyncio
async def test_native_decompilers_kuna_and_retdec(runtime: Runtime) -> None:
    # 1. Kuna Rust Decompile
    kuna_res = await runtime.invoke(
        "kuna_rust_decompile",
        {
            "library_name": "libnative-crypto.so",
            "target_arch": "arm64-v8a",
            "symbol_filter": "Java_com_example_Crypto_decryptKey",
        },
    )
    assert kuna_res.data["decompiler_engine"] == "kuna_rust"
    assert kuna_res.data["library_name"] == "libnative-crypto.so"
    assert "Java_com_example_Crypto_decryptKey" in kuna_res.data["decompiled_ast_c"]
    assert kuna_res.data["recovered_functions_count"] >= 1

    # 2. RetDec Native Decompile
    retdec_res = await runtime.invoke(
        "retdec_native_decompile",
        {
            "library_name": "libnative-payload.so",
            "target_arch": "armeabi-v7a",
        },
    )
    assert retdec_res.data["decompiler_engine"] == "retdec_llvm"
    assert retdec_res.data["target_arch"] == "armeabi-v7a"
    assert retdec_res.data["recovered_functions_count"] >= 2


# 2. Mach-O & Apple Analysis Tools
@pytest.mark.asyncio
async def test_macho_apple_analysis_tools(runtime: Runtime) -> None:
    # 1. Malimite Mach-O demangling & headers
    malimite_res = await runtime.invoke(
        "malimite_macho_demangle",
        {"binary_path": "Payload/TargetApp.app/TargetApp"},
    )
    assert malimite_res.data["architecture"] == "arm64"
    assert any("CryptoManager" in sym for sym in malimite_res.data["demangled_symbols"])
    assert len(malimite_res.data["objc_classes"]) >= 1

    # 2. Mach-O Swift reflection section parser
    swift_res = await runtime.invoke(
        "macho_swift_section_parse",
        {"binary_path": "Payload/TargetApp.app/TargetApp"},
    )
    assert swift_res.data["swift_version"] == "5.10"
    assert len(swift_res.data["swift_types"]) >= 1
    assert swift_res.data["swift_types"][0]["type_name"] == "CryptoManager"

    # 3. Objective-C interface reconstruction
    objc_res = await runtime.invoke(
        "objc_helper_macho_reconstruct",
        {"binary_path": "Payload/TargetApp.app/TargetApp"},
    )
    assert len(objc_res.data["objc_classes"]) >= 2
    assert any(c["class_name"] == "AppDelegate" for c in objc_res.data["objc_classes"])


# 3. GDB/MI Interactive Debugger Session
@pytest.mark.asyncio
async def test_native_gdb_mi_session_flow(runtime: Runtime) -> None:
    # Start session
    start_res = await runtime.invoke(
        "native_gdb_mi_session",
        {
            "action": "start",
            "target_binary": "/system/bin/app_process64",
        },
        profile="dynamic",
    )
    session_id = start_res.data["session_id"]
    assert session_id is not None
    assert start_res.data["target_binary"] == "/system/bin/app_process64"
    assert start_res.data["execution_state"] == "stopped"

    # Set breakpoint
    bp_res = await runtime.invoke(
        "native_gdb_mi_session",
        {
            "action": "breakpoint",
            "target_binary": "/system/bin/app_process64",
            "session_id": session_id,
            "breakpoint_location": "main",
        },
        profile="dynamic",
    )
    assert len(bp_res.data["breakpoints"]) == 1

    # Query registers
    reg_res = await runtime.invoke(
        "native_gdb_mi_session",
        {
            "action": "registers",
            "target_binary": "/system/bin/app_process64",
            "session_id": session_id,
        },
        profile="dynamic",
    )
    assert "x0" in reg_res.data["registers"]
    assert "pc" in reg_res.data["registers"]

    # Execute command
    cmd_res = await runtime.invoke(
        "native_gdb_mi_session",
        {
            "action": "command",
            "target_binary": "/system/bin/app_process64",
            "session_id": session_id,
            "command_str": "x/10i $pc",
        },
        profile="dynamic",
    )
    assert cmd_res.data["execution_state"] == "running"
    assert "running" in cmd_res.data["last_mi_response"]

    # Stop session
    stop_res = await runtime.invoke(
        "native_gdb_mi_session",
        {
            "action": "stop",
            "target_binary": "/system/bin/app_process64",
            "session_id": session_id,
        },
        profile="dynamic",
    )
    assert stop_res.data["execution_state"] == "terminated"


# 4. Objdump DWARF & Engine Bridges (Rizin, Ghidra)
@pytest.mark.asyncio
async def test_objdump_dwarf_and_engine_bridges(runtime: Runtime) -> None:
    # 1. Native Objdump DWARF
    dwarf_res = await runtime.invoke(
        "native_objdump_dwarf_inspect",
        {
            "target_file": "libnative.so",
            "target_symbol": "validate_license",
        },
    )
    assert dwarf_res.data["tool_engine"] == "objdump_dwarf"
    assert len(dwarf_res.data["dwarf_source_links"]) >= 1
    assert len(dwarf_res.data["disassembled_instructions"]) >= 1

    # 2. Rizin Cutter headless bridge
    rizin_res = await runtime.invoke(
        "engine_rizin_cutter_bridge",
        {"target_file": "libnative.so"},
    )
    assert rizin_res.data["tool_engine"] == "rizin_cutter"
    assert rizin_res.data["control_flow_graphs_count"] >= 10

    # 3. Ghidra headless bridge
    ghidra_res = await runtime.invoke(
        "engine_ghidra_headless_bridge",
        {
            "target_file": "libnative.so",
            "analysis_script": "DecompileHeadless.java",
        },
    )
    assert ghidra_res.data["tool_engine"] == "ghidra_headless"
    assert ghidra_res.data["control_flow_graphs_count"] >= 20


# 5. IoT Companion Firmware Partition Extractor
@pytest.mark.asyncio
async def test_iot_firmware_partition_extractor(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "iot_firmware_partition_extract",
        {"apk_path": "smart_thermostat_companion.apk"},
    )
    assert res.data["partition_table_type"] == "esp32"
    assert len(res.data["partitions_extracted"]) >= 2
    assert res.data["total_size_bytes"] > 0


# 6. Device Lockscreen Bypasses & Hardware Keystrokes
@pytest.mark.asyncio
async def test_device_lockscreen_operations(runtime: Runtime) -> None:
    device = "emulator-5554"

    # 1. ADB Lock Bypass
    bypass_res = await runtime.invoke(
        "device_lock_bypass_adb",
        {"device_id": device},
        profile="dynamic",
    )
    assert bypass_res.data["bypass_method"] == "adb_keyguard_dismiss"
    assert bypass_res.data["status"] == "success"

    # 2. ADB Lock Bruteforce
    brute_res = await runtime.invoke(
        "device_lock_bruteforce_adb",
        {"device_id": device, "max_digits": 4},
        profile="dynamic",
    )
    assert brute_res.data["bypass_method"] == "pin_bruteforce"
    assert brute_res.data["details"]["discovered_pin"] is not None

    # 3. Rubber Ducky payload generator
    ducky_res = await runtime.invoke(
        "device_hid_ducky_payload_gen",
        {"target_pin": "5432"},
        profile="dynamic",
    )
    assert ducky_res.data["bypass_method"] == "usb_hid_ducky"
    assert "STRING 1234" in ducky_res.data["generated_payload"]

    # 4. Gatekeeper credential clear
    gate_res = await runtime.invoke(
        "device_gatekeeper_credential_clear",
        {"device_id": device},
        profile="dynamic",
    )
    assert gate_res.data["bypass_method"] == "gatekeeper_clear"
    assert len(gate_res.data["credentials_cleared"]) >= 1

    # 5. Xposed unlock hook inject
    xposed_res = await runtime.invoke(
        "xposed_unlock_hook_inject",
        {"device_id": device},
        profile="dynamic",
    )
    assert xposed_res.data["bypass_method"] == "xposed_hook"
    assert xposed_res.data["details"]["hook_class"] is not None


# 7. Nanobot Daemon & Chat Notification Dispatcher
@pytest.mark.asyncio
async def test_nanobot_daemon_and_notification(runtime: Runtime) -> None:
    # 1. Start daemon
    start_daemon = await runtime.invoke(
        "nanobot_daemon_ctl",
        {"action": "start"},
        profile="admin",
    )
    assert start_daemon.data["daemon_running"] is True

    # 2. Schedule cron
    cron_res = await runtime.invoke(
        "nanobot_daemon_ctl",
        {
            "action": "schedule_cron",
            "cron_expression": "*/15 * * * *",
            "job_name": "auto_decompilation_sweep",
        },
        profile="admin",
    )
    assert any(j["job"] == "auto_decompilation_sweep" for j in cron_res.data["scheduled_crons"])

    # 3. Dispatch chat alert
    notify_res = await runtime.invoke(
        "nanobot_notify_dispatch",
        {
            "channel": "slack",
            "title": "Critical Vuln Found",
            "message": "Hardcoded AWS secret in libauth.so",
            "severity": "CRITICAL",
        },
        profile="admin",
    )
    assert notify_res.data["channel"] == "slack"
    assert notify_res.data["status"] == "delivered"


# 8. Air-Gapped Lastbook Knowledge Base
@pytest.mark.asyncio
async def test_airgap_lastbook_query(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "airgap_lastbook_query",
        {
            "query": "MASTG-STORAGE-1",
            "category": "mastg",
        },
    )
    assert res.data["zero_network_verified"] is True
    assert res.data["category"] == "mastg"
    assert len(res.data["results"]) >= 1
    assert "MASTG-STORAGE-1" in res.data["results"][0]["id"]


# 9. CLI Subcommands End-to-End Test Suite
def test_cli_binary_subcommands_e2e(tmp_path: Path) -> None:
    ws = str(tmp_path)

    # 1. kuna-decompile
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "kuna-decompile", "--lib", "libnative.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["decompiler_engine"] == "kuna_rust"

    # 2. retdec-decompile
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "retdec-decompile", "--lib", "libcrypto.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["decompiler_engine"] == "retdec_llvm"

    # 3. macho-demangle
    res = runner.invoke(
        app,
        ["--workspace", ws, "--json", "binary", "macho-demangle", "--path", "Payload/App.app/App"],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["architecture"] == "arm64"

    # 4. swift-sections
    res = runner.invoke(
        app,
        ["--workspace", ws, "--json", "binary", "swift-sections", "--path", "Payload/App.app/App"],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["swift_version"] == "5.10"

    # 5. objc-reconstruct
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "binary",
            "objc-reconstruct",
            "--path",
            "Payload/App.app/App",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert len(data["data"]["objc_classes"]) >= 1

    # 6. gdb-session
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "binary",
            "gdb-session",
            "--action",
            "start",
            "--target",
            "/system/bin/app_process",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["session_id"] is not None

    # 7. objdump-dwarf
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "objdump-dwarf", "--target", "libnative.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["tool_engine"] == "objdump_dwarf"

    # 8. rizin-bridge
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "rizin-bridge", "--target", "libnative.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["tool_engine"] == "rizin_cutter"

    # 9. ghidra-bridge
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "ghidra-bridge", "--target", "libnative.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["tool_engine"] == "ghidra_headless"

    # 10. iot-extract
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "iot-extract", "--apk", "thermostat.apk"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["partition_table_type"] == "esp32"

    # 11. lock-bypass
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "lock-bypass", "--device", "emulator-5554"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "success"

    # 12. lock-bruteforce
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "binary",
            "lock-bruteforce",
            "--device",
            "emulator-5554",
            "--digits",
            "4",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["details"]["discovered_pin"] is not None

    # 13. ducky-payload
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "ducky-payload", "--pin", "9876"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "STRING 1234" in data["data"]["generated_payload"]

    # 14. gatekeeper-clear
    res = runner.invoke(
        app,
        ["--workspace", ws, "--json", "binary", "gatekeeper-clear", "--device", "emulator-5554"],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert len(data["data"]["credentials_cleared"]) >= 1

    # 15. xposed-hook
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "xposed-hook", "--device", "emulator-5554"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "success"

    # 16. nanobot-daemon
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "nanobot-daemon", "--action", "status"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "daemon_running" in data["data"]

    # 17. nanobot-notify
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "binary",
            "nanobot-notify",
            "--channel",
            "telegram",
            "--title",
            "Alert",
            "-m",
            "Found token",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "delivered"

    # 18. lastbook
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "binary", "lastbook", "-q", "storage", "-c", "mastg"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["zero_network_verified"] is True
