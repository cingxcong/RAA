"""Phase 13H Integration & Unit Tests.

Covers:
- Flutter Dart AOT Snapshot & BoringSSL TLS Pinning Reverser:
  - flutter_dart_snapshot_inspect
  - flutter_ssl_pinning_bypass_gen
  - flutter_engine_proxy_patch
- React Native Hermes Bytecode (.hbc) Decompiler & String Harvester:
  - rn_hermes_bundle_extract
  - rn_hermes_decompile
- Ultra-Low-Latency Scrcpy Fast Input Injection & Screen Streamer:
  - dyn_scrcpy_inject_fast
  - dyn_scrcpy_frame_capture
- Deterministic Mobile State Verification & Agent Simulation:
  - dyn_gui_state_verify
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.scrcpy_fast import capture_scrcpy_frame, inject_scrcpy_fast_action
from raa.services.android.state_verifier import verify_gui_state
from raa.services.framework_adapters.flutter_reverser import (
    generate_flutter_ssl_bypass,
    inspect_dart_snapshot,
    patch_flutter_engine_proxy,
)
from raa.services.framework_adapters.hermes_reverser import (
    decompile_hermes_bytecode,
    extract_hermes_bundle,
)

runner = CliRunner()


# =====================================================================
# Unit Tests: Service Layer
# =====================================================================


def test_service_flutter_reverser() -> None:
    # 1. Dart snapshot inspect
    snapshot = inspect_dart_snapshot(architecture="arm64")
    assert snapshot["snapshot_magic_valid"] is True
    assert snapshot["architecture"] == "arm64"
    assert snapshot["class_count"] >= 3
    assert len(snapshot["api_endpoints"]) >= 2
    assert "MyApp" in snapshot["classes"][0]

    # 2. SSL pinning bypass generator
    arm64_bypass = generate_flutter_ssl_bypass(architecture="arm64")
    assert arm64_bypass["architecture"] == "arm64"
    assert arm64_bypass["target_symbol"] == "session_verify_cert_chain"
    assert "mov x0, #1; ret" in arm64_bypass["patch_disassembly"]
    assert "Interceptor.replace" in arm64_bypass["frida_script"]

    x86_bypass = generate_flutter_ssl_bypass(architecture="x86_64")
    assert "mov rax, 1; ret" in x86_bypass["patch_disassembly"]

    # 3. Engine proxy patch
    patched = patch_flutter_engine_proxy(proxy_host="192.168.1.100", proxy_port=8888)
    assert patched["status"] == "patched"
    assert patched["proxy_endpoint"] == "192.168.1.100:8888"
    assert "http" in patched["rerouted_protocols"]


def test_service_hermes_reverser() -> None:
    # 1. Hermes bundle extraction
    bundle_info = extract_hermes_bundle()
    assert bundle_info["is_hermes_bytecode"] is True
    assert bundle_info["format"] == "HBC"
    assert bundle_info["bytecode_version"] == 96
    assert bundle_info["function_count"] > 1000

    # 2. Hermes decompilation & secret harvesting
    decomp = decompile_hermes_bytecode(extract_secrets=True)
    assert decomp["status"] == "decompiled"
    assert decomp["bytecode_version"] == 96
    assert len(decomp["string_table"]) >= 5
    assert len(decomp["secrets_harvested"]) >= 3
    sec_types = {s["type"] for s in decomp["secrets_harvested"]}
    assert "Google API Key" in sec_types
    assert "Firebase Database URL" in sec_types


def test_service_scrcpy_fast() -> None:
    # 1. Fast action injection
    touch_res = inject_scrcpy_fast_action(
        action_type="touch",
        x=500,
        y=1000,
        action="down",
    )
    assert touch_res["status"] == "injected"
    assert touch_res["action_type"] == "touch"
    assert touch_res["latency_ms"] < 5.0
    assert touch_res["target_coordinates"] == {"x": 500, "y": 1000}
    assert touch_res["binary_wire_hex"].startswith("0200")

    # Keycode injection
    key_res = inject_scrcpy_fast_action(action_type="keycode", keycode=4)
    assert key_res["status"] == "injected"
    assert key_res["scrcpy_control_msg_type"] == 0

    # 2. Frame capture
    frame = capture_scrcpy_frame(width=1080, height=2400)
    assert frame["status"] == "captured"
    assert frame["resolution"] == "1080x2400"
    assert frame["fps"] == 60
    assert frame["latency_ms"] < 20.0
    assert "SurfaceControl" in frame["frame_source"]


def test_service_state_verifier() -> None:
    curr = {
        "activity": "LoginActivity",
        "visible_elements": ["btn_submit", "txt_user", "txt_pass"],
        "screen_title": "Login",
    }
    exp = {
        "activity": "LoginActivity",
        "visible_elements": ["btn_submit", "txt_user", "txt_pass"],
        "screen_title": "Login",
    }
    res = verify_gui_state(current_state=curr, expected_state=exp, match_tolerance=0.9)
    assert res["verified"] is True
    assert res["parity_score"] == 1.0
    assert res["activity_matches"] is True
    assert res["title_matches"] is True
    assert res["missing_elements"] == []

    # Mismatch test
    curr_diff = {
        "activity": "HomeActivity",
        "visible_elements": ["btn_logout"],
        "screen_title": "Home",
    }
    res_diff = verify_gui_state(current_state=curr_diff, expected_state=exp, match_tolerance=0.9)
    assert res_diff["verified"] is False
    assert res_diff["parity_score"] < 0.5
    assert len(res_diff["missing_elements"]) > 0


# =====================================================================
# Integration Tests: Runtime Invocations & Profile Checks
# =====================================================================


@pytest.mark.asyncio
async def test_phase13h_runtime_tools(runtime: Runtime) -> None:
    # 1. flutter_dart_snapshot_inspect
    r1 = await runtime.invoke("flutter_dart_snapshot_inspect", {"architecture": "arm64"})
    assert r1.data["snapshot_magic_valid"] is True
    assert r1.data["architecture"] == "arm64"

    # 2. flutter_ssl_pinning_bypass_gen
    r2 = await runtime.invoke("flutter_ssl_pinning_bypass_gen", {"architecture": "arm64"})
    assert r2.data["target_symbol"] == "session_verify_cert_chain"

    # 3. flutter_engine_proxy_patch
    r3 = await runtime.invoke(
        "flutter_engine_proxy_patch",
        {"proxy_host": "127.0.0.1", "proxy_port": 8080},
    )
    assert r3.data["status"] == "patched"
    assert r3.data["proxy_endpoint"] == "127.0.0.1:8080"

    # 4. rn_hermes_bundle_extract
    r4 = await runtime.invoke("rn_hermes_bundle_extract", {})
    assert r4.data["is_hermes_bytecode"] is True
    assert r4.data["format"] == "HBC"

    # 5. rn_hermes_decompile
    r5 = await runtime.invoke("rn_hermes_decompile", {"extract_secrets": True})
    assert r5.data["status"] == "decompiled"
    assert len(r5.data["secrets_harvested"]) >= 3

    # 6. dyn_scrcpy_inject_fast
    r6 = await runtime.invoke(
        "dyn_scrcpy_inject_fast",
        {"action_type": "touch", "x": 540, "y": 1200, "action": "down"},
        profile="dynamic",
    )
    assert r6.data["status"] == "injected"
    assert r6.data["latency_ms"] < 5.0

    # 7. dyn_scrcpy_frame_capture
    r7 = await runtime.invoke(
        "dyn_scrcpy_frame_capture",
        {"width": 1080, "height": 2400},
        profile="dynamic",
    )
    assert r7.data["status"] == "captured"

    # 8. dyn_gui_state_verify
    r8 = await runtime.invoke(
        "dyn_gui_state_verify",
        {"match_tolerance": 0.8},
        profile="dynamic",
    )
    assert r8.data["verified"] is True


@pytest.mark.asyncio
async def test_phase13h_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 210
    assert data["planned_tools"] >= 210

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] >= 119
    assert profiles["dynamic"] >= 150
    assert profiles["api"] == 139
    assert profiles["ui"] >= 138
    assert profiles["admin"] >= 18
    assert profiles["full"] >= 210


# =====================================================================
# CLI Tests: Subcommand Execution
# =====================================================================


def test_cli_flutter_commands(tmp_path: Path) -> None:
    # flutter snapshot
    r1 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "flutter", "snapshot", "--arch", "arm64"],
    )
    assert r1.exit_code == 0
    p1 = json.loads(r1.stdout)
    assert p1["data"]["snapshot_magic_valid"] is True

    # flutter ssl-bypass
    r2 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "flutter", "ssl-bypass", "--arch", "arm64"],
    )
    assert r2.exit_code == 0
    p2 = json.loads(r2.stdout)
    assert p2["data"]["target_symbol"] == "session_verify_cert_chain"

    # flutter proxy-patch
    r3 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "flutter",
            "proxy-patch",
            "--host",
            "10.0.2.2",
            "--port",
            "8888",
        ],
    )
    assert r3.exit_code == 0
    p3 = json.loads(r3.stdout)
    assert p3["data"]["proxy_endpoint"] == "10.0.2.2:8888"


def test_cli_react_native_commands(tmp_path: Path) -> None:
    # hermes-extract
    r1 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "react-native", "hermes-extract"],
    )
    assert r1.exit_code == 0
    p1 = json.loads(r1.stdout)
    assert p1["data"]["is_hermes_bytecode"] is True

    # hermes-decompile
    r2 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "react-native", "hermes-decompile"],
    )
    assert r2.exit_code == 0
    p2 = json.loads(r2.stdout)
    assert p2["data"]["status"] == "decompiled"
    assert len(p2["data"]["secrets_harvested"]) >= 3


def test_cli_dynamic_commands(tmp_path: Path) -> None:
    # scrcpy-inject
    r1 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--profile",
            "dynamic",
            "--json",
            "dynamic",
            "scrcpy-inject",
            "-x",
            "540",
            "-y",
            "1200",
        ],
    )
    assert r1.exit_code == 0
    p1 = json.loads(r1.stdout)
    assert p1["data"]["status"] == "injected"

    # scrcpy-frame
    r2 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--profile",
            "dynamic",
            "--json",
            "dynamic",
            "scrcpy-frame",
            "-w",
            "1080",
            "-h",
            "2400",
        ],
    )
    assert r2.exit_code == 0
    p2 = json.loads(r2.stdout)
    assert p2["data"]["status"] == "captured"

    # state-verify
    r3 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--profile",
            "dynamic",
            "--json",
            "dynamic",
            "state-verify",
            "--action",
            "tap_login",
        ],
    )
    assert r3.exit_code == 0
    p3 = json.loads(r3.stdout)
    assert p3["data"]["verified"] is True
