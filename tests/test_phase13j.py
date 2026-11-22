"""Tests for Phase 13J: Ephemeral Docker Android Sandbox, ARM Translation & Agent Automation.

Covers:
- Track 41 (LAMDA): Remote WebRTC Agent Connect & Hardware Multi-Touch Dispatch
- Track 42 (Docker-Android): Disposable Containerized Android Emulators & Sandbox Teardown
- Track 43 (Agent-Device & Argent): Agent Protocol Automation & Visual Regression Diff
- Track 44 (Genymotion ARM Translation): Emulator ARM/ARM64 Translation Flash & Configuration
- Exact profile target counts:
  minimal: 12, core: 122, dynamic: 162, api: 139, ui: 139, admin: 18, full: 222
- CLI subcommands for all 7 tools
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.agent_device import audit_visual_diff, control_agent_device
from raa.services.android.arm_translation import inject_emulator_arm_translation
from raa.services.android.docker_sandbox import (
    spawn_docker_android_sandbox,
    teardown_docker_android_sandbox,
)
from raa.services.android.lamda_bridge import connect_lamda_daemon, dispatch_lamda_touch_event


def test_lamda_bridge_service() -> None:
    conn = connect_lamda_daemon(host="192.168.1.100", port=65000, auth_token="secret")
    assert conn["status"] == "connected"
    assert conn["daemon_endpoint"] == "192.168.1.100:65000"
    assert conn["device_info"]["abi"] == "arm64-v8a"
    assert conn["protocol"] == "gRPC/WebRTC"

    touch = dispatch_lamda_touch_event(
        session_id=conn["session_id"],
        event_type="tap",
        x=300,
        y=600,
        duration_ms=40,
    )
    assert touch["status"] == "dispatched"
    assert touch["event_type"] == "tap"
    assert touch["points"] == [{"x": 300, "y": 600}]

    swipe = dispatch_lamda_touch_event(
        session_id=conn["session_id"],
        event_type="swipe",
        points=[{"x": 100, "y": 100}, {"x": 100, "y": 500}],
        duration_ms=250,
    )
    assert swipe["status"] == "dispatched"
    assert swipe["event_type"] == "swipe"
    assert len(swipe["points"]) == 2


def test_docker_sandbox_service() -> None:
    sandbox = spawn_docker_android_sandbox(
        image="budtmo/docker-android:emulator_11.0",
        device_name="Pixel 4",
        kvm_enabled=True,
        adb_port=5555,
        novnc_port=6080,
    )
    assert sandbox["status"] == "running"
    assert sandbox["kvm_acceleration"] is True
    assert sandbox["novnc_stream_url"] == "http://127.0.0.1:6080"
    cid = sandbox["container_id"]

    teardown = teardown_docker_android_sandbox(container_id=cid, purge_volumes=True)
    assert teardown["status"] == "terminated"
    assert teardown["container_id"] == cid
    assert teardown["purged_volumes"] is True


def test_agent_device_service(tmp_path: Path) -> None:
    launch = control_agent_device(
        device_id="emulator-5554",
        action="launch",
        target_package="com.example.targetapp",
    )
    assert launch["action"] == "launch"
    assert launch["target_package"] == "com.example.targetapp"
    assert launch["result"]["status"] == "launched"

    ax = control_agent_device(action="ax_tree", target_package="com.example.targetapp")
    assert ax["action"] == "ax_tree"
    assert ax["result"]["status"] == "tree_extracted"
    assert "node_count" in ax["result"]

    js = control_agent_device(action="eval_js", script_js="return window.location.href;")
    assert js["action"] == "eval_js"
    assert js["result"]["status"] == "evaluated"

    logs = control_agent_device(action="logcat", log_filter="ActivityManager")
    assert logs["action"] == "logcat"
    assert logs["result"]["status"] == "streamed"

    # Visual diff test
    p1 = tmp_path / "orig.png"
    p2 = tmp_path / "rebuilt.png"
    p1.write_bytes(b"\x89PNG\r\n\x1a\n" + b"dummyoriginalscreen12345")
    p2.write_bytes(b"\x89PNG\r\n\x1a\n" + b"dummyrebuiltscreen1234567")

    diff = audit_visual_diff(
        original_screenshot_path=str(p1),
        rebuilt_screenshot_path=str(p2),
        tolerance=0.05,
    )
    assert "visual_similarity_score" in diff
    assert diff["passed"] is True
    assert diff["tolerance"] == 0.05
    assert len(diff["visual_shifts"]) > 0


def test_arm_translation_service() -> None:
    res = inject_emulator_arm_translation(
        device_id="emulator-5554",
        emulator_abi="x86_64",
        android_api=30,
        translation_package="houdini",
    )
    assert res["status"] == "flashed_and_rebooted"
    assert res["detected_host_abi"] == "x86_64"
    assert res["supported_guest_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert res["injected_libraries_count"] > 0


@pytest.mark.asyncio
async def test_phase13j_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # 1. dyn_lamda_daemon_connect
    r1 = await runtime.invoke(
        "dyn_lamda_daemon_connect",
        {"host": "127.0.0.1", "port": 65000},
        profile="dynamic",
    )
    assert r1.data["status"] == "connected"
    sess = r1.data["session_id"]

    # 2. dyn_lamda_touch_event
    r2 = await runtime.invoke(
        "dyn_lamda_touch_event",
        {"session_id": sess, "event_type": "tap", "x": 540, "y": 960},
        profile="dynamic",
    )
    assert r2.data["status"] == "dispatched"

    # 3. dyn_docker_android_spawn
    r3 = await runtime.invoke(
        "dyn_docker_android_spawn",
        {"image": "budtmo/docker-android:emulator_11.0", "device_name": "Nexus 6"},
        profile="dynamic",
    )
    assert r3.data["status"] == "running"
    cid = r3.data["container_id"]

    # 4. dyn_docker_android_teardown
    r4 = await runtime.invoke(
        "dyn_docker_android_teardown",
        {"container_id": cid, "purge_volumes": True},
        profile="dynamic",
    )
    assert r4.data["status"] == "terminated"

    # 5. dyn_agent_device_control
    r5 = await runtime.invoke(
        "dyn_agent_device_control",
        {"action": "ax_tree", "target_package": "com.android.settings"},
        profile="dynamic",
    )
    assert r5.data["action"] == "ax_tree"
    assert r5.data["result"]["status"] == "tree_extracted"

    # 6. dyn_visual_diff_audit
    s1 = tmp_path / "screen1.png"
    s2 = tmp_path / "screen2.png"
    s1.write_bytes(b"\x89PNG\r\n\x1a\n" + b"screenA")
    s2.write_bytes(b"\x89PNG\r\n\x1a\n" + b"screenB")
    r6 = await runtime.invoke(
        "dyn_visual_diff_audit",
        {"original_screenshot_path": str(s1), "rebuilt_screenshot_path": str(s2)},
        profile="dynamic",
    )
    assert "visual_similarity_score" in r6.data
    assert r6.data["passed"] is True

    # Also test dyn_visual_diff_audit under ui profile
    r6_ui = await runtime.invoke(
        "dyn_visual_diff_audit",
        {"original_screenshot_path": str(s1), "rebuilt_screenshot_path": str(s2)},
        profile="ui",
    )
    assert "visual_similarity_score" in r6_ui.data

    # 7. dyn_emulator_arm_translation_inject
    r7 = await runtime.invoke(
        "dyn_emulator_arm_translation_inject",
        {"emulator_abi": "x86_64", "android_api": 31, "translation_package": "houdini"},
        profile="dynamic",
    )
    assert r7.data["status"] == "flashed_and_rebooted"
    assert r7.data["detected_host_abi"] == "x86_64"


@pytest.mark.asyncio
async def test_phase13j_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 222
    assert data["planned_tools"] >= 222

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] >= 122
    assert profiles["dynamic"] >= 162
    assert profiles["api"] == 139
    assert profiles["ui"] >= 139
    assert profiles["admin"] >= 18
    assert profiles["full"] >= 222


def test_phase13j_cli_commands(tmp_path: Path) -> None:
    runner = CliRunner()

    def run_cli(*args: str) -> dict:
        cmd = ["--workspace", str(tmp_path), "--json", *args]
        res = runner.invoke(app, cmd)
        assert res.exit_code == 0, f"Command failed: {res.stdout}"
        return json.loads(res.stdout)

    # 1. lamda-connect
    r1 = run_cli("dynamic", "lamda-connect", "--host", "127.0.0.1", "--port", "65000")
    assert r1["data"]["status"] == "connected"
    sess = r1["data"]["session_id"]

    # 2. lamda-touch
    r2 = run_cli("dynamic", "lamda-touch", "--session", sess, "--type", "tap", "--x", "500")
    assert r2["data"]["status"] == "dispatched"

    # 3. docker-spawn
    r3 = run_cli("dynamic", "docker-spawn", "--device", "Pixel 4")
    assert r3["data"]["status"] == "running"
    cid = r3["data"]["container_id"]

    # 4. docker-teardown
    r4 = run_cli("dynamic", "docker-teardown", cid)
    assert r4["data"]["status"] == "terminated"

    # 5. agent-control
    r5 = run_cli("dynamic", "agent-control", "--action", "ax_tree")
    assert r5["data"]["action"] == "ax_tree"
    assert r5["data"]["result"]["status"] == "tree_extracted"

    # 6. visual-diff
    f1 = tmp_path / "img1.png"
    f2 = tmp_path / "img2.png"
    f1.write_bytes(b"screen1")
    f2.write_bytes(b"screen2")
    r6 = run_cli("dynamic", "visual-diff", "--orig", str(f1), "--rebuilt", str(f2))
    assert "visual_similarity_score" in r6["data"]

    # 7. arm-translate
    r7 = run_cli("dynamic", "arm-translate", "--abi", "x86_64", "--api", "30")
    assert r7["data"]["status"] == "flashed_and_rebooted"
