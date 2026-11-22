"""Tests for Phase 13L: Accessibility Agent, AppAgent Recording, QA Telemetry & AppFunctions.

Covers:
- Track 48 (Tencent AppAgent): Demonstration GUI Task Recorder & Action Graph Replay
- Track 49 (MobileAgent-Android): PC-Less Standalone On-Device Accessibility Fuzzing Agent
- Track 50 (android-qa-agent): QA Scenario Replay with Real-Time Telemetry & Perfetto Trace Slicing
- Track 51 (nowinandroid): AGENTS.md Repository Architecture Contract Generator
- Track 52 (appfunctions): Android 16 AppFunctionManager Dynamic Invocation & Security Fuzzer
- Profile target counts:
  minimal: 12, core: 125, dynamic: 166, api: 139, ui: 139, admin: 19, full: 230
- CLI subcommands: gui-record, accessibility-agent, qa-replay, agents-spec, appfunction-invoke
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.accessibility_agent import control_ondevice_accessibility_agent
from raa.services.android.appfunction_fuzzer import invoke_or_fuzz_appfunction
from raa.services.android.gui_recorder import record_or_playback_gui_actions
from raa.services.android.qa_telemetry import replay_qa_scenario
from raa.services.rebuild.agents_spec import generate_agents_spec


def test_gui_recorder_service() -> None:
    rec = record_or_playback_gui_actions(action="record")
    assert rec["status"] == "recording_active"
    assert rec["total_steps"] > 0
    sess = rec["session_id"]

    stopped = record_or_playback_gui_actions(action="stop_record", session_id=sess)
    assert stopped["status"] == "recording_stopped_and_compiled"

    replayed = record_or_playback_gui_actions(
        action="playback", session_id=sess, fuzz_boundaries=True
    )
    assert replayed["status"] == "replayed_with_boundary_fuzzing"
    assert replayed["fuzzing_mutations_count"] > 0


def test_accessibility_agent_service() -> None:
    installed = control_ondevice_accessibility_agent(action="install_agent")
    assert installed["status"] == "installed_and_enabled"
    assert installed["accessibility_permission_granted"] is True

    started = control_ondevice_accessibility_agent(action="start")
    assert started["status"] == "running"
    assert started["tether_required"] is False

    stopped = control_ondevice_accessibility_agent(action="stop")
    assert stopped["status"] == "stopped"


def test_qa_telemetry_service() -> None:
    res = replay_qa_scenario(
        target_package="com.example.bank",
        capture_perfetto_on_drop=True,
        fps_drop_threshold=45,
    )
    assert res["target_package"] == "com.example.bank"
    assert "average_fps" in res
    assert "peak_cpu_pct" in res
    assert res["frame_drop_detected"] is True
    assert res["perfetto_trace_captured"] is True
    assert res["perfetto_trace_path"] is not None


def test_agents_spec_service(tmp_path: Path) -> None:
    out_file = tmp_path / "AGENTS.md"
    res = generate_agents_spec(
        project_id="proj-rebuild-01",
        app_name="TestModernApp",
        output_path=str(out_file),
    )
    assert res["app_name"] == "TestModernApp"
    assert out_file.is_file()
    text = out_file.read_text(encoding="utf-8")
    assert "Compose-First UI" in text
    assert "dyn_gui_state_verify" in text


def test_appfunction_fuzzer_service() -> None:
    trusted = invoke_or_fuzz_appfunction(
        caller_package="com.google.android.googlequicksearchbox",
        fuzz_mode=False,
    )
    assert trusted["caller_authorized"] is True
    assert trusted["execution_status"] == "success"

    untrusted = invoke_or_fuzz_appfunction(
        caller_package="com.unauthorized.thirdparty",
        fuzz_mode=True,
    )
    assert untrusted["caller_authorized"] is False
    assert untrusted["execution_status"] == "permission_denied"
    assert untrusted["fuzz_mutations_count"] > 0


@pytest.mark.asyncio
async def test_phase13l_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # 1. dyn_gui_record_playback
    r1 = await runtime.invoke(
        "dyn_gui_record_playback",
        {"action": "playback", "fuzz_boundaries": True},
        profile="dynamic",
    )
    assert r1.data["status"] == "replayed_with_boundary_fuzzing"

    # 2. dyn_ondevice_accessibility_agent
    r2 = await runtime.invoke(
        "dyn_ondevice_accessibility_agent",
        {"action": "start"},
        profile="dynamic",
    )
    assert r2.data["status"] == "running"

    # 3. dyn_qa_scenario_replay
    r3 = await runtime.invoke(
        "dyn_qa_scenario_replay",
        {"target_package": "com.target.app"},
        profile="dynamic",
    )
    assert "average_fps" in r3.data

    # 4. rebuild_agents_spec_generate
    spec_path = tmp_path / "AGENTS.md"
    r4 = await runtime.invoke(
        "rebuild_agents_spec_generate",
        {"app_name": "DemoComposeApp", "output_path": str(spec_path)},
        profile="core",
    )
    assert r4.data["app_name"] == "DemoComposeApp"
    assert spec_path.is_file()

    # 5. dyn_appfunction_invoke
    r5 = await runtime.invoke(
        "dyn_appfunction_invoke",
        {"function_id": "sharePhoto", "fuzz_mode": True},
        profile="dynamic",
    )
    assert r5.data["fuzz_mode"] is True


@pytest.mark.asyncio
async def test_phase13l_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 230
    assert data["planned_tools"] >= 230

    profiles = data["profiles"]
    assert profiles["minimal"] >= 12
    assert profiles["core"] >= 125
    assert profiles["dynamic"] >= 166
    assert profiles["api"] >= 139
    assert profiles["ui"] >= 139
    assert profiles["admin"] >= 19
    assert profiles["full"] >= 230


def test_phase13l_cli_commands(tmp_path: Path) -> None:
    runner = CliRunner()

    def run_cli(*args: str) -> dict:
        cmd = ["--workspace", str(tmp_path), "--json", *args]
        res = runner.invoke(app, cmd)
        assert res.exit_code == 0, f"Command failed: {res.stdout}"
        return json.loads(res.stdout)

    # 1. dynamic gui-record
    r1 = run_cli("dynamic", "gui-record", "--action", "record")
    assert r1["data"]["status"] == "recording_active"

    # 2. dynamic accessibility-agent
    r2 = run_cli("dynamic", "accessibility-agent", "--action", "start")
    assert r2["data"]["status"] == "running"

    # 3. dynamic qa-replay
    r3 = run_cli("dynamic", "qa-replay", "--package", "com.target.app")
    assert "average_fps" in r3["data"]

    # 4. rebuild agents-spec
    out_spec = tmp_path / "CLI_AGENTS.md"
    r4 = run_cli("rebuild", "agents-spec", "--app-name", "CliApp", "--output", str(out_spec))
    assert r4["data"]["app_name"] == "CliApp"
    assert out_spec.is_file()

    # 5. dynamic appfunction-invoke
    r5 = run_cli("dynamic", "appfunction-invoke", "--func", "sendDirectMessage", "--fuzz")
    assert r5["data"]["fuzz_mode"] is True
