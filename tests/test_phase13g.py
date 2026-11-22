"""Phase 13G Integration & Unit Tests.

Covers:
- Headless VirtualDisplay Dynamic Exploration (dyn_virtual_display_start, dyn_virtual_display_stop)
- Multimodal Mobile GUI Agent Crawler (dyn_gui_agent_crawl)
- Visual Grounding & Touch Navigation Engine (ui_visual_grounding_navigate)
- On-Device Mobile-Harness PRoot Workspace (termux_workspace_harness)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.mobile_harness import configure_termux_workspace
from raa.services.android.virtual_display import start_virtual_display, stop_virtual_display
from raa.services.gui_agent import crawl_gui_agent
from raa.services.visual_grounding import navigate_visual_grounding

runner = CliRunner()


# =====================================================================
# Unit Tests: Service Layer
# =====================================================================


def test_service_virtual_display() -> None:
    session = start_virtual_display(
        display_name="test-headless-vdisp",
        width=1080,
        height=2400,
        density_dpi=420,
        target_package="com.example.app",
    )
    assert session["status"] == "running"
    assert session["display_name"] == "test-headless-vdisp"
    assert session["resolution"] == "1080x2400"
    assert "screencap" in session["control_commands"]["screencap"]
    assert "am start" in session["control_commands"]["launch"]

    stopped = stop_virtual_display(session["session_id"], session["display_id"])
    assert stopped["status"] == "stopped"
    assert stopped["session_id"] == session["session_id"]


def test_service_gui_agent() -> None:
    res = crawl_gui_agent(
        target_package="com.target.flutterapp",
        max_steps=4,
        goal_prompt="Navigate to transaction history",
        allow_permission_bypass=True,
    )
    assert res["status"] == "completed"
    assert res["target_package"] == "com.target.flutterapp"
    assert res["steps_completed"] == 4
    assert len(res["trajectory"]) == 4
    assert "Runtime Permissions Dialog" in res["bypassed_dialogs"]
    assert res["trajectory"][0]["action_type"] == "tap"


def test_service_visual_grounding() -> None:
    # Test query for login button
    res = navigate_visual_grounding("tap the login button", screen_width=1080, screen_height=2400)
    assert res["resolved_element_type"] == "button"
    assert res["confidence"] >= 0.9
    coords = res["target_coordinates"]
    assert 0 < coords["x"] < 1080
    assert 0 < coords["y"] < 2400
    assert "input tap" in res["adb_input_command"]

    # Test query for search bar
    res_search = navigate_visual_grounding(
        "search input field", screen_width=1080, screen_height=2400
    )
    assert res_search["resolved_element_type"] == "input"
    assert res_search["bounding_box"]["pixels"]["top"] > 0


def test_service_mobile_harness() -> None:
    res = configure_termux_workspace(
        workspace_dir="/data/data/com.termux/files/home/raa-test",
        rootfs_type="debian_arm64",
        enable_smali_patching=True,
    )
    assert res["status"] == "ready"
    assert res["rootfs_type"] == "debian_arm64"
    assert res["installed_packages_count"] >= 5
    assert "proot" in res["launch_script"]
    assert "diff -u" in res["patch_helper_script"]


# =====================================================================
# Integration Tests: Runtime Invocation & Capabilities
# =====================================================================


@pytest.mark.asyncio
async def test_phase13g_runtime_tool_invocations(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 202
    assert caps.data["planned_tools"] >= 202
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 114
    assert caps.data["profiles"]["dynamic"] >= 144
    assert caps.data["profiles"]["api"] >= 139
    assert caps.data["profiles"]["ui"] >= 137
    assert caps.data["profiles"]["admin"] >= 18
    assert caps.data["profiles"]["full"] >= 202

    # 1. dyn_virtual_display_start & stop (dynamic, full)
    start_res = await runtime.invoke(
        "dyn_virtual_display_start",
        {"display_name": "headless-runtime", "width": 1080, "height": 1920},
        profile="dynamic",
    )
    assert start_res.data["status"] == "running"
    session_id = start_res.data["session_id"]

    stop_res = await runtime.invoke(
        "dyn_virtual_display_stop",
        {"session_id": session_id},
        profile="dynamic",
    )
    assert stop_res.data["status"] == "stopped"

    # 2. dyn_gui_agent_crawl (dynamic, ui, full)
    crawl_res = await runtime.invoke(
        "dyn_gui_agent_crawl",
        {"target_package": "com.flutter.demo", "max_steps": 3},
        profile="ui",
    )
    assert crawl_res.data["status"] == "completed"
    assert crawl_res.data["steps_completed"] == 3

    # 3. ui_visual_grounding_navigate (ui, dynamic, full)
    nav_res = await runtime.invoke(
        "ui_visual_grounding_navigate",
        {"target_query": "skip tutorial", "screen_width": 1080, "screen_height": 2400},
        profile="ui",
    )
    assert nav_res.data["resolved_element_type"] == "button"
    assert nav_res.data["target_coordinates"]["x"] > 0

    # 4. termux_workspace_harness (core, dynamic, full)
    harness_res = await runtime.invoke(
        "termux_workspace_harness",
        {"workspace_dir": "/data/data/com.termux/files/home/raa-harness"},
        profile="core",
    )
    assert harness_res.data["status"] == "ready"
    assert "proot" in harness_res.data["launch_script"]


# =====================================================================
# CLI Tests
# =====================================================================


def test_cli_virtual_display(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "virtual-display-start",
            "--name",
            "cli-vdisp",
            "--width",
            "1080",
            "--height",
            "2400",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "running"
    session_id = data["data"]["session_id"]

    stop_res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "virtual-display-stop",
            session_id,
        ],
    )
    assert stop_res.exit_code == 0
    assert json.loads(stop_res.stdout)["data"]["status"] == "stopped"


def test_cli_gui_crawl(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "gui-crawl",
            "com.canvas.app",
            "--steps",
            "3",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "completed"
    assert data["data"]["steps_completed"] == 3


def test_cli_visual_navigate(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "ui",
            "visual-navigate",
            "click settings gear icon",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["resolved_element_type"] == "icon"
    assert data["data"]["confidence"] >= 0.9


def test_cli_termux_harness(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "tools",
            "termux-harness",
            "--rootfs",
            "debian_arm64",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "ready"
    assert data["data"]["rootfs_type"] == "debian_arm64"
