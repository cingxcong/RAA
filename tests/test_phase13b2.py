"""Tests for Phase 13B-2: Perfetto Dynamic Tracing & Semantic Jetpack Compose Parity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.perfetto_analyzer import (
    analyze_perfetto_events,
    generate_perfetto_config,
    record_perfetto_trace,
)
from raa.services.semantic_compose import (
    diff_compose_parity,
    modernize_xml_to_compose,
)

runner = CliRunner()


def _invoke_cli(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["--workspace", str(tmp_path / "workspace"), *args],
    )


SAMPLE_XML_LAYOUT = """<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <TextView
        android:id="@+id/tv_title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Welcome to CryptoVault"
        android:textSize="20sp" />

    <EditText
        android:id="@+id/et_passphrase"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="Enter seed phrase" />

    <Button
        android:id="@+id/btn_unlock"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Unlock Wallet" />

    <FrameLayout
        android:id="@+id/fl_container"
        android:layout_width="match_parent"
        android:layout_height="wrap_content">
        <ImageView
            android:id="@+id/iv_badge"
            android:layout_width="48dp"
            android:layout_height="48dp"
            android:contentDescription="Security Shield" />
    </FrameLayout>
</LinearLayout>
"""


# =====================================================================
# Unit Tests: Perfetto Dynamic Tracing & Storm Analyzer
# =====================================================================


def test_perfetto_config_generation() -> None:
    config_text = generate_perfetto_config(
        duration_ms=8000,
        buffer_kb=32768,
        enable_binder=True,
        enable_scheduling=True,
    )
    assert "duration_ms: 8000" in config_text
    assert "size_kb: 32768" in config_text
    assert 'ftrace_events: "binder/binder_transaction"' in config_text
    assert 'ftrace_events: "sched/sched_switch"' in config_text


def test_perfetto_record_trace() -> None:
    trace_info = record_perfetto_trace(
        package_name="com.example.cryptovault",
        duration_ms=5000,
    )
    assert trace_info["package_name"] == "com.example.cryptovault"
    assert "perfetto" in trace_info["adb_record_command"]
    assert "pull" in trace_info["adb_pull_command"]
    assert trace_info["status"] == "trace_configured"


def test_perfetto_storm_analyzer_anomalies() -> None:
    events = []
    # 1. 60 binder events
    for _ in range(60):
        events.append({"name": "binder_transaction", "dur_ms": 1.0})
    # 2. 120 sched events with minimal duration
    for _ in range(120):
        events.append({"name": "sched_switch", "dur_ms": 0.1})
    # 3. ANR duration block
    events.append({"name": "main_thread_block", "dur_ms": 5200.0})

    analysis = analyze_perfetto_events(events, target_package="com.example.cryptovault")
    assert analysis["has_binder_storm"] is True
    assert analysis["has_anr_risk"] is True
    assert analysis["binder_transactions"] == 60
    assert analysis["cpu_active_slices"] == 120
    assert analysis["ui_thread_blocked_ms"] >= 5200.0
    assert len(analysis["anomalies"]) >= 2


# =====================================================================
# Unit Tests: Semantic XML to Jetpack Compose & Parity Diff Engine
# =====================================================================


def test_semantic_compose_modernize() -> None:
    res = modernize_xml_to_compose(
        xml_content=SAMPLE_XML_LAYOUT,
        target_package="com.example.cryptovault.ui",
        screen_name="CryptoVaultScreen",
        enable_edge_to_edge=True,
    )
    code = res["kotlin_composable_code"]
    assert "@Composable" in code
    assert "fun CryptoVaultScreen(" in code
    assert "safeDrawingPadding()" in code
    assert "Column(" in code
    assert 'Text(text = "Welcome to CryptoVault"' in code
    assert "OutlinedTextField(" in code
    assert "Button(" in code
    assert "Box(" in code  # FrameLayout -> Box
    assert res["elements_transformed_count"] >= 4
    assert res["depth_reduction_ratio"] >= 0.0


def test_compose_parity_diff() -> None:
    parity = diff_compose_parity(
        xml_element_count=5,
        compose_element_count=5,
        has_text_parity=True,
        has_click_parity=True,
    )
    assert parity["parity_score"] >= 90.0
    assert parity["is_acceptable_parity"] is True
    assert parity["fidelity_rating"] == "EXCELLENT"

    sub_parity = diff_compose_parity(
        xml_element_count=10,
        compose_element_count=5,
        has_text_parity=False,
        has_click_parity=False,
    )
    assert sub_parity["parity_score"] < 70.0
    assert sub_parity["is_acceptable_parity"] is False
    assert len(sub_parity["deductions"]) >= 2


# =====================================================================
# Integration Tests: Runtime Invocation & Tool Registration
# =====================================================================


@pytest.mark.asyncio
async def test_phase13b2_runtime_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # Verify capabilities and profile sizes
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 177
    assert caps.data["planned_tools"] >= 177
    assert caps.data["profiles"]["dynamic"] >= 126
    assert caps.data["profiles"]["ui"] >= 129
    assert caps.data["profiles"]["full"] >= 177

    proj = runtime.projects.create(
        name="Phase 13B-2 Project",
        description="Testing Phase 13B-2",
        scopes=["dynamic.device", "project.read", "static.read", "export.raw"],
    )
    pid = proj.id

    # 1. dyn_perfetto_record
    record_res = await runtime.invoke(
        "dyn_perfetto_record",
        {"project_id": pid, "package_name": "com.example.wallet", "duration_ms": 3000},
        profile="dynamic",
    )
    assert record_res.data["package_name"] == "com.example.wallet"
    assert "adb_record_command" in record_res.data
    assert "config_pftxt" in record_res.data

    # 2. dyn_perfetto_query
    query_res = await runtime.invoke(
        "dyn_perfetto_query",
        {
            "project_id": pid,
            "target_package": "com.example.wallet",
            "events_log": "binder_transaction node=1\nbinder_transaction node=2\n",
        },
        profile="dynamic",
    )
    assert "has_binder_storm" in query_res.data
    assert query_res.data["binder_transactions"] == 2

    # 3. ui_xml_semantic_modernize
    mod_res = await runtime.invoke(
        "ui_xml_semantic_modernize",
        {
            "project_id": pid,
            "xml_content": SAMPLE_XML_LAYOUT,
            "screen_name": "MainScreen",
            "enable_edge_to_edge": True,
        },
        profile="ui",
    )
    assert "@Composable" in mod_res.data["kotlin_composable_code"]
    assert mod_res.data["edge_to_edge_enabled"] is True

    # 4. ui_parity_diff
    diff_res = await runtime.invoke(
        "ui_parity_diff",
        {
            "project_id": pid,
            "xml_element_count": 5,
            "compose_element_count": 5,
            "has_text_parity": True,
            "has_click_parity": True,
        },
        profile="ui",
    )
    assert diff_res.data["parity_score"] >= 90.0
    assert diff_res.data["is_acceptable_parity"] is True


# =====================================================================
# CLI Tests: Dynamic Perfetto & UI Semantic Modernize
# =====================================================================


def test_cli_perfetto_and_semantic_modernize(tmp_path: Path) -> None:
    # First create a project with dynamic.device scope
    create_res = _invoke_cli(
        tmp_path,
        "--json",
        "project",
        "create",
        "CLI Perfetto Test",
        "--scope",
        "dynamic.device",
        "--scope",
        "project.read",
    )
    assert create_res.exit_code == 0
    project_id = json.loads(create_res.stdout)["data"]["id"]

    # Test dynamic perfetto-record
    rec_result = _invoke_cli(
        tmp_path,
        "--json",
        "dynamic",
        "perfetto-record",
        project_id,
        "--package",
        "com.test.app",
        "--duration",
        "4000",
    )
    assert rec_result.exit_code == 0
    rec_data = json.loads(rec_result.stdout)
    assert rec_data["data"]["package_name"] == "com.test.app"

    # Test dynamic perfetto-query
    query_result = _invoke_cli(
        tmp_path,
        "--json",
        "dynamic",
        "perfetto-query",
        project_id,
        "--package",
        "com.test.app",
        "--log",
        "binder_transaction slice=10\n",
    )
    assert query_result.exit_code == 0
    query_data = json.loads(query_result.stdout)
    assert "has_binder_storm" in query_data["data"]

    # Test ui semantic-modernize
    mod_result = _invoke_cli(
        tmp_path,
        "--json",
        "ui",
        "semantic-modernize",
        SAMPLE_XML_LAYOUT,
        "--name",
        "GeneratedScreen",
    )
    assert mod_result.exit_code == 0
    mod_data = json.loads(mod_result.stdout)
    assert "@Composable" in mod_data["data"]["kotlin_composable_code"]

    # Test ui parity-diff
    diff_result = _invoke_cli(
        tmp_path,
        "--json",
        "ui",
        "parity-diff",
        "--xml-count",
        "6",
        "--compose-count",
        "6",
    )
    assert diff_result.exit_code == 0
    diff_data = json.loads(diff_result.stdout)
    assert diff_data["data"]["parity_score"] >= 90.0
