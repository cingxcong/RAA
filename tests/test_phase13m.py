"""Tests for Phase 13M: RASP Bypass, Zero-Config VPN, Shizuku Bridge & Chaos Mutator.

Covers:
- Track 53 (httptoolkit-android): dyn_httptoolkit_vpn_intercept
- Track 54 (freeRASP & Promon): sec_rasp_signature_scan & dyn_rasp_bypass_gen
- Track 55 (BetterAndroid Notification Icons): ui_notification_icon_audit
- Track 56 (ShizukuX Binder IPC): shizuku_privileged_exec
- Track 57 (oh-my-android Chaos Mutator): dyn_device_env_mutate & termux_ondevice_binary_bundle
- Profile target counts:
  minimal: 12, core: 128, dynamic: 169, api: 139, ui: 140, admin: 19, full: 237
- CLI subcommands:
  dynamic vpn-intercept, dynamic rasp-bypass, dynamic device-mutate,
  dynamic shizuku-exec, dynamic termux-bundle, security rasp-scan, ui notification-audit
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.device_mutator import mutate_device_environment
from raa.services.android.notification_icons import (
    audit_notification_icons,
    generate_notification_icon,
)
from raa.services.android.rasp_bypass import generate_rasp_bypass
from raa.services.android.shizuku_bridge import execute_shizuku_command
from raa.services.android.termux_bundle import manage_termux_bundle
from raa.services.android.vpn_interceptor import manage_vpn_interception
from raa.services.security.rasp_detector import scan_rasp_signatures


def test_vpn_interceptor_service(tmp_path: Path) -> None:
    # Test status
    status = manage_vpn_interception(action="status")
    assert status["action"] == "status"
    assert "proxy_active" in status

    # Test start & stop
    start = manage_vpn_interception(action="start", proxy_host="127.0.0.1", proxy_port=8080)
    assert start["action"] == "start"
    assert start["status"] == "interception_active"

    stop = manage_vpn_interception(action="stop")
    assert stop["action"] == "stop"
    assert stop["status"] == "interception_stopped"

    # Test inject_ca
    fake_cert = tmp_path / "test_ca.crt"
    fake_cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIICfake\n-----END CERTIFICATE-----\n")
    inject = manage_vpn_interception(action="inject_ca", ca_cert_path=str(fake_cert))
    assert inject["action"] == "inject_ca"
    assert inject["status"] == "success"
    assert len(inject["cert_hash"]) > 0


def test_rasp_detector_service(tmp_path: Path) -> None:
    # Build sample directory with mock Smali and native files
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "Threats.smali").write_text(
        """.class public Lcom/aheaditec/talsec/security/ThreatListener;
        .method public onRootDetected()V
        return-void
        .end method
        """,
        encoding="utf-8",
    )
    (smali_dir / "RootCheck.smali").write_text(
        """const-string v0, "/system/bin/su"
        invoke-static {v0}, Ljava/io/File;->exists()Z
        """,
        encoding="utf-8",
    )

    res = scan_rasp_signatures(str(tmp_path))
    assert res["risk_level"] in {"CRITICAL", "HIGH"}
    assert res["total_signatures_found"] >= 2
    fws = [f["framework"] for f in res["detected_frameworks"]]
    assert "freeRASP" in fws
    assert len(res["recommendations"]) > 0


def test_rasp_bypass_service(tmp_path: Path) -> None:
    out_js = tmp_path / "bypass.js"
    res = generate_rasp_bypass(
        target_package="com.bank.app",
        bypasses=["freerasp", "root", "debugger", "emulator"],
        output_script_path=str(out_js),
        auto_inject=False,
    )
    assert res["target_package"] == "com.bank.app"
    assert "freerasp" in res["bypasses_applied"]
    assert "root" in res["bypasses_applied"]
    assert out_js.exists()
    content = out_js.read_text(encoding="utf-8")
    assert "ThreatListener" in content
    assert "/system/bin/su" in content


def test_notification_icons_service(tmp_path: Path) -> None:
    gen = generate_notification_icon(
        icon_name="ic_stat_bell",
        output_dir=str(tmp_path / "res"),
        generate_vector_xml=True,
        generate_png_densities=True,
    )
    assert gen["icon_name"] == "ic_stat_bell"
    assert len(gen["generated_files"]) >= 5
    assert Path(gen["vector_xml_path"]).exists()

    # Test audit
    manifest_snippet = """<manifest>
    <application>
        <meta-data android:name="com.google.firebase.messaging.default_notification_icon"
                   android:resource="@drawable/ic_stat_bell" />
    </application>
    </manifest>
    """
    audit = audit_notification_icons(manifest_xml=manifest_snippet)
    assert audit["has_default_icon_metadata"] is True
    assert audit["default_icon_drawable"] == "ic_stat_bell"
    assert audit["contrast_ratio_light"] > 4.5


def test_shizuku_bridge_service() -> None:
    status = execute_shizuku_command(command="", action="status")
    assert status["action"] == "status"
    assert "status_info" in status

    # Exec mock command
    exec_res = execute_shizuku_command(
        command="echo shizuku_test",
        action="exec",
        use_rish=False,
    )
    assert exec_res["action"] == "exec"
    assert "command_executed" in exec_res


def test_device_mutator_service() -> None:
    status = mutate_device_environment(action="status")
    assert status["action"] == "status"
    assert "current_state" in status

    # Dark mode mutation
    mut = mutate_device_environment(action="dark_mode", params={"enabled": True})
    assert mut["action"] == "dark_mode"
    assert any("dark_mode" in m for m in mut["mutations_applied"])

    # Reset all
    reset = mutate_device_environment(action="reset_all")
    assert reset["action"] == "reset_all"


def test_termux_bundle_service() -> None:
    listed = manage_termux_bundle(action="list")
    assert listed["action"] == "list"
    assert "sqlite3" in listed["available_catalog"]
    assert "busybox" in listed["available_catalog"]

    deploy = manage_termux_bundle(action="deploy", binaries=["busybox", "sqlite3"])
    assert deploy["action"] == "deploy"
    assert "busybox" in deploy["binaries_deployed"]


@pytest.mark.asyncio
async def test_phase13m_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # 1. dyn_httptoolkit_vpn_intercept
    vpn_res = await runtime.invoke(
        "dyn_httptoolkit_vpn_intercept",
        {"action": "status"},
        profile="dynamic",
    )
    assert vpn_res.data["action"] == "status"

    # 2. sec_rasp_signature_scan
    scan_res = await runtime.invoke(
        "sec_rasp_signature_scan",
        {"target_path": str(tmp_path)},
        profile="core",
    )
    assert "risk_level" in scan_res.data

    # 3. dyn_rasp_bypass_gen
    bypass_res = await runtime.invoke(
        "dyn_rasp_bypass_gen",
        {"target_package": "com.test.target", "bypasses": ["freerasp", "root"]},
        profile="dynamic",
    )
    assert bypass_res.data["target_package"] == "com.test.target"

    # 4. ui_notification_icon_audit
    notif_res = await runtime.invoke(
        "ui_notification_icon_audit",
        {},
        profile="ui",
    )
    assert "has_default_icon_metadata" in notif_res.data

    # 5. shizuku_privileged_exec
    shizuku_res = await runtime.invoke(
        "shizuku_privileged_exec",
        {"action": "status", "command": ""},
        profile="core",
    )
    assert shizuku_res.data["action"] == "status"

    # 6. dyn_device_env_mutate
    mutate_res = await runtime.invoke(
        "dyn_device_env_mutate",
        {"action": "status"},
        profile="dynamic",
    )
    assert mutate_res.data["action"] == "status"

    # 7. termux_ondevice_binary_bundle
    termux_res = await runtime.invoke(
        "termux_ondevice_binary_bundle",
        {"action": "list"},
        profile="core",
    )
    assert termux_res.data["action"] == "list"


@pytest.mark.asyncio
async def test_phase13m_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 237
    assert data["planned_tools"] >= 237

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] >= 128
    assert profiles["dynamic"] >= 169
    assert profiles["api"] >= 139
    assert profiles["ui"] >= 140
    assert profiles["admin"] >= 19
    assert profiles["full"] >= 237


def test_phase13m_cli_commands(tmp_path: Path) -> None:
    runner = CliRunner()

    # 1. dynamic vpn-intercept
    res = runner.invoke(app, ["dynamic", "vpn-intercept", "--action", "status"])
    assert res.exit_code == 0

    # 2. dynamic rasp-bypass
    out_js = str(tmp_path / "frida_test.js")
    res = runner.invoke(
        app,
        ["dynamic", "rasp-bypass", "--package", "com.test.cli", "--output", out_js],
    )
    assert res.exit_code == 0

    # 3. dynamic device-mutate
    res = runner.invoke(app, ["dynamic", "device-mutate", "--action", "status"])
    assert res.exit_code == 0

    # 4. dynamic shizuku-exec
    res = runner.invoke(app, ["dynamic", "shizuku-exec", "--action", "status"])
    assert res.exit_code == 0

    # 5. dynamic termux-bundle
    res = runner.invoke(app, ["dynamic", "termux-bundle", "--action", "list"])
    assert res.exit_code == 0

    # 6. security rasp-scan
    res = runner.invoke(app, ["security", "rasp-scan", str(tmp_path)])
    assert res.exit_code == 0

    # 7. ui notification-audit
    res = runner.invoke(app, ["ui", "notification-audit"])
    assert res.exit_code == 0
