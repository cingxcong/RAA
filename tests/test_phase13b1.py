"""Tests for Phase 13B-1 (v1.3.5): Android Asset Studio, Adaptive Icon Suite & Play Store Banner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.asset_studio import (
    generate_adaptive_icon_suite,
    generate_notification_silhouette,
    generate_play_store_banner,
)

runner = CliRunner()


def _invoke_cli(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["--workspace", str(tmp_path / "workspace"), *args],
    )


# =====================================================================
# Unit Tests: Adaptive Icon Suite Generator
# =====================================================================


def test_adaptive_icon_suite_generation(tmp_path: Path) -> None:
    res = generate_adaptive_icon_suite(
        name="ic_app_launcher",
        background_color="#FF5722",
        output_dir=tmp_path / "assets",
    )

    assert res["icon_name"] == "ic_app_launcher"
    assert res["background_color"] == "#FF5722"
    assert res["has_monochrome_layer"] is True
    assert res["has_round_variant"] is True
    assert len(res["generated_files"]) == 5
    assert len(res["density_mipmap_specs"]) >= 5

    # Check files written to disk
    adaptive_xml = tmp_path / "assets" / "res" / "mipmap-anydpi-v26" / "ic_app_launcher.xml"
    assert adaptive_xml.exists()
    content = adaptive_xml.read_text(encoding="utf-8")
    assert "<adaptive-icon" in content
    assert "ic_app_launcher_monochrome" in content

    fg_xml = tmp_path / "assets" / "res" / "drawable" / "ic_app_launcher_foreground.xml"
    assert fg_xml.exists()
    assert "<vector" in fg_xml.read_text(encoding="utf-8")


# =====================================================================
# Unit Tests: Google Play Store Feature Graphic Banner
# =====================================================================


def test_play_store_banner_generation(tmp_path: Path) -> None:
    banner_file = tmp_path / "feature_graphic.svg"
    res = generate_play_store_banner(
        app_title="VaultGuard Pro",
        tagline="Zero-Knowledge Password Manager",
        primary_color="#1E3A8A",
        secondary_color="#3B82F6",
        accent_color="#10B981",
        output_path=banner_file,
    )

    assert res["width_px"] == 1024
    assert res["height_px"] == 500
    assert res["dimensions"] == "1024x500"
    assert res["google_play_compliant"] is True
    assert res["has_transparency"] is False
    assert res["safe_zone"]["safe_width_px"] == 864
    assert res["safe_zone"]["safe_height_px"] == 380

    assert banner_file.exists()
    svg_text = banner_file.read_text(encoding="utf-8")
    assert 'width="1024" height="500"' in svg_text
    assert "VaultGuard Pro" in svg_text
    assert "Zero-Knowledge Password Manager" in svg_text


# =====================================================================
# Unit Tests: Notification Silhouette & Status Bar Asset Studio
# =====================================================================


def test_notification_silhouette_generation(tmp_path: Path) -> None:
    res = generate_notification_silhouette(
        name="ic_stat_download",
        output_dir=tmp_path / "res_out",
    )

    assert res["icon_name"] == "ic_stat_download"
    assert res["is_monochrome_silhouette"] is True
    assert res["has_alpha_channel"] is True
    assert res["viewport"] == "24x24dp"
    assert res["android_notification_compliant"] is True
    assert len(res["density_specs"]) >= 5

    out_xml = tmp_path / "res_out" / "res" / "drawable" / "ic_stat_download.xml"
    assert out_xml.exists()
    xml_text = out_xml.read_text(encoding="utf-8")
    assert 'android:width="24dp"' in xml_text
    assert 'android:tint="#FFFFFFFF"' in xml_text


# =====================================================================
# Integration Tests: Runtime Invocations & Capabilities Check
# =====================================================================


@pytest.mark.asyncio
async def test_phase13b1_runtime_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # 1. Capabilities check: >= 173 tools
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 173
    assert caps.data["planned_tools"] >= 173
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 107
    assert caps.data["profiles"]["dynamic"] >= 124
    assert caps.data["profiles"]["api"] >= 126
    assert caps.data["profiles"]["ui"] >= 127
    assert caps.data["profiles"]["full"] >= 173

    proj = runtime.projects.create(name="Phase 13B-1 Project", description="Testing Phase 13B-1")
    pid = proj.id

    # 2. ui_icon_generate
    icon_res = await runtime.invoke(
        "ui_icon_generate",
        {"project_id": pid, "icon_name": "ic_crypto", "background_color": "#000000"},
        profile="ui",
    )
    assert icon_res.data["icon_name"] == "ic_crypto"
    assert icon_res.data["has_monochrome_layer"] is True

    # 3. ui_banner_generate
    banner_res = await runtime.invoke(
        "ui_banner_generate",
        {"project_id": pid, "app_title": "FinTech App", "tagline": "Banking Redefined"},
        profile="ui",
    )
    assert banner_res.data["dimensions"] == "1024x500"
    assert banner_res.data["google_play_compliant"] is True

    # 4. ui_notification_icon_generate
    notif_res = await runtime.invoke(
        "ui_notification_icon_generate",
        {"project_id": pid, "name": "ic_stat_sync"},
        profile="ui",
    )
    assert notif_res.data["android_notification_compliant"] is True


# =====================================================================
# CLI Integration Tests
# =====================================================================


def test_phase13b1_cli_commands(tmp_path: Path) -> None:
    # 1. ui generate-icon
    res_icon = _invoke_cli(
        tmp_path,
        "--json",
        "ui",
        "generate-icon",
        "--name",
        "ic_super_app",
        "--bg",
        "#123456",
    )
    assert res_icon.exit_code == 0
    data_icon = json.loads(res_icon.stdout)
    assert data_icon["data"]["icon_name"] == "ic_super_app"
    assert data_icon["data"]["has_monochrome_layer"] is True

    # 2. ui generate-banner
    res_banner = _invoke_cli(
        tmp_path,
        "--json",
        "ui",
        "generate-banner",
        "SuperApp",
        "--tagline",
        "All-in-One Utility",
        "--primary",
        "#212121",
    )
    assert res_banner.exit_code == 0
    data_banner = json.loads(res_banner.stdout)
    assert data_banner["data"]["dimensions"] == "1024x500"

    # 3. ui generate-notification-icon
    res_notif = _invoke_cli(
        tmp_path,
        "--json",
        "ui",
        "generate-notification-icon",
        "--name",
        "ic_stat_message",
    )
    assert res_notif.exit_code == 0
    data_notif = json.loads(res_notif.stdout)
    assert data_notif["data"]["android_notification_compliant"] is True
