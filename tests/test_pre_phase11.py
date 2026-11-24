"""Pre-Phase 11 comprehensive test suite.

Validates the 12 new MCP tools and CLI subcommands across:
1. Hybrid UI Reconstruction & Redesign Engine
2. Advanced API Reverse Engineering Studio
3. Deep Framework Reversing Adapters (Flutter & Unity)
4. Dynamic Instrumentation & Frida Gadget
5. Specialized AI Agents & Coverage Tracker
6. Reusable Skills Catalog
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.policy.scopes import ALL_SCOPES
from raa.runtime import Runtime
from raa.services.skills import SkillService

runner = CliRunner()


def _make_dummy_apk(path: Path) -> Path:
    import zipfile

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
        zf.writestr("classes.dex", b"dex\n035\x00dummy")
        zf.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF\x02\x01\x01\x00")
        dart_data = (
            b"\x7fELF\x02\x01\x01\x00DartSnapshot\x00"
            b"https://api.example.com/v1/auth\x00SECRET_TOKEN_12345\x00"
        )
        zf.writestr("lib/arm64-v8a/libapp.so", dart_data)
        meta_data = b"\xaf\x1b\xb1\xfa\x1d\x00\x00\x00" + b"\x00" * 256
        zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", meta_data)
    return path


@pytest.mark.asyncio
async def test_ui_hybrid_engine_tools(runtime: Runtime, tmp_path: Path) -> None:
    # 1. Project creation
    proj_res = await runtime.invoke(
        "project_create",
        {"name": "UI Engine Test", "scopes": list(ALL_SCOPES)},
        profile="ui",
    )
    project_id = proj_res.data["id"]

    # 2. ui_runtime_capture
    cap_res = await runtime.invoke(
        "ui_runtime_capture",
        {"project_id": project_id, "screen_name": "LoginScreen"},
        profile="ui",
    )
    assert cap_res.data["activity_name"] == "LoginScreen"
    screen_id = cap_res.data["screen_id"]
    assert "bounds_matrix" in cap_res.data
    assert "screenshot_path" in cap_res.data

    # 3. ui_webview_inspect
    web_res = await runtime.invoke(
        "ui_webview_inspect",
        {"project_id": project_id, "cdp_port": 9222},
        profile="ui",
    )
    assert web_res.data["webview_count"] >= 1
    assert "dom_tree" in web_res.data
    assert "tag" in web_res.data["dom_tree"]

    # 4. ui_redesign_generate
    redesign_res = await runtime.invoke(
        "ui_redesign_generate",
        {
            "project_id": project_id,
            "screen_id": screen_id,
            "target_framework": "compose",
        },
        profile="ui",
    )
    assert redesign_res.data["target_framework"] == "compose"
    assert 8 in redesign_res.data["design_tokens"]["spacing_grid"]
    assert "colors" in redesign_res.data["design_tokens"]
    assert "Composable" in redesign_res.data["code"] or "fun " in redesign_res.data["code"]

    # 5. ui_visual_compare
    compare_res = await runtime.invoke(
        "ui_visual_compare",
        {
            "project_id": project_id,
            "original_screen_id": screen_id,
            "redesigned_screen_id": screen_id,
        },
        profile="ui",
    )
    assert compare_res.data["similarity_score"] >= 0.8
    assert "diff_image_path" in compare_res.data
    assert "layout_conformance" in compare_res.data


@pytest.mark.asyncio
async def test_api_reverse_engineering_studio_tools(runtime: Runtime) -> None:
    proj_res = await runtime.invoke(
        "project_create",
        {"name": "API Studio Test", "scopes": list(ALL_SCOPES)},
        profile="api",
    )
    project_id = proj_res.data["id"]

    # 1. api_synthesize_spec
    spec_res = await runtime.invoke(
        "api_synthesize_spec",
        {"project_id": project_id, "title": "Synthesized Test API", "version": "2.0.0"},
        profile="api",
    )
    assert spec_res.data["openapi_version"] == "3.1.0"
    assert spec_res.data["total_endpoints"] > 0
    assert "/api/v1/auth/login" in spec_res.data["spec_dict"]["paths"]

    # 2. api_export_postman
    postman_res = await runtime.invoke(
        "api_export_postman",
        {"project_id": project_id, "collection_name": "Test Collection"},
        profile="api",
    )
    assert postman_res.data["request_count"] > 0
    col_dict = json.loads(postman_res.data["collection_json"])
    assert col_dict["info"]["name"] == "Test Collection"
    assert len(col_dict["item"]) > 0


@pytest.mark.asyncio
async def test_framework_reversing_adapters_tools(runtime: Runtime, tmp_path: Path) -> None:
    proj_res = await runtime.invoke(
        "project_create",
        {"name": "Framework Test", "scopes": list(ALL_SCOPES)},
        profile="full",
    )
    project_id = proj_res.data["id"]

    apk_path = _make_dummy_apk(tmp_path / "app.apk")
    ingest_res = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(apk_path)},
        profile="full",
    )
    artifact_id = ingest_res.data["id"]

    # 1. flutter_patch_tls
    patch_res = await runtime.invoke(
        "flutter_patch_tls",
        {"project_id": project_id, "artifact_id": artifact_id},
        profile="full",
    )
    assert patch_res.data["success"] is True
    assert "patched_artifact_id" in patch_res.data
    assert len(patch_res.data["patch_offsets"]) > 0

    # 2. flutter_dump_strings
    strings_res = await runtime.invoke(
        "flutter_dump_strings",
        {"project_id": project_id, "artifact_id": artifact_id, "min_length": 6},
        profile="full",
    )
    assert strings_res.data["total_strings"] > 0
    assert len(strings_res.data["api_endpoints"]) > 0
    assert any(s.find("https://") >= 0 for s in strings_res.data["api_endpoints"])

    # 3. unity_dump_metadata
    unity_res = await runtime.invoke(
        "unity_dump_metadata",
        {"project_id": project_id, "artifact_id": artifact_id},
        profile="full",
    )
    assert "unity_version" in unity_res.data
    assert unity_res.data["total_types"] > 0
    assert len(unity_res.data["string_literals"]) > 0


@pytest.mark.asyncio
async def test_dynamic_instrumentation_tools(runtime: Runtime, tmp_path: Path) -> None:
    proj_res = await runtime.invoke(
        "project_create",
        {"name": "Dynamic Test", "scopes": list(ALL_SCOPES)},
        profile="dynamic",
    )
    project_id = proj_res.data["id"]

    apk_path = _make_dummy_apk(tmp_path / "dynamic_app.apk")
    ingest_res = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(apk_path)},
        profile="dynamic",
    )
    artifact_id = ingest_res.data["id"]

    # 1. dynamic_inject_gadget
    gadget_res = await runtime.invoke(
        "dynamic_inject_gadget",
        {"project_id": project_id, "artifact_id": artifact_id, "target_arch": "arm64-v8a"},
        profile="dynamic",
    )
    assert gadget_res.data["success"] is True
    assert gadget_res.data["target_arch"] == "arm64-v8a"
    assert "patched_artifact_id" in gadget_res.data

    # 2. dynamic_dump_storage
    storage_res = await runtime.invoke(
        "dynamic_dump_storage",
        {"project_id": project_id, "target_type": "all"},
        profile="dynamic",
    )
    assert len(storage_res.data["database_files"]) > 0
    assert "app_preferences.xml" in storage_res.data["shared_preferences"]
    assert "auth_token" in storage_res.data["sensitive_keys_found"]


@pytest.mark.asyncio
async def test_coverage_tracker_and_admin_tool(runtime: Runtime) -> None:
    proj_res = await runtime.invoke(
        "project_create",
        {"name": "Coverage Test", "scopes": list(ALL_SCOPES)},
        profile="core",
    )
    project_id = proj_res.data["id"]

    cov_res = await runtime.invoke(
        "agent_coverage_get",
        {"project_id": project_id},
        profile="admin",
    )
    data = cov_res.data
    assert data["project_id"] == project_id
    assert "overall_coverage_pct" in data
    assert "dimensions" in data
    assert "activities" in data["dimensions"]
    assert "api_endpoints" in data["dimensions"]
    assert "native_binaries" in data["dimensions"]
    assert "ui_reconstruction" in data["dimensions"]
    assert isinstance(data["unresolved_gaps"], list)


def test_reusable_skills_catalog() -> None:
    service = SkillService()
    skills = {s.id: s for s in service.discover()}

    expected_skills = [
        "raa-apk-triage",
        "raa-source-reconstruct",
        "raa-ui-redesign",
        "raa-api-discovery",
        "raa-flutter-reversing",
        "raa-native-reversing",
        "raa-security-audit",
        "raa-controlled-rebuild",
    ]
    for skill_id in expected_skills:
        assert skill_id in skills, f"Skill {skill_id} must be discovered"
        skill = skills[skill_id]
        assert len(skill.tools) > 0, f"Skill {skill_id} must declare tools"
        assert len(skill.description) > 10


def test_pre_phase11_cli_subcommands(tmp_path: Path) -> None:
    # 1. Project create via CLI with required dynamic/patch scopes
    proj_out = runner.invoke(
        app,
        [
            "--json",
            "project",
            "create",
            "CLI Test",
            "--scope",
            "project.read",
            "--scope",
            "project.write",
            "--scope",
            "static.read",
            "--scope",
            "export.write",
            "--scope",
            "dynamic.device",
            "--scope",
            "android.patch",
        ],
    )
    assert proj_out.exit_code == 0
    proj_payload = json.loads(proj_out.stdout)
    project_id = proj_payload["data"]["id"]

    # 2. UI CLI commands
    cap_out = runner.invoke(
        app,
        ["--json", "ui", "capture", project_id, "--screen-name", "CliScreen"],
    )
    assert cap_out.exit_code == 0
    cap_data = json.loads(cap_out.stdout)["data"]
    screen_id = cap_data["screen_id"]

    redesign_out = runner.invoke(
        app,
        ["--json", "ui", "redesign", project_id, screen_id, "-f", "compose"],
    )
    assert redesign_out.exit_code == 0
    redesign_data = json.loads(redesign_out.stdout)["data"]
    redesign_screen_id = redesign_data["screen_id"]

    compare_out = runner.invoke(
        app,
        ["--json", "ui", "visual-compare", project_id, screen_id, redesign_screen_id],
    )
    assert compare_out.exit_code == 0

    # 3. API CLI commands
    synth_out = runner.invoke(
        app,
        ["--json", "api", "synthesize", project_id, "--title", "CLI Synth API"],
    )
    assert synth_out.exit_code == 0

    postman_out = runner.invoke(
        app,
        ["--json", "api", "export-postman", project_id, "--name", "CLI Postman"],
    )
    assert postman_out.exit_code == 0

    # 4. Dynamic CLI commands
    storage_out = runner.invoke(
        app,
        ["--json", "dynamic", "dump-storage", project_id, "--type", "all"],
    )
    assert storage_out.exit_code == 0

    # 5. Admin Coverage CLI command
    cov_out = runner.invoke(
        app,
        ["--json", "admin", "coverage", project_id],
    )
    assert cov_out.exit_code == 0
    cov_data = json.loads(cov_out.stdout)["data"]
    assert cov_data["project_id"] == project_id
