"""Tests for Phase 18 (v2.4.0): Autonomous UI Reconstruction, Living Canvas & Cross-Platform Re-Engineering.

Covers 20 tools:
- stitch_ui_modernize
- stitch_design_spec_export
- hig_doctor_compliance_audit
- ui_liquid_glass_widget_gen
- ui_bento_grid_summary_render
- reconstruct_clean_arch_lint
- clean_room_spec_extract
- ui_multi_viewport_match
- assets_palette_typography_extract
- game_unity_asset_dump
- game_godot_pck_extract
- db_sqlite_forensic_extract
- docmd_llms_txt_compile
- task_observer_skill_evolve
- dot_coworker_webrtc_session
- ekko_canvas_pipeline_run
- tui_codewhale_session
- receipt_cryptographic_sign
- sodu_cicd_pipeline_run
- gh_actions_build_android
- CLI subcommands under `raa canvas`:
  stitch-modernize, stitch-spec, hig-audit, liquid-glass, bento-grid, clean-lint,
  clean-spec, viewport-match, tokens-extract, unity-dump, godot-extract,
  sqlite-forensics, docmd-compile, skill-evolve, coworker-dot, ekko-pipeline,
  tui-codewhale, receipt-sign, sodu-cicd, gh-actions-gen
- Registry tool total: 300 tools
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime

runner = CliRunner()


@pytest.fixture
def project_id(runtime: Runtime) -> str:
    import asyncio

    res = asyncio.run(
        runtime.invoke(
            "project_create",
            {
                "name": "Phase 18 Canvas Project",
                "description": "Testing UI Reconstruction & Living Canvas",
            },
        )
    )
    return str(res.data["id"])


# 1. Google Stitch UI Re-Engineering
@pytest.mark.asyncio
async def test_stitch_modernization_and_design_spec(runtime: Runtime, project_id: str) -> None:
    # 1. Modernize to Compose
    mod_res = await runtime.invoke(
        "stitch_ui_modernize",
        {
            "project_id": project_id,
            "layout_xml": "<LinearLayout><Button android:text='Click'/></LinearLayout>",
            "target_framework": "jetpack_compose",
        },
    )
    assert mod_res.data["project_id"] == project_id
    assert "@Composable" in mod_res.data["modernized_code"]
    assert mod_res.data["wcag_compliance_score"] >= 95.0

    # 2. Modernize to React Native
    mod_rn = await runtime.invoke(
        "stitch_ui_modernize",
        {
            "project_id": project_id,
            "layout_xml": "<LinearLayout><Button/></LinearLayout>",
            "target_framework": "react_native",
        },
    )
    assert "SafeAreaView" in mod_rn.data["modernized_code"]

    # 3. Export Design Spec
    spec_res = await runtime.invoke(
        "stitch_design_spec_export",
        {"project_id": project_id, "theme_name": "AppTheme"},
    )
    assert spec_res.data["theme_name"] == "AppTheme"
    assert "primary" in spec_res.data["tokens"]["colors"]
    assert len(spec_res.data["component_catalog"]) >= 3


# 2. Apple HIG Auditor & Liquid Glass / Bento Grid
@pytest.mark.asyncio
async def test_hig_liquid_glass_and_bento_grid(runtime: Runtime, project_id: str) -> None:
    # 1. HIG Audit
    hig_res = await runtime.invoke(
        "hig_doctor_compliance_audit",
        {"project_id": project_id, "target_view": "CheckoutView"},
    )
    assert hig_res.data["compliance_passed"] is True
    assert hig_res.data["touch_target_min_pt"] == 44

    # 2. Liquid Glass widget generator
    glass_res = await runtime.invoke(
        "ui_liquid_glass_widget_gen",
        {"widget_name": "BlurCard", "framework": "flutter"},
    )
    assert "Liquid Glass Fragment Shader" in glass_res.data["shader_source"]
    assert glass_res.data["blur_radius"] == 24.0

    # 3. Bento Grid Dashboard Render
    bento_res = await runtime.invoke(
        "ui_bento_grid_summary_render",
        {
            "grid_title": "Security Dashboard",
            "metrics": {"security_score": "A+", "clean_components": 12},
        },
    )
    assert len(bento_res.data["cards"]) >= 3
    assert "<div class='grid grid-cols-3" in bento_res.data["html_presentation"]


# 3. Clean Architecture & Clean-Room Functional Spec
@pytest.mark.asyncio
async def test_clean_arch_lint_and_clean_room_spec(runtime: Runtime) -> None:
    # 1. Clean Architecture Linter
    lint_res = await runtime.invoke(
        "reconstruct_clean_arch_lint",
        {
            "file_path": "com/target/AuthActivity.java",
            "source_code": "public class AuthActivity extends Activity { void login() {} }",
        },
    )
    assert "Domain-Driven Design" in lint_res.data["architecture_style"]
    assert len(lint_res.data["anti_patterns_removed"]) >= 2

    # 2. Clean-Room Spec Extraction
    clean_res = await runtime.invoke(
        "clean_room_spec_extract",
        {
            "module_name": "BiometricAuthManager",
            "decompiled_context": "Disassembly of BiometricPrompt and CryptoObject wrappers",
        },
    )
    assert clean_res.data["zero_proprietary_code_verified"] is True
    assert len(clean_res.data["abstracted_interfaces"]) >= 2


# 4. Multi-Viewport Matcher & Mobile Design Tokens
@pytest.mark.asyncio
async def test_multi_viewport_and_asset_tokens(runtime: Runtime) -> None:
    # 1. Multi-viewport validation
    view_res = await runtime.invoke(
        "ui_multi_viewport_match",
        {"screen_name": "HomeScreen"},
    )
    assert view_res.data["compact_phone_match_pct"] >= 95.0
    assert view_res.data["expanded_tablet_match_pct"] >= 95.0
    assert view_res.data["semantic_ast_parity"] is True

    # 2. Asset tokens extraction
    token_res = await runtime.invoke(
        "assets_palette_typography_extract",
        {"apk_path": "target.apk"},
    )
    assert "primary" in token_res.data["palette"]
    assert len(token_res.data["spacing_grid"]) >= 4
    parsed_json = json.loads(token_res.data["tokens_json"])
    assert "color" in parsed_json


# 5. Game Engine Dumpers & SQLite Forensics
@pytest.mark.asyncio
async def test_game_asset_dump_and_sqlite_forensics(runtime: Runtime) -> None:
    # 1. Unity dump
    unity_res = await runtime.invoke(
        "game_unity_asset_dump",
        {"package_name": "com.game.unitytarget"},
    )
    assert unity_res.data["engine"] == "unity"
    assert len(unity_res.data["extracted_assets"]) >= 2
    assert len(unity_res.data["scripts_recovered"]) >= 2

    # 2. Godot dump
    godot_res = await runtime.invoke(
        "game_godot_pck_extract",
        {"package_name": "com.game.godottarget"},
    )
    assert godot_res.data["engine"] == "godot"
    assert len(godot_res.data["extracted_assets"]) >= 1

    # 3. SQLite forensics
    sql_res = await runtime.invoke(
        "db_sqlite_forensic_extract",
        {
            "database_path": "/data/data/com.app/databases/app.db",
            "encryption_key": "secret_key_hex",
        },
    )
    assert len(sql_res.data["tables_recovered"]) >= 3
    assert sql_res.data["decrypted_successfully"] is True


# 6. docmd llms.txt & Task Observer Evolution
@pytest.mark.asyncio
async def test_docmd_compiler_and_skill_evolution(runtime: Runtime, project_id: str) -> None:
    # 1. docmd compiler
    doc_res = await runtime.invoke(
        "docmd_llms_txt_compile",
        {"project_id": project_id, "title": "Target Mobile App Portal"},
        profile="admin",
    )
    assert "llms.txt" in doc_res.data["llms_txt_content"]
    assert doc_res.data["tokens_count"] > 0

    # 2. Task observer skill self-evolution
    evolve_res = await runtime.invoke(
        "task_observer_skill_evolve",
        {
            "skill_name": "raa-apk-triage",
            "feedback_history": ["Always check 16KB alignment", "Use Kuna decompiler"],
        },
        profile="admin",
    )
    assert "proposed_prompt_diff" in evolve_res.data
    assert evolve_res.data["evolution_confidence"] >= 0.9


# 7. Dot Reversing Coworker & Visual Ekko Pipeline
@pytest.mark.asyncio
async def test_dot_coworker_and_ekko_canvas(runtime: Runtime) -> None:
    # 1. Coworker session
    dot_res = await runtime.invoke(
        "dot_coworker_webrtc_session",
        {"action": "connect"},
        profile="dynamic",
    )
    assert dot_res.data["webrtc_channel_status"] == "connected"
    assert dot_res.data["assistant_persona"] == "RAA Dot"
    assert len(dot_res.data["suggested_actions"]) >= 1

    # 2. Ekko canvas pipeline run
    ekko_res = await runtime.invoke(
        "ekko_canvas_pipeline_run",
        {"graph_name": "FullReverseAndModernize"},
    )
    assert ekko_res.data["pipeline_status"] == "succeeded"
    assert len(ekko_res.data["nodes_executed"]) >= 3


# 8. Codewhale TUI, Cryptographic Receipts & Sodu CI/CD
@pytest.mark.asyncio
async def test_codewhale_receipts_sodu_and_gh_actions(runtime: Runtime) -> None:
    # 1. Codewhale TUI
    tui_res = await runtime.invoke(
        "tui_codewhale_session",
        {"action": "launch"},
    )
    assert tui_res.data["tui_status"] == "active"
    assert len(tui_res.data["monitored_subagents"]) >= 2

    # 2. Cryptographic Receipt Signing
    receipt_res = await runtime.invoke(
        "receipt_cryptographic_sign",
        {
            "tool_name": "apk_rebuild",
            "input_data": "{'project_id': 'p1'}",
            "output_data": "{'signed_apk': 'app.apk'}",
        },
        profile="admin",
    )
    assert receipt_res.data["receipt_id"].startswith("rcpt_")
    assert receipt_res.data["verified"] is True
    assert len(receipt_res.data["hmac_sha256_signature"]) == 64

    # 3. Sodu CI/CD Pipeline
    sodu_res = await runtime.invoke(
        "sodu_cicd_pipeline_run",
        {
            "target_apk": "sample.apk",
            "patch_recipe": "patch_ssl_pinning",
        },
    )
    assert sodu_res.data["build_success"] is True
    assert len(sodu_res.data["stages_completed"]) >= 4

    # 4. GitHub Actions Builder Workflow
    gh_res = await runtime.invoke(
        "gh_actions_build_android",
        {"app_name": "SampleBankingApp"},
    )
    assert "name: RAA Automated Rebuild & Verify" in gh_res.data["workflow_yaml"]
    assert gh_res.data["signing_v2v3_configured"] is True


# 9. Profile Tool Registry Invariants for Phase 18
def test_phase18_profile_target_counts(runtime: Runtime) -> None:
    assert runtime.registry.count() >= 300
    counts = {
        p: len(runtime.registry.for_profile(p))
        for p in ("minimal", "core", "full", "dynamic", "api", "ui", "admin", "swarm")
    }
    assert counts["minimal"] == 12
    assert counts["core"] >= 171
    assert counts["dynamic"] >= 207
    assert counts["api"] >= 171
    assert counts["ui"] >= 171
    assert counts["admin"] >= 31
    assert counts["swarm"] >= 141
    assert counts["full"] >= 300


# 10. CLI Integration Tests for raa canvas
def test_cli_canvas_subcommands_e2e(tmp_path: Path) -> None:
    ws = str(tmp_path)

    # 1. Create project
    proj_res = runner.invoke(
        app, ["--workspace", ws, "--json", "project", "create", "CanvasTestProj"]
    )
    assert proj_res.exit_code == 0
    p_id = json.loads(proj_res.stdout)["data"]["id"]

    # 2. stitch-modernize
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "canvas",
            "stitch-modernize",
            "-p",
            p_id,
            "-f",
            "jetpack_compose",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "@Composable" in data["data"]["modernized_code"]

    # 3. stitch-spec
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "stitch-spec", "-p", p_id, "-t", "BentoTheme"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["theme_name"] == "BentoTheme"

    # 4. hig-audit
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "hig-audit", "-p", p_id, "-v", "SettingsView"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["compliance_passed"] is True

    # 5. liquid-glass
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "liquid-glass", "-n", "Card", "-f", "swiftui"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "ultraThinMaterial" in data["data"]["shader_source"]

    # 6. bento-grid
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "bento-grid", "-t", "Overview"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert len(data["data"]["cards"]) >= 2

    # 7. clean-lint
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "clean-lint", "-f", "Domain.kt"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "Clean Architecture" in data["data"]["architecture_style"]

    # 8. clean-spec
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "clean-spec", "-m", "BillingModule"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["zero_proprietary_code_verified"] is True

    # 9. viewport-match
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "viewport-match", "-s", "Profile"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["semantic_ast_parity"] is True

    # 10. tokens-extract
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "tokens-extract", "--apk", "app.apk"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "primary" in data["data"]["palette"]

    # 11. unity-dump
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "unity-dump", "-p", "com.game"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["engine"] == "unity"

    # 12. godot-extract
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "godot-extract", "-p", "com.game"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["engine"] == "godot"

    # 13. sqlite-forensics
    res = runner.invoke(
        app,
        ["--workspace", ws, "--json", "canvas", "sqlite-forensics", "-d", "app.db", "-k", "key123"],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["decrypted_successfully"] is True

    # 14. docmd-compile
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "docmd-compile", "-p", p_id, "-t", "Portal"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "llms.txt" in data["data"]["llms_txt_content"]

    # 15. skill-evolve
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "skill-evolve", "-s", "apk-triage"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "proposed_prompt_diff" in data["data"]

    # 16. coworker-dot
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "coworker-dot", "-a", "connect"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["webrtc_channel_status"] == "connected"

    # 17. ekko-pipeline
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "ekko-pipeline", "-g", "ReversePipeline"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["pipeline_status"] == "succeeded"

    # 18. tui-codewhale
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "canvas", "tui-codewhale", "-a", "launch"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["tui_status"] == "active"

    # 19. receipt-sign
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "canvas",
            "receipt-sign",
            "-t",
            "decompile",
            "-i",
            "in",
            "-o",
            "out",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["verified"] is True

    # 20. sodu-cicd
    res = runner.invoke(
        app,
        ["--workspace", ws, "--json", "canvas", "sodu-cicd", "--apk", "app.apk", "-r", "recipe"],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["build_success"] is True

    # 21. gh-actions-gen
    res = runner.invoke(app, ["--workspace", ws, "--json", "canvas", "gh-actions-gen", "-n", "App"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["signing_v2v3_configured"] is True
