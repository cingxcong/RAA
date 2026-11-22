"""Tests for Phase 13K: Architecture Diagrams, Decompiled Code Review & Skip Swift.

Covers:
- Track 45 ( cathrynlavery/diagram-design ): Interactive SVG+HTML Architecture & Taint Diagram
- Track 46 ( alibaba/open-code-review ): Hybrid AST & Semantic Decompiled Source Code Reviewer
- Track 47 ( skiptools/skills ): Skip Swift-to-Kotlin Transpiled Framework Reverser
- Profile target counts:
  minimal: 12, core: 124, dynamic: 162, api: 139, ui: 139, admin: 19, full: 225
- CLI subcommands: security arch-diagram, security code-review, framework skip-inspect
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.framework_adapters.skip_swift import inspect_skip_swift_framework
from raa.services.security.arch_diagram import render_architecture_diagram
from raa.services.security.code_reviewer import review_decompiled_source_code


def test_arch_diagram_service(tmp_path: Path) -> None:
    html_out = tmp_path / "arch_diagram.html"
    res = render_architecture_diagram(
        project_id="proj-demo-123",
        title="Custom Architecture Test",
        theme="light",
        include_taint_flows=True,
        output_path=str(html_out),
    )
    assert res["title"] == "Custom Architecture Test"
    assert res["theme"] == "light"
    assert res["total_nodes"] > 0
    assert res["taint_flows_count"] > 0
    assert res["output_path"] == str(html_out)
    assert html_out.is_file()
    assert "Custom Architecture Test" in html_out.read_text(encoding="utf-8")


def test_code_reviewer_service(tmp_path: Path) -> None:
    # Test with simulated findings
    res = review_decompiled_source_code(ruleset="all", severity_threshold="low")
    assert res["total_findings"] >= 3
    assert res["severity_counts"]["critical"] > 0
    assert res["severity_counts"]["high"] > 0

    # Test with an actual source file on disk
    src_file = tmp_path / "InsecureCrypto.java"
    src_file.write_text(
        "public class InsecureCrypto {\n"
        "    public void init() {\n"
        '        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    res_disk = review_decompiled_source_code(file_paths=[str(src_file)])
    assert res_disk["total_findings"] >= 1
    assert any(f["rule_id"] == "SEC-CRYPTO-ECB" for f in res_disk["findings"])


def test_skip_swift_service() -> None:
    res = inspect_skip_swift_framework(deobfuscate_models=True)
    assert res["is_skip_app"] is True
    assert res["skip_transpiler_detected"] is True
    assert res["skip_runtime_version"] == "1.2.4"
    assert res["reconstructed_swift_models_count"] > 0
    assert res["swiftui_views_count"] > 0
    assert res["bridge_bindings_count"] > 0


@pytest.mark.asyncio
async def test_phase13k_tool_invocations(runtime: Runtime, tmp_path: Path) -> None:
    # 1. sec_arch_diagram_render (admin profile)
    out_file = tmp_path / "diagram.html"
    r1 = await runtime.invoke(
        "sec_arch_diagram_render",
        {"title": "Runtime Diagram", "output_path": str(out_file)},
        profile="admin",
    )
    assert r1.data["total_nodes"] > 0
    assert out_file.is_file()

    # 2. sec_source_code_review (core profile)
    r2 = await runtime.invoke(
        "sec_source_code_review",
        {"ruleset": "all", "severity_threshold": "low"},
        profile="core",
    )
    assert r2.data["total_findings"] > 0
    assert "findings" in r2.data

    # 3. skip_swift_framework_inspect (core profile)
    r3 = await runtime.invoke(
        "skip_swift_framework_inspect",
        {"deobfuscate_models": True},
        profile="core",
    )
    assert r3.data["is_skip_app"] is True
    assert r3.data["reconstructed_swift_models_count"] > 0


@pytest.mark.asyncio
async def test_phase13k_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 225
    assert data["planned_tools"] >= 225

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] >= 124
    assert profiles["dynamic"] >= 162
    assert profiles["api"] == 139
    assert profiles["ui"] >= 139
    assert profiles["admin"] >= 19
    assert profiles["full"] >= 225


def test_phase13k_cli_commands(tmp_path: Path) -> None:
    runner = CliRunner()

    def run_cli(*args: str) -> dict:
        cmd = ["--workspace", str(tmp_path), "--json", *args]
        res = runner.invoke(app, cmd)
        assert res.exit_code == 0, f"Command failed: {res.stdout}"
        return json.loads(res.stdout)

    # 1. security arch-diagram
    diag_file = tmp_path / "cli_diag.html"
    r1 = run_cli("security", "arch-diagram", "--title", "CLI Diagram", "--output", str(diag_file))
    assert r1["data"]["total_nodes"] > 0
    assert diag_file.is_file()

    # 2. security code-review
    r2 = run_cli("security", "code-review", "--ruleset", "all")
    assert r2["data"]["total_findings"] > 0

    # 3. framework skip-inspect
    r3 = run_cli("framework", "skip-inspect")
    assert r3["data"]["is_skip_app"] is True
    assert r3["data"]["reconstructed_swift_models_count"] > 0
