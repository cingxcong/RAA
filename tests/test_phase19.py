"""Tests for Phase 19 (v2.5.0): Enterprise MCP & Multi-Harness CLI Ecosystem Integration.

Covers 12 tools:
- mcp_postman_collection_run
- mcp_postman_test_assert
- mcp_github_pr_manage
- mcp_playwright_webview_test
- mcp_apify_store_scrape
- cli_harness_dispatch
- omnigent_meta_policy_enforce
- spring_ai_nacos_register
- n8n_workflow_bridge_sync
- engine_wasm_plugin_sandbox
- binary_byte_search_entropy
- forensic_mutation_digest_guard
- CLI subcommands under `raa enterprise`:
  postman-run, postman-assert, github-pr, playwright-webview, apify-scrape,
  cli-dispatch, omnigent-enforce, nacos-register, n8n-sync, wasm-sandbox,
  simd-entropy, mutation-guard
- Total tool registry count: 312
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime

runner = CliRunner()


# 1. Postman MCP Integration
@pytest.mark.asyncio
async def test_postman_mcp_collection_and_assertions(runtime: Runtime) -> None:
    # 1. Postman collection runner
    run_res = await runtime.invoke(
        "mcp_postman_collection_run",
        {
            "collection_path": "api/collections/auth_suite.json",
            "environment_vars": {"BASE_URL": "https://api.internal.target"},
        },
    )
    assert run_res.data["assertions_passed"] >= 3
    assert run_res.data["latency_average_ms"] > 0
    assert len(run_res.data["test_report"]) >= 2

    # 2. Living contract assertion
    assert_res = await runtime.invoke(
        "mcp_postman_test_assert",
        {
            "endpoint_url": "https://api.internal.target/v2/auth",
            "expected_status": 200,
        },
    )
    assert assert_res.data["status_code"] == 200
    assert assert_res.data["schema_valid"] is True
    assert assert_res.data["headers_verified"] is True


# 2. GitHub, Playwright & Apify MCP Mesh
@pytest.mark.asyncio
async def test_github_playwright_and_apify_mcp(runtime: Runtime) -> None:
    # 1. GitHub PR Manager
    pr_res = await runtime.invoke(
        "mcp_github_pr_manage",
        {
            "repo": "corp/target-mobile-app",
            "title": "Clean-Room Rebuild Parity PR",
            "head_branch": "feature/rebuilt-compose-app",
            "base_branch": "main",
        },
        profile="admin",
    )
    assert pr_res.data["pr_number"] == 42
    assert "github.com" in pr_res.data["pr_url"]
    assert pr_res.data["commits_pushed"] >= 1

    # 2. Playwright in-app WebView & OAuth interception
    pw_res = await runtime.invoke(
        "mcp_playwright_webview_test",
        {
            "target_url": "https://login.target-bank.com/oauth/authorize",
            "capture_oauth": True,
        },
        profile="dynamic",
    )
    assert pw_res.data["success"] is True
    assert len(pw_res.data["oauth_tokens_captured"]) >= 1
    assert pw_res.data["oauth_tokens_captured"][0]["token_type"] == "Bearer"

    # 3. Apify App Store scraper
    apify_res = await runtime.invoke(
        "mcp_apify_store_scrape",
        {
            "store": "google_play",
            "app_id": "com.target.mobile.banking",
        },
    )
    assert apify_res.data["store"] == "google_play"
    assert "security@" in apify_res.data["developer_email"]
    assert len(apify_res.data["version_history"]) >= 2


# 3. Universal 7-CLI Gateway Dispatcher
@pytest.mark.asyncio
async def test_cli_harness_dispatcher(runtime: Runtime) -> None:
    for harness in (
        "claude_code",
        "codex",
        "gemini_cli",
        "antigravity",
        "deepseek_cli",
        "minimax_cli",
        "grok_build",
    ):
        dispatch_res = await runtime.invoke(
            "cli_harness_dispatch",
            {
                "harness": harness,
                "task_instruction": "Triage APK manifest components and flag exported services",
            },
        )
        assert dispatch_res.data["harness"] == harness
        assert dispatch_res.data["exit_code"] == 0
        assert dispatch_res.data["normalized_receipt"]["execution_mode"] == "sandboxed_meta_adapter"


# 4. Omnigent Meta-Policy & Spring AI Nacos
@pytest.mark.asyncio
async def test_omnigent_and_spring_ai_nacos(runtime: Runtime) -> None:
    # 1. Omnigent policy enforcement
    omni_res = await runtime.invoke(
        "omnigent_meta_policy_enforce",
        {
            "agent_id": "agent_codex_external_01",
            "requested_action": "invoke_retdec_native_decompile",
        },
        profile="admin",
    )
    assert omni_res.data["allowed"] is True
    assert omni_res.data["workspace_boundary_enforced"] is True
    assert omni_res.data["budget_remaining_usd"] > 0

    # 2. Spring AI Nacos registration
    nacos_res = await runtime.invoke(
        "spring_ai_nacos_register",
        {
            "service_name": "raa-enterprise-mesh",
            "tools_count": 312,
        },
        profile="admin",
    )
    assert nacos_res.data["cluster_status"] == "UP"
    assert nacos_res.data["registered_tools_count"] == 312


# 5. n8n Workflow Bridge & WASM Sandbox
@pytest.mark.asyncio
async def test_n8n_bridge_and_wasm_sandbox(runtime: Runtime) -> None:
    # 1. n8n workflow sync
    n8n_res = await runtime.invoke(
        "n8n_workflow_bridge_sync",
        {
            "workflow_name": "Automated_Security_Triage",
            "trigger_event": "critical_hardcoded_key_detected",
        },
        profile="admin",
    )
    assert n8n_res.data["workflow_id"].startswith("n8n_")
    assert "n8n-nodes-base" in n8n_res.data["n8nac_definition_yaml"]

    # 2. WASM sandbox runtime
    wasm_res = await runtime.invoke(
        "engine_wasm_plugin_sandbox",
        {
            "plugin_name": "entropy_scanner.wasm",
            "plugin_bytes_hex": "0061736d01000000",
        },
        profile="admin",
    )
    assert wasm_res.data["sandbox_egress_blocked"] is True
    assert wasm_res.data["fuel_consumed"] > 0
    assert wasm_res.data["output_data"]["status"] == "clean"


# 6. SIMD Entropy Analysis & Mutation Guardrail
@pytest.mark.asyncio
async def test_simd_entropy_and_mutation_guard(runtime: Runtime) -> None:
    # 1. SIMD byte entropy scan
    simd_res = await runtime.invoke(
        "binary_byte_search_entropy",
        {"target_binary": "libnative-crypto.so"},
    )
    assert simd_res.data["shannon_entropy"] >= 7.0
    assert simd_res.data["packed_probability"] >= 0.9
    assert len(simd_res.data["simd_matches"]) >= 1

    # 2. Forensic mutation guardrail
    pre_hex = "48656c6c6f20576f726c64"  # Hello World
    post_hex = "48656c6c6f205061746368"  # Hello Patch
    guard_res = await runtime.invoke(
        "forensic_mutation_digest_guard",
        {
            "file_path": "libnative.so",
            "pre_data_hex": pre_hex,
            "post_data_hex": post_hex,
        },
        profile="admin",
    )
    assert guard_res.data["pre_sha256"] != guard_res.data["post_sha256"]
    assert guard_res.data["integrity_verified"] is True
    assert "MUTATION_AUDIT_TRAIL" in guard_res.data["non_repudiation_receipt"]


# 7. Profile Tool Registry Invariants for Phase 19
def test_phase19_profile_target_counts(runtime: Runtime) -> None:
    assert runtime.registry.count() >= 312
    counts = {
        p: len(runtime.registry.for_profile(p))
        for p in ("minimal", "core", "full", "dynamic", "api", "ui", "admin", "swarm")
    }
    assert counts["minimal"] >= 12
    assert counts["core"] >= 176
    assert counts["dynamic"] >= 213
    assert counts["api"] >= 176
    assert counts["ui"] >= 176
    assert counts["admin"] >= 37
    assert counts["swarm"] >= 146
    assert counts["full"] >= 312


# 8. CLI Integration Tests for raa enterprise
def test_cli_enterprise_subcommands_e2e(tmp_path: Path) -> None:
    ws = str(tmp_path)

    # 1. postman-run
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "enterprise", "postman-run", "-c", "auth_suite.json"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["assertions_passed"] >= 2

    # 2. postman-assert
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "postman-assert",
            "-e",
            "https://api.test/v1",
            "-s",
            "200",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["schema_valid"] is True

    # 3. github-pr
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "github-pr",
            "-r",
            "org/repo",
            "-t",
            "Patch",
            "-h",
            "patch-br",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["pr_number"] == 42

    # 4. playwright-webview
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "playwright-webview",
            "-u",
            "https://login.target.com",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["success"] is True

    # 5. apify-scrape
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "apify-scrape",
            "-a",
            "com.app.target",
            "-s",
            "google_play",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["store"] == "google_play"

    # 6. cli-dispatch
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "cli-dispatch",
            "-h",
            "antigravity",
            "-t",
            "Triage manifest",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["harness"] == "antigravity"

    # 7. omnigent-enforce
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "omnigent-enforce",
            "-a",
            "agent_1",
            "--action",
            "read",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["allowed"] is True

    # 8. nacos-register
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "nacos-register",
            "-s",
            "raa-mesh",
            "-t",
            "312",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["cluster_status"] == "UP"

    # 9. n8n-sync
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "n8n-sync",
            "-w",
            "VulnAlertWorkflow",
            "-t",
            "cve_alert",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "n8n_" in data["data"]["workflow_id"]

    # 10. wasm-sandbox
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "wasm-sandbox",
            "-p",
            "scanner.wasm",
            "-b",
            "0061736d",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["sandbox_egress_blocked"] is True

    # 11. simd-entropy
    res = runner.invoke(
        app, ["--workspace", ws, "--json", "enterprise", "simd-entropy", "-t", "libcore.so"]
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["shannon_entropy"] >= 7.0

    # 12. mutation-guard
    res = runner.invoke(
        app,
        [
            "--workspace",
            ws,
            "--json",
            "enterprise",
            "mutation-guard",
            "-f",
            "libcore.so",
            "--pre",
            "4141",
            "--post",
            "4242",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["integrity_verified"] is True
