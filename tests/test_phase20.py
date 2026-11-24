"""Tests for Phase 20 (v3.0.0 Production):
Offensive Security Operations, Yaklang HackSkills, Deep HTTP 403 Bypass Mutator,
Computer-Use GUI Agent, FrontierAgent ReAct/Swarm Switcher, OpenMausBot Gatekeeper,
Exploit PoC Chaining, SkillNet Evaluation Gym, Portable SkillPack Bundles,
v3.0 Tamper-Evident Report Seal & Final System Benchmark.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.config import Settings
from raa.runtime import Runtime
from raa.services.offensive import OffensiveSecurityService

runner = CliRunner()


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


@pytest.fixture
def runtime(temp_workspace: Path) -> Runtime:
    settings = Settings(workspace=temp_workspace)
    return Runtime(settings)


@pytest.fixture
def offensive_service(temp_workspace: Path) -> OffensiveSecurityService:
    return OffensiveSecurityService(temp_workspace)


# --- Unit Tests for OffensiveSecurityService ---


def test_offensive_service_initialization(offensive_service: OffensiveSecurityService) -> None:
    assert offensive_service.workspace.exists()


def test_offensive_service_yak_skill_run(offensive_service: OffensiveSecurityService) -> None:
    res = offensive_service.run_yak_skill_playbook(
        playbook_name="mobile_jwt_tamper",
        target_endpoint="https://api.target.com/v1/auth",
    )
    assert res.playbook_name == "mobile_jwt_tamper"
    assert res.target_endpoint == "https://api.target.com/v1/auth"
    assert res.execution_status == "completed"
    assert len(res.findings) >= 1
    assert "token_spoofing" in res.findings[0] or "findings" in res.findings[0]
    assert res.safe_mode is True


def test_offensive_service_yak_skill_unknown_playbook(
    offensive_service: OffensiveSecurityService,
) -> None:
    res = offensive_service.run_yak_skill_playbook(
        playbook_name="custom_unknown_exploit",
        target_endpoint="https://api.target.com/test",
    )
    assert res.playbook_name == "custom_unknown_exploit"
    assert res.execution_status == "completed"
    assert len(res.findings) >= 1


def test_offensive_service_mutate_http_403(offensive_service: OffensiveSecurityService) -> None:
    res = offensive_service.mutate_http_403_bypass(
        target_url="https://api.target.com/admin/dashboard",
    )
    assert res.target_url == "https://api.target.com/admin/dashboard"
    assert res.bypass_candidates_count >= 10
    assert any("X-Forwarded-For" in m.get("technique", "") or "headers" in m for m in res.mutations)
    assert any(
        "path" in m.get("technique", "").lower() or "normalized" in m.get("technique", "").lower()
        for m in res.mutations
    )
    assert any(
        "verb" in m.get("technique", "").lower() or "override" in m.get("technique", "").lower()
        for m in res.mutations
    )


def test_offensive_service_computer_use_gui(offensive_service: OffensiveSecurityService) -> None:
    for app_name in ["ghidra", "ida_pro", "jadx_gui", "burp_suite"]:
        res = offensive_service.execute_computer_use_gui(
            target_application=app_name,  # type: ignore
            task_description="Decompile target native library and export call graph",
        )
        assert res.target_application == app_name
        assert res.task_description == "Decompile target native library and export call graph"
        assert res.status == "executed"
        assert len(res.actions_taken) >= 3
        assert res.screenshot_verified is True


def test_offensive_service_frontier_mode_switch(
    offensive_service: OffensiveSecurityService,
) -> None:
    res_swarm = offensive_service.switch_frontier_mode(
        desired_mode="swarm_deep",
        reason="Complex multi-surface vulnerability chain required",
    )
    assert res_swarm.active_mode == "swarm_deep"
    assert res_swarm.active_mode_agents >= 4
    assert res_swarm.switched is True

    res_react = offensive_service.switch_frontier_mode(
        desired_mode="react_fast",
        reason="Fast iterative triage needed",
    )
    assert res_react.active_mode == "react_fast"
    assert res_react.active_mode_agents == 1
    assert res_react.switched is True


def test_offensive_service_mausbot_gatekeeper_prompt(
    offensive_service: OffensiveSecurityService,
) -> None:
    res = offensive_service.prompt_mausbot_gatekeeper(
        operation_name="patch_arm64_relocation_table",
        payload_preview="- 00 00 A0 E3\n+ 1E FF 2F E1",
    )
    assert res.operation_name == "patch_arm64_relocation_table"
    assert res.risk_level in ["high", "critical", "medium"]
    assert res.gatekeeper_verdict in ["pending_human_approval", "approved", "rejected"]
    assert "patch_arm64" in res.impact_summary
    assert "+ 1E FF" in res.diff_preview


def test_offensive_service_exploit_chain_verify(
    offensive_service: OffensiveSecurityService,
) -> None:
    steps = [
        "Read exported ContentProvider without permission check",
        "Leak internal SQLite credentials via SQL injection payload",
        "Derive AES master key via PBKDF2 with leaked salt",
    ]
    res = offensive_service.verify_exploit_chain(
        vulnerability_id="CVE-2026-9999",
        proposed_chain=steps,
    )
    assert res.vulnerability_id == "CVE-2026-9999"
    assert res.chain_length == 3
    assert res.verification_receipt is not None
    assert res.non_destructive_verified is True
    assert res.safety_verdict == "safe_poc_validated"


def test_offensive_service_skillnet_benchmark_eval(
    offensive_service: OffensiveSecurityService,
) -> None:
    res = offensive_service.evaluate_skillnet_benchmark(benchmark_suite="full_reverse_gym")
    assert res.benchmark_suite == "full_reverse_gym"
    assert res.total_benchmarks >= 10
    assert res.accuracy_percentage >= 95.0
    assert res.grade in ["A+", "A", "Production-Ready"]


def test_offensive_service_skillpack_bundle_manage(
    offensive_service: OffensiveSecurityService,
) -> None:
    # 1. List
    list_res = offensive_service.manage_skillpack_bundle(
        action="list", skillpack_name="mobile_pack"
    )
    assert list_res.action == "list"
    assert len(list_res.skillpacks) >= 1

    # 2. Package
    pkg_res = offensive_service.manage_skillpack_bundle(
        action="package", skillpack_name="android_security_pack"
    )
    assert pkg_res.action == "package"
    assert pkg_res.bundle_path.endswith(".skillpack")
    assert pkg_res.status == "success"

    # 3. Validate
    val_res = offensive_service.manage_skillpack_bundle(
        action="validate", skillpack_name="android_security_pack"
    )
    assert val_res.action == "validate"
    assert val_res.status == "valid"

    # 4. Install
    inst_res = offensive_service.manage_skillpack_bundle(
        action="install", skillpack_name="android_security_pack"
    )
    assert inst_res.action == "install"
    assert inst_res.status == "installed"


def test_offensive_service_audit_tamper_seal_v3(
    offensive_service: OffensiveSecurityService,
) -> None:
    sample_report = "# Security Audit Report v3.0\nTarget: com.acme.banking\nVerdict: Secure"
    res = offensive_service.generate_audit_tamper_seal_v3(report_content=sample_report)
    assert len(res.sha256_seal) == 64
    assert res.cyclonedx_sbom_manifest["bomFormat"] == "CycloneDX"
    assert res.cyclonedx_sbom_manifest["specVersion"] == "1.5"
    assert res.verified_tool_count == 322
    assert res.tamper_evident_status == "sealed"


def test_offensive_service_v3_full_system_benchmark(
    offensive_service: OffensiveSecurityService,
) -> None:
    res = offensive_service.run_v3_full_system_benchmark()
    assert res.total_registered_tools == 322
    assert res.total_skills_verified >= 30
    assert res.production_quality_score >= 98.0
    assert res.production_gate_passed is True


# --- Runtime Tool Invocation Tests ---


@pytest.mark.asyncio
async def test_tool_hack_yak_skill_run(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "hack_yak_skill_run",
        {"playbook_name": "mobile_jwt_tamper", "target_endpoint": "https://api.test.com"},
    )
    assert res.data["playbook_name"] == "mobile_jwt_tamper"
    assert res.data["execution_status"] == "completed"


@pytest.mark.asyncio
async def test_tool_hack_403_deep_mutate(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "hack_403_deep_mutate",
        {"target_url": "https://api.test.com/v1/internal/users"},
    )
    assert res.data["bypass_candidates_count"] >= 10
    assert len(res.data["mutations"]) >= 10


@pytest.mark.asyncio
async def test_tool_computer_use_gui_execute(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "computer_use_gui_execute",
        {
            "target_application": "jadx_gui",
            "task_description": "Export all obfuscated class names to text file",
        },
        profile="dynamic",
    )
    assert res.data["target_application"] == "jadx_gui"
    assert res.data["screenshot_verified"] is True


@pytest.mark.asyncio
async def test_tool_frontier_mode_switch(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "frontier_mode_switch",
        {"desired_mode": "swarm_deep", "reason": "Deep vulnerability analysis required"},
    )
    assert res.data["active_mode"] == "swarm_deep"


@pytest.mark.asyncio
async def test_tool_mausbot_gatekeeper_prompt(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "mausbot_gatekeeper_prompt",
        {
            "operation_name": "binary_patch_injection",
            "payload_preview": "NOP out function sub_128A",
        },
        profile="admin",
    )
    assert res.data["operation_name"] == "binary_patch_injection"
    assert "NOP out function" in res.data["diff_preview"]


@pytest.mark.asyncio
async def test_tool_exploit_chain_verify(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "exploit_chain_verify",
        {
            "vulnerability_id": "VULN-2026-001",
            "proposed_chain": ["Step 1: Broadcast trigger", "Step 2: Log inspection"],
        },
    )
    assert res.data["non_destructive_verified"] is True
    assert res.data["chain_length"] == 2


@pytest.mark.asyncio
async def test_tool_skillnet_benchmark_eval(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "skillnet_benchmark_eval",
        {"benchmark_suite": "full_reverse_gym"},
        profile="admin",
    )
    assert res.data["accuracy_percentage"] >= 90.0


@pytest.mark.asyncio
async def test_tool_skillpack_bundle_manage(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "skillpack_bundle_manage",
        {"action": "package", "skillpack_name": "crypto_audit_pack"},
        profile="admin",
    )
    assert res.data["status"] == "success"


@pytest.mark.asyncio
async def test_tool_audit_tamper_seal_v3(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "audit_tamper_seal_v3",
        {"report_content": "Final Audit Report for Banking App"},
        profile="admin",
    )
    assert len(res.data["sha256_seal"]) == 64
    assert res.data["verified_tool_count"] == 322


@pytest.mark.asyncio
async def test_tool_v3_full_system_benchmark(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "v3_full_system_benchmark",
        {"target_environment": "production"},
        profile="admin",
    )
    assert res.data["total_registered_tools"] == 322
    assert res.data["production_gate_passed"] is True


# --- CLI Command Invocation Tests ---


def test_cli_offensive_yak_run(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--json",
            "offensive",
            "yak-run",
            "--playbook",
            "mobile_jwt_tamper",
            "--endpoint",
            "https://api.target.com/v1",
        ],
    )
    assert result.exit_code == 0
    assert "mobile_jwt_tamper" in result.output


def test_cli_offensive_mutate_403(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--json",
            "offensive",
            "mutate-403",
            "--url",
            "https://api.target.com/admin",
        ],
    )
    assert result.exit_code == 0
    assert "bypass_candidates_count" in result.output


def test_cli_offensive_computer_use(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "dynamic",
            "--json",
            "offensive",
            "computer-use",
            "--app",
            "ghidra",
            "--task",
            "Decompile libc.so and export symbols",
        ],
    )
    assert result.exit_code == 0
    assert "ghidra" in result.output


def test_cli_offensive_frontier_mode(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--json",
            "offensive",
            "frontier-mode",
            "--mode",
            "swarm_deep",
            "--reason",
            "Autonomous pentest coordination",
        ],
    )
    assert result.exit_code == 0
    assert "swarm_deep" in result.output


def test_cli_offensive_gatekeeper_prompt(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "admin",
            "--json",
            "offensive",
            "gatekeeper-prompt",
            "--operation",
            "firmware_memory_dump",
            "--preview",
            "Dump region 0x80000000 to 0x8FFFFFFF",
        ],
    )
    assert result.exit_code == 0
    assert "firmware_memory_dump" in result.output


def test_cli_offensive_exploit_verify(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--json",
            "offensive",
            "exploit-verify",
            "--vuln-id",
            "CVE-2026-1234",
            "--step",
            "Trigger broadcast intent",
            "--step",
            "Inspect memory leak receipt",
        ],
    )
    assert result.exit_code == 0
    assert "safe_poc_validated" in result.output


def test_cli_offensive_skillnet_eval(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "admin",
            "--json",
            "offensive",
            "skillnet-eval",
            "--suite",
            "full_reverse_gym",
        ],
    )
    assert result.exit_code == 0
    assert "accuracy_percentage" in result.output


def test_cli_offensive_skillpack(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "admin",
            "--json",
            "offensive",
            "skillpack",
            "--action",
            "package",
            "--name",
            "forensics_bundle",
        ],
    )
    assert result.exit_code == 0
    assert "forensics_bundle" in result.output


def test_cli_offensive_tamper_seal(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "admin",
            "--json",
            "offensive",
            "tamper-seal",
            "--report",
            "# Final Security Report\nAll clear",
        ],
    )
    assert result.exit_code == 0
    assert "sha256_seal" in result.output


def test_cli_offensive_benchmark_v3(temp_workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "--workspace",
            str(temp_workspace),
            "--profile",
            "admin",
            "--json",
            "offensive",
            "benchmark-v3",
            "--env",
            "production",
        ],
    )
    assert result.exit_code == 0
    assert "production_gate_passed" in result.output
    assert "322" in result.output
