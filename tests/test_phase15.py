"""Tests for Phase 15 (v2.1.0): Swarm Governance, Orchestration & Memory Federation.

Covers:
- Paperclip Swarm Governance & Organizational Chart (swarm_org_govern)
- Paperclip & Nasiko Token Budget Metering & Cost Ceilings (swarm_budget_meter)
- Deer-Flow Long-Horizon Recursive Exploration Subagent (subagent_deerflow_spawn)
- Ruflo Tideline Long-Term Cross-Agent Memory Graph (memory_tideline_sync)
- MetaGPT Reverse-Engineering Standard Operating Procedures (sop_pipeline_execute)
- Peer-to-Peer Agent Blackboard Message Bus (swarm_blackboard_post / read)
- Edict Tri-Chamber Institutional Governance & Veto Gates (swarm_edict_gate_evaluate)
- LoopX 24/7 Always-On Long-Horizon Goal & Attention Queue Control Plane (loopx_goal_control_plane)
- CLI subcommands under `raa swarm`:
  govern, budget, spawn-deerflow, sop, blackboard-post, blackboard-read, edict-gate, loopx
- Profile target counts:
  minimal: 12, core: 140, dynamic: 169, api: 139, ui: 140, admin: 23, swarm: 110, full: 253
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
            {"name": "Phase 15 Swarm Test Project", "description": "Testing Phase 15 Swarm"},
        )
    )
    return str(res.data["id"])


# 1. Swarm Org Governance
async def test_swarm_org_govern(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "swarm_org_govern",
        {
            "project_id": project_id,
            "swarm_name": "Test Security Swarm",
            "lead_role": "lead_architect",
            "roles": [
                {
                    "role_id": "lead_architect",
                    "name": "Lead Architect",
                    "description": "Directs overall reversing strategy.",
                    "subordinates": ["analyst_alpha", "analyst_beta"],
                },
                {
                    "role_id": "analyst_alpha",
                    "name": "Analyst Alpha",
                    "description": "Static analysis specialist.",
                    "reports_to": "lead_architect",
                },
            ],
        },
        profile="swarm",
    )
    data = res.data
    assert data["project_id"] == project_id
    assert data["swarm_name"] == "Test Security Swarm"
    assert data["lead_role"] == "lead_architect"
    assert len(data["roles"]) == 2
    assert data["roles"][0]["role_id"] == "lead_architect"


# 2. Swarm Budget Metering
async def test_swarm_budget_metering(runtime: Runtime, project_id: str) -> None:
    # First invocation within budget
    res = await runtime.invoke(
        "swarm_budget_meter",
        {
            "project_id": project_id,
            "tokens": 5000,
            "cost_usd": 0.05,
            "subagent_name": "analyst_alpha",
            "set_token_cap": 10000,
            "set_cost_cap_usd": 0.50,
        },
        profile="swarm",
    )
    assert res.data["total_tokens_consumed"] == 5000
    assert res.data["total_cost_usd"] == 0.05
    assert not res.data["breached"]
    assert res.data["enforcement_action"] == "allow"
    assert "analyst_alpha" in res.data["subagent_spend"]

    # Exceed budget ceiling
    res2 = await runtime.invoke(
        "swarm_budget_meter",
        {
            "project_id": project_id,
            "tokens": 8000,
            "cost_usd": 0.60,
            "subagent_name": "analyst_alpha",
        },
        profile="swarm",
    )
    assert res2.data["total_tokens_consumed"] == 13000
    assert res2.data["breached"] is True
    assert res2.data["enforcement_action"] == "block"


# 3. Deer-Flow Long-Horizon Subagent Spawn
async def test_subagent_deerflow_spawn(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "subagent_deerflow_spawn",
        {
            "project_id": project_id,
            "agent_name": "deep_crypto_hunter",
            "mission_goal": "Identify custom AES key schedules and IV derivations in native JNI library.",
            "max_depth": 4,
            "steps": ["locate_so", "disassemble_entry", "trace_crypto", "synthesize_poc"],
        },
        profile="swarm",
    )
    data = res.data
    assert data["project_id"] == project_id
    assert data["agent_name"] == "deep_crypto_hunter"
    assert len(data["executed_steps"]) == 4
    assert Path(data["scratchpad_path"]).exists()


# 4. Ruflo Tideline Memory Graph Sync
async def test_memory_tideline_sync(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "memory_tideline_sync",
        {
            "project_id": project_id,
            "domain": "crypto",
            "entity_key": "com.target.security.CryptoManager",
            "attributes": {
                "algorithm": "AES/CBC/PKCS7Padding",
                "key_derivation": "PBKDF2WithHmacSHA256",
                "iterations": 10000,
                "obfuscated": False,
            },
        },
        profile="swarm",
    )
    data = res.data
    assert data["domain"] == "crypto"
    assert data["entity_key"] == "com.target.security.CryptoManager"
    assert data["current_state"]["algorithm"] == "AES/CBC/PKCS7Padding"
    assert data["total_domain_entities"] == 1

    # Update entity attributes
    res2 = await runtime.invoke(
        "memory_tideline_sync",
        {
            "project_id": project_id,
            "domain": "crypto",
            "entity_key": "com.target.security.CryptoManager",
            "attributes": {"iv_hardcoded": True},
        },
        profile="swarm",
    )
    assert res2.data["current_state"]["iv_hardcoded"] is True
    assert res2.data["current_state"]["algorithm"] == "AES/CBC/PKCS7Padding"


# 5. MetaGPT SOP Pipeline Execution
async def test_sop_pipeline_execute(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "sop_pipeline_execute",
        {
            "project_id": project_id,
            "sop_name": "api_key_extraction",
            "target_entity": "com.target.mobile.app",
        },
        profile="swarm",
    )
    data = res.data
    assert data["sop_name"] == "api_key_extraction"
    assert data["total_stages"] == 3
    assert data["status"] == "completed"
    assert data["stages"][0]["assigned_agent"] == "apk_analysis_agent"
    assert data["stages"][1]["assigned_agent"] == "security_agent"


# 6. Swarm Blackboard Post and Read
async def test_swarm_blackboard_coordination(runtime: Runtime, project_id: str) -> None:
    # Post hypothesis 1
    post1 = await runtime.invoke(
        "swarm_blackboard_post",
        {
            "project_id": project_id,
            "topic": "crypto",
            "author": "analyst_alpha",
            "hypothesis": "Hardcoded AES key discovered in native libsecurity.so",
            "evidence_ids": ["evi_001", "evi_002"],
            "confidence": 0.85,
        },
        profile="swarm",
    )
    entry1 = post1.data
    assert entry1["topic"] == "crypto"
    assert entry1["confidence"] == 0.85

    # Post hypothesis 2 in network topic
    await runtime.invoke(
        "swarm_blackboard_post",
        {
            "project_id": project_id,
            "topic": "network",
            "author": "analyst_beta",
            "hypothesis": "Self-signed certificate accepted without hostname validation",
            "evidence_ids": ["evi_003"],
            "confidence": 0.95,
        },
        profile="swarm",
    )

    # Read all entries
    read_all = await runtime.invoke(
        "swarm_blackboard_read", {"project_id": project_id}, profile="swarm"
    )
    assert read_all.data["count"] == 2

    # Read filtered by topic
    read_crypto = await runtime.invoke(
        "swarm_blackboard_read", {"project_id": project_id, "topic": "crypto"}, profile="swarm"
    )
    assert read_crypto.data["count"] == 1
    assert read_crypto.data["entries"][0]["author"] == "analyst_alpha"

    # Read filtered by min_confidence
    read_high = await runtime.invoke(
        "swarm_blackboard_read", {"project_id": project_id, "min_confidence": 0.90}, profile="swarm"
    )
    assert read_high.data["count"] == 1
    assert read_high.data["entries"][0]["topic"] == "network"


# 7. Edict Tri-Chamber Governance Evaluation
async def test_swarm_edict_gate_evaluation(runtime: Runtime, project_id: str) -> None:
    # Safe low-risk action approved
    safe_eval = await runtime.invoke(
        "swarm_edict_gate_evaluate",
        {
            "project_id": project_id,
            "action_type": "disassemble_smali",
            "draft_summary": "Disassemble MainActivity.smali for control flow analysis",
            "risk_level": "low",
        },
        profile="swarm",
    )
    assert safe_eval.data["approved"] is True
    assert safe_eval.data["veto_applied"] is False

    # Critical action without safety justification vetoed by Review Chamber
    unsafe_eval = await runtime.invoke(
        "swarm_edict_gate_evaluate",
        {
            "project_id": project_id,
            "action_type": "flash_partition",
            "draft_summary": "Wipe device and flash custom recovery image",
            "risk_level": "critical",
        },
        profile="swarm",
    )
    assert unsafe_eval.data["approved"] is False
    assert unsafe_eval.data["veto_applied"] is True
    assert unsafe_eval.data["veto_chamber"] == "Review Chamber"

    # High-risk action with bypass requested vetoed by Execution Chamber
    bypass_eval = await runtime.invoke(
        "swarm_edict_gate_evaluate",
        {
            "project_id": project_id,
            "action_type": "mutate_binary",
            "draft_summary": "Safe patch with binary verification verified",
            "risk_level": "high",
            "bypass_requested": True,
        },
        profile="swarm",
    )
    assert bypass_eval.data["approved"] is False
    assert bypass_eval.data["veto_applied"] is True
    assert bypass_eval.data["veto_chamber"] == "Execution Chamber"


# 8. LoopX 24/7 Long-Horizon Goal & Attention Queue Control Plane
async def test_loopx_goal_control_plane(runtime: Runtime, project_id: str) -> None:
    # 1. Create Goal
    create_res = await runtime.invoke(
        "loopx_goal_control_plane",
        {
            "action": "create",
            "project_id": project_id,
            "title": "Reverse-engineer proprietary banking protocol",
        },
        profile="swarm",
    )
    goal = create_res.data["goal"]
    gid = goal["goal_id"]
    assert gid.startswith("goal_")
    assert goal["status"] == "in_progress"

    # 2. Enqueue Attention Items
    enq_res = await runtime.invoke(
        "loopx_goal_control_plane",
        {
            "action": "enqueue_attention",
            "project_id": project_id,
            "goal_id": gid,
            "attention_item": "inspect_jni_register_natives",
        },
        profile="swarm",
    )
    assert enq_res.data["queue_length"] == 1

    # 3. Advance Step
    step_res = await runtime.invoke(
        "loopx_goal_control_plane",
        {
            "action": "step",
            "project_id": project_id,
            "goal_id": gid,
        },
        profile="swarm",
    )
    assert step_res.data["active_step"] == 1
    assert step_res.data["processed_attention"] == "inspect_jni_register_natives"
    assert step_res.data["remaining_attention"] == 0

    # 4. Checkpoint State
    cp_res = await runtime.invoke(
        "loopx_goal_control_plane",
        {
            "action": "checkpoint",
            "project_id": project_id,
            "goal_id": gid,
            "checkpoint_data": {"findings_count": 3, "status": "checkpointed"},
        },
        profile="swarm",
    )
    assert cp_res.data["checkpoints_count"] == 1
    assert cp_res.data["latest_checkpoint"]["findings_count"] == 3

    # 5. List Goals
    list_res = await runtime.invoke(
        "loopx_goal_control_plane",
        {
            "action": "list",
            "project_id": project_id,
        },
        profile="swarm",
    )
    assert list_res.data["count"] >= 1


# 9. Profile and Tool Registry Invariants
def test_phase15_tool_registry_and_profiles(runtime: Runtime) -> None:
    assert runtime.registry.count() >= 253
    counts = {
        p: len(runtime.registry.for_profile(p))
        for p in ("minimal", "core", "full", "dynamic", "api", "ui", "admin", "swarm")
    }
    assert counts["minimal"] >= 12
    assert counts["core"] >= 140
    assert counts["dynamic"] >= 169
    assert counts["api"] >= 139
    assert counts["ui"] >= 140
    assert counts["admin"] >= 23
    assert counts["swarm"] >= 110
    assert counts["full"] >= 253


# 10. CLI Integration Tests
def test_phase15_cli_commands() -> None:
    # First create a project through CLI so its directory exists in the workspace
    create_res = runner.invoke(app, ["--json", "project", "create", "Phase15 CLI Project"])
    assert create_res.exit_code == 0
    project_id = json.loads(create_res.output)["data"]["id"]

    # 1. CLI govern
    res = runner.invoke(
        app,
        ["swarm", "govern", "-p", project_id, "-n", "CLI Test Swarm", "-l", "director"],
    )
    assert res.exit_code == 0
    assert "CLI Test Swarm" in res.output

    # 2. CLI budget
    res = runner.invoke(
        app,
        ["swarm", "budget", "-p", project_id, "-t", "1000", "-c", "0.02", "-s", "cli_agent"],
    )
    assert res.exit_code == 0
    assert "1000" in res.output

    # 3. CLI spawn-deerflow
    res = runner.invoke(
        app,
        ["swarm", "spawn-deerflow", "-p", project_id, "-g", "Autonomous decompilation run"],
    )
    assert res.exit_code == 0
    assert "deerflow" in res.output.lower()

    # 4. CLI sop
    res = runner.invoke(
        app,
        ["swarm", "sop", "-p", project_id, "-t", "com.example.pkg"],
    )
    assert res.exit_code == 0
    assert "framework_audit" in res.output

    # 5. CLI blackboard-post and read
    res = runner.invoke(
        app,
        [
            "swarm",
            "blackboard-post",
            "-p",
            project_id,
            "--topic",
            "cli_topic",
            "--author",
            "cli_bot",
            "--hypothesis",
            "Discovered bypass endpoint",
        ],
    )
    assert res.exit_code == 0

    res_read = runner.invoke(
        app,
        ["swarm", "blackboard-read", "-p", project_id, "--topic", "cli_topic"],
    )
    assert res_read.exit_code == 0
    assert "Discovered bypass endpoint" in res_read.output

    # 6. CLI edict-gate
    res = runner.invoke(
        app,
        [
            "swarm",
            "edict-gate",
            "-p",
            project_id,
            "-a",
            "read_memory",
            "-s",
            "Safe read-only memory inspection",
            "-r",
            "low",
        ],
    )
    assert res.exit_code == 0
    assert "approved" in res.output.lower()

    # 7. CLI loopx
    res = runner.invoke(
        app,
        ["swarm", "loopx", "-a", "create", "-p", project_id, "--title", "CLI Goal"],
    )
    assert res.exit_code == 0
    assert "CLI Goal" in res.output
