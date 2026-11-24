"""Tests for Phase 16 (v2.2.0): Dual-Context Adversarial Auditing, Cognitive Reasoning & Exploit Economics.

Covers:
- Elephant-Goldfish Dual-Context Adversarial Audit Engine (audit_elephant_draft_spec / audit_goldfish_adversarial_review)
- Google Agent Development Kit (ADK) Python State Engine (adk_workflow_run)
- Cognitive Architecture & Strategy Selector (reasoning_strategy_select)
- In-App Purchase (IAP) & Monetization Intelligence (fin_iap_billing_audit)
- QuantDinger Exploit Payoff Simulation (exploit_payoff_simulate)
- OpenExecutive Board-Level Cyber Risk Briefing (exec_briefing_synthesize)
- Dr. Claw Academic Vulnerability Research Whitepaper Synthesis (sec_research_whitepaper_synthesize)
- Haystack Decompiled Bytecode & Source Code Semantic Search (rag_haystack_query)
- CLI subcommands under `raa cognitive`:
  elephant-draft, goldfish-review, adk-workflow, strategy-select, iap-audit, exploit-payoff,
  exec-briefing, whitepaper, haystack
- Profile target counts:
  minimal: 12, core: 145, dynamic: 174, api: 145, ui: 145, admin: 26, swarm: 115, full: 262
"""

from __future__ import annotations

import json

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
                "name": "Phase 16 Cognitive Test Project",
                "description": "Testing Phase 16 Cognitive & Adversarial",
            },
        )
    )
    return str(res.data["id"])


# 1. Track 69: Elephant-Goldfish Dual-Context Adversarial Engine
async def test_elephant_goldfish_adversarial_audit(runtime: Runtime, project_id: str) -> None:
    # 1. Elephant drafts full-context spec
    spec_res = await runtime.invoke(
        "audit_elephant_draft_spec",
        {
            "project_id": project_id,
            "target_component": "com.banking.security.MasterKeyStore",
            "architecture_overview": "Native Android JNI crypto architecture wrapping libcrypto.so",
            "codebase_context": "Includes MasterKeyStore.java, KeyDerivation.smali, libcrypto.so disassembly, and Manifest permissions",
            "claims": [
                {
                    "claim_id": "claim_01",
                    "claim_text": "Static AES encryption key hardcoded in libcrypto.so .rodata section",
                },
                {
                    "claim_id": "claim_02",
                    "claim_text": "Remote code execution possible through exported BroadcastReceiver with unverified parcelable",
                },
            ],
        },
    )
    spec_data = spec_res.data
    assert spec_data["target_component"] == "com.banking.security.MasterKeyStore"
    assert len(spec_data["proposed_reversing_claims"]) == 2

    # 2. Goldfish zero-context review on legitimate claim with empirical evidence
    goldfish_pass = await runtime.invoke(
        "audit_goldfish_adversarial_review",
        {
            "project_id": project_id,
            "claim_id": "claim_01",
            "claim_text": "Static AES encryption key hardcoded in libcrypto.so .rodata section",
            "isolated_evidence": [
                "Disassembly byte sequence at offset 0x4A20: 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6",
                "Cross-reference: Java_com_banking_security_MasterKeyStore_initAES reads from rodata_0x4A20",
            ],
            "prior_confidence": 0.85,
        },
    )
    assert goldfish_pass.data["adversarial_verdict"] == "confirmed"
    assert goldfish_pass.data["confidence_delta"] > 0

    # 3. Goldfish zero-context review on hallucinated claim with zero evidence
    goldfish_hallucination = await runtime.invoke(
        "audit_goldfish_adversarial_review",
        {
            "project_id": project_id,
            "claim_id": "claim_02",
            "claim_text": "Remote code execution possible through exported BroadcastReceiver with unverified parcelable",
            "isolated_evidence": [],
            "prior_confidence": 0.90,
        },
    )
    assert goldfish_hallucination.data["adversarial_verdict"] == "hallucination_flagged"
    assert goldfish_hallucination.data["confidence_delta"] < 0

    # 4. Goldfish zero-context review on claim with contradictory evidence
    goldfish_refuted = await runtime.invoke(
        "audit_goldfish_adversarial_review",
        {
            "project_id": project_id,
            "claim_id": "claim_03",
            "claim_text": "Device fingerprinting bypass found",
            "isolated_evidence": [
                "Test showed not reproducible on physical Pixel 8 with Android 15"
            ],
        },
    )
    assert goldfish_refuted.data["adversarial_verdict"] == "refuted"


# 2. Track 70: Google Agent Development Kit (ADK) Python Workflow
async def test_adk_workflow_run(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "adk_workflow_run",
        {
            "project_id": project_id,
            "workflow_name": "adk_decompile_and_verify",
            "initial_state": {"target": "com.example.app", "depth": 2},
        },
    )
    data = res.data
    assert data["status"] == "completed"
    assert len(data["steps_executed"]) == 4
    assert len(data["opentelemetry_traces"]) == 4
    assert data["opentelemetry_traces"][0]["span_name"] == "adk.step.validate_input"


# 3. Track 71: Cognitive Architecture & Strategy Selector
async def test_reasoning_strategy_selector(runtime: Runtime) -> None:
    # 1. Simple target -> Fast ReAct
    s_simple = await runtime.invoke(
        "reasoning_strategy_select",
        {
            "target": "com.simple.app",
            "obfuscation_level": "none",
            "has_native_crypto": False,
            "lines_of_code": 800,
        },
    )
    assert s_simple.data["recommended_strategy"] == "fast_react"

    # 2. Moderate target -> Plan-and-Solve
    s_medium = await runtime.invoke(
        "reasoning_strategy_select",
        {
            "target": "com.finance.app",
            "obfuscation_level": "medium",
            "has_native_crypto": False,
            "lines_of_code": 15000,
        },
    )
    assert s_medium.data["recommended_strategy"] == "plan_and_solve"

    # 3. Packed/Complex target -> Multi-Agent Debate
    s_heavy = await runtime.invoke(
        "reasoning_strategy_select",
        {
            "target": "com.protected.game",
            "obfuscation_level": "packed",
            "has_native_crypto": True,
            "lines_of_code": 120000,
        },
    )
    assert s_heavy.data["recommended_strategy"] == "multi_agent_debate"


# 4. Track 72: In-App Billing / Monetization Intelligence
async def test_fin_iap_billing_audit(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "fin_iap_billing_audit",
        {
            "project_id": project_id,
            "declared_permissions": ["com.android.vending.BILLING"],
            "decompiled_classes": [
                "com.android.vending.billing.IInAppBillingService",
                "com.target.billing.SecurityVerifyPurchase",
            ],
            "string_constants": [
                "verifyReceiptLocally",
                "onPurchasesUpdated",
                "BillingClient",
            ],
        },
        profile="api",
    )
    data = res.data
    assert "Google Play Billing Library" in data["sdk_detected"]
    assert data["client_side_validation_found"] is True
    assert data["unverified_receipt_handling"] is True
    assert data["monetization_risk_score"] >= 8.0
    assert len(data["intent_spoofing_vulnerabilities"]) >= 2


# 5. Track 73: QuantDinger Exploit Payoff Simulation
async def test_exploit_payoff_simulate(runtime: Runtime) -> None:
    res = await runtime.invoke(
        "exploit_payoff_simulate",
        {
            "vulnerability_id": "VULN-2026-IAP-001",
            "vulnerability_title": "Client-Side Billing Signature Bypass",
            "severity": "critical",
            "attacker_skill_required": "intermediate",
            "exploit_asset_type": "payment_bypass",
        },
        profile="admin",
    )
    data = res.data
    assert data["vulnerability_id"] == "VULN-2026-IAP-001"
    assert data["attacker_cost_usd"] == 500.0
    assert data["attacker_reward_usd"] == 24000.0  # 12000 * 2.0 for critical
    assert data["payoff_ratio"] == 48.0
    assert data["economic_viability"] == "highly_lucrative"
    assert data["blast_radius"] == "enterprise_tenant"


# 6. Track 74: OpenExecutive Board-Level Cyber Risk Briefing
async def test_exec_briefing_synthesize(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "exec_briefing_synthesize",
        {
            "project_id": project_id,
            "app_name": "SecureBank Mobile",
            "vulnerabilities": [
                {"title": "Unauthenticated ContentProvider SQL Injection", "severity": "critical"},
                {"title": "Cleartext HTTP API Communication", "severity": "high"},
            ],
            "total_users": 50000,
        },
        profile="admin",
    )
    data = res.data
    assert data["app_name"] == "SecureBank Mobile"
    assert data["overall_risk_level"] == "critical"
    assert data["financial_exposure_usd"] > 0
    assert "GDPR_Article_32_Security_of_Processing" in data["compliance_exposure"]
    assert len(data["remediation_roadmap"]) == 3


# 7. Track 74B: Dr. Claw Vulnerability Whitepaper Synthesizer
async def test_sec_research_whitepaper_synthesize(runtime: Runtime, project_id: str) -> None:
    res = await runtime.invoke(
        "sec_research_whitepaper_synthesize",
        {
            "project_id": project_id,
            "paper_title": "Automated Exploitation of Hardcoded Dynamic JNI Key Derivation Schemes",
            "vulnerability_mechanisms": [
                "Constant array XOR transformation in native library init",
                "Unprotected memory buffer holding decrypted token",
            ],
            "cve_candidate": "CVE-2026-99999",
        },
        profile="admin",
    )
    data = res.data
    assert (
        data["paper_title"]
        == "Automated Exploitation of Hardcoded Dynamic JNI Key Derivation Schemes"
    )
    assert data["cve_candidate_id"] == "CVE-2026-99999"
    assert len(data["literature_review_citations"]) == 3
    assert "COORDINATED VULNERABILITY DISCLOSURE" in data["disclosure_brief"]


# 8. Haystack Code RAG Search Pipeline
async def test_rag_haystack_query(runtime: Runtime, project_id: str) -> None:
    # Index source files
    code_files = {
        "com/target/crypto/AESCipher.java": "public class AESCipher { private static final String CIPHER = 'AES/CBC/PKCS7Padding'; }",
        "com/target/network/ApiGateway.java": "public class ApiGateway { private static final String BASE_URL = 'https://api.target.com/v1'; }",
        "com/target/auth/TokenStorage.java": "public class TokenStorage { public void saveBearerToken(String token) { SharedPreferences.Editor e; } }",
    }

    res = await runtime.invoke(
        "rag_haystack_query",
        {
            "project_id": project_id,
            "query": "AES/CBC/PKCS7Padding cipher",
            "top_k": 3,
            "index_documents": code_files,
        },
    )
    data = res.data
    assert data["total_matches"] >= 1
    assert data["results"][0]["doc_id"] == "com/target/crypto/AESCipher.java"
    assert data["results"][0]["score"] > 0.0


# 9. Tool Registry and Profile Invariants for Phase 16
def test_phase16_tool_registry_and_profiles(runtime: Runtime) -> None:
    assert runtime.registry.count() >= 262
    counts = {
        p: len(runtime.registry.for_profile(p))
        for p in ("minimal", "core", "full", "dynamic", "api", "ui", "admin", "swarm")
    }
    assert counts["minimal"] >= 12
    assert counts["core"] >= 145
    assert counts["dynamic"] >= 174
    assert counts["api"] >= 145
    assert counts["ui"] >= 145
    assert counts["admin"] >= 26
    assert counts["swarm"] >= 115
    assert counts["full"] >= 262


# 10. CLI Integration Tests
def test_phase16_cli_commands() -> None:
    create_res = runner.invoke(app, ["--json", "project", "create", "Phase16 CLI Project"])
    assert create_res.exit_code == 0
    project_id = json.loads(create_res.output)["data"]["id"]

    # 1. CLI elephant-draft
    res1 = runner.invoke(
        app,
        ["cognitive", "elephant-draft", "-p", project_id, "-t", "CryptoEngine"],
    )
    assert res1.exit_code == 0
    assert "CryptoEngine" in res1.output

    # 2. CLI goldfish-review
    res2 = runner.invoke(
        app,
        [
            "cognitive",
            "goldfish-review",
            "-p",
            project_id,
            "--claim-id",
            "claim_01",
            "--claim-text",
            "Weak DES cipher used in transport layer",
            "-e",
            "Found 'DES/ECB/PKCS5Padding' constant string in Smali",
        ],
    )
    assert res2.exit_code == 0
    assert "confirmed" in res2.output.lower()

    # 3. CLI adk-workflow
    res3 = runner.invoke(
        app,
        ["cognitive", "adk-workflow", "-p", project_id, "-n", "full_triage_flow"],
    )
    assert res3.exit_code == 0
    assert "completed" in res3.output.lower()

    # 4. CLI strategy-select
    res4 = runner.invoke(
        app,
        [
            "cognitive",
            "strategy-select",
            "-t",
            "ComplexTarget",
            "--obfuscation",
            "high",
            "--crypto",
        ],
    )
    assert res4.exit_code == 0
    assert "multi_agent_debate" in res4.output.lower()

    # 5. CLI iap-audit
    res5 = runner.invoke(
        app,
        ["cognitive", "iap-audit", "-p", project_id],
    )
    assert res5.exit_code == 0
    assert "Google Play Billing" in res5.output

    # 6. CLI exploit-payoff
    res6 = runner.invoke(
        app,
        [
            "cognitive",
            "exploit-payoff",
            "--vuln-id",
            "PAY-001",
            "--title",
            "IAP Bypass",
            "--severity",
            "high",
            "--skill",
            "intermediate",
            "--asset",
            "payment_bypass",
        ],
    )
    assert res6.exit_code == 0
    assert "payoff_ratio" in res6.output.lower()

    # 7. CLI exec-briefing
    res7 = runner.invoke(
        app,
        ["cognitive", "exec-briefing", "-p", project_id, "-n", "DemoApp"],
    )
    assert res7.exit_code == 0
    assert "executive_summary" in res7.output.lower()

    # 8. CLI whitepaper
    res8 = runner.invoke(
        app,
        [
            "cognitive",
            "whitepaper",
            "-p",
            project_id,
            "--title",
            "Novel Bytecode Deobfuscation Attack",
        ],
    )
    assert res8.exit_code == 0
    assert "CVE-2026" in res8.output

    # 9. CLI haystack
    res9 = runner.invoke(
        app,
        ["cognitive", "haystack", "-p", project_id, "-q", "AES encryption"],
    )
    assert res9.exit_code == 0
    assert "haystack" in res9.output.lower()
