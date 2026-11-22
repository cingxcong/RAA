"""Phase 13I Integration & Unit Tests.

Covers:
- Automated APK Secret Leakage & Cloud Credential Harvester (sec_apkleaks_secret_scan)
- Sensitive API Call-Graph & Privacy Taint Flow Tracer (sec_sensitive_api_taint_trace)
- Codeless Runtime Hook Generation & Dynamic Method Interceptor:
  - dyn_rms_hook_generate
  - dyn_rms_method_override
- Automated MASTG Verification Procedures & MAPT Test Runner (sec_mastg_procedure_run)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.rms_interceptor import generate_rms_runtime_hooks, override_rms_method
from raa.services.security.apkleaks_scanner import calculate_shannon_entropy, scan_apkleaks_secrets
from raa.services.security.mastg_runner import run_mastg_verification
from raa.services.security.taint_tracer import trace_sensitive_api_taint

runner = CliRunner()


# =====================================================================
# Unit Tests: Service Layer
# =====================================================================


def test_service_apkleaks_scanner() -> None:
    # 1. Entropy calculation
    ent_low = calculate_shannon_entropy("aaaaaaaa")
    assert ent_low == 0.0
    ent_high = calculate_shannon_entropy("AKIA" + "IOSFODNN7EXAMPLE")
    assert ent_high > 3.0

    # 2. Secret scan
    sample_strings = [
        "AKIA" + "IOSFODNN7EXAMPLE",
        "AIza" + "SyD-7389148209384_VerifiedGcpProductionKey",
        "sk_live_" + "51NzQ8pL2rJk8W1z84839210948392019",
        "https://production-fleet-eu.firebaseio.com",
        "simple_word_without_token",
    ]
    res = scan_apkleaks_secrets(content_strings=sample_strings, min_entropy=2.0)
    assert res["secrets_found_count"] >= 3
    providers = res["summary_by_provider"]
    assert "Google Cloud" in providers or "Stripe" in providers
    for sec in res["secrets"]:
        assert "...[REDACTED]" in sec["masked_value"]
        assert sec["entropy"] >= 2.0


def test_service_taint_tracer() -> None:
    res = trace_sensitive_api_taint(project_id="prj_test", enforce_strict_gdpr=True)
    assert res["status"] == "analyzed"
    assert res["total_sources_found"] >= 5
    assert res["total_sinks_found"] >= 4
    assert res["total_taint_flows"] >= 2
    assert len(res["gdpr_violations"]) >= 1
    assert res["privacy_compliance_score"] < 100
    flow = res["taint_flows"][0]
    assert "getCurrentLocation" in flow["source_method"]
    assert "OkHttpClient" in flow["sink_api"]


def test_service_rms_interceptor() -> None:
    # 1. Pre-configured hooks
    hook_crypto = generate_rms_runtime_hooks(category="crypto")
    assert hook_crypto["status"] == "ready"
    assert "Cipher" in hook_crypto["monitored_classes"][0]
    assert "Cipher.init" in hook_crypto["frida_script"]

    hook_keystore = generate_rms_runtime_hooks(category="keystore")
    assert "KeyStore" in hook_keystore["monitored_classes"][0]

    # 2. Codeless method override
    override_res = override_rms_method(
        target_class="com.example.Security",
        target_method="checkRoot",
        return_value_override=False,
        log_arguments=True,
    )
    assert override_res["status"] == "ready"
    assert override_res["override_active"] is True
    assert "com.example.Security" in override_res["frida_script"]
    assert "checkRoot" in override_res["frida_script"]
    assert "return false;" in override_res["frida_script"]


def test_service_mastg_runner() -> None:
    props = {
        "debuggable": True,
        "allow_backup": True,
        "cleartext_traffic": True,
        "exported_unprotected_components": 2,
        "root_detection_present": False,
        "custom_trust_manager_flaw": True,
        "tapjacking_protected": False,
    }
    report = run_mastg_verification(static_properties=props)
    assert report["tests_executed"] >= 7
    assert report["failed_count"] >= 4
    assert report["compliance_percentage"] < 50.0

    # Passing configuration
    passing_props = {
        "debuggable": False,
        "allow_backup": False,
        "cleartext_traffic": False,
        "exported_unprotected_components": 0,
        "root_detection_present": True,
        "custom_trust_manager_flaw": False,
        "tapjacking_protected": True,
    }
    clean_report = run_mastg_verification(static_properties=passing_props)
    assert clean_report["failed_count"] == 0
    assert clean_report["compliance_percentage"] >= 90.0


# =====================================================================
# Integration Tests: Runtime Invocation & Capabilities
# =====================================================================


@pytest.mark.asyncio
async def test_phase13i_runtime_tools(runtime: Runtime) -> None:
    # 1. sec_apkleaks_secret_scan
    r1 = await runtime.invoke("sec_apkleaks_secret_scan", {"min_entropy": 2.5})
    assert r1.data["secrets_found_count"] >= 1

    # 2. sec_sensitive_api_taint_trace
    r2 = await runtime.invoke("sec_sensitive_api_taint_trace", {"enforce_strict_gdpr": True})
    assert r2.data["status"] == "analyzed"
    assert len(r2.data["taint_flows"]) >= 2

    # 3. sec_mastg_procedure_run
    r3 = await runtime.invoke("sec_mastg_procedure_run", {})
    assert r3.data["tests_executed"] >= 5

    # 4. dyn_rms_hook_generate
    r4 = await runtime.invoke(
        "dyn_rms_hook_generate",
        {"category": "crypto"},
        profile="dynamic",
    )
    assert r4.data["status"] == "ready"
    assert r4.data["category"] == "crypto"

    # 5. dyn_rms_method_override
    r5 = await runtime.invoke(
        "dyn_rms_method_override",
        {"target_class": "com.target.Security", "target_method": "isTampered"},
        profile="dynamic",
    )
    assert r5.data["status"] == "ready"
    assert r5.data["target_method"] == "isTampered"


@pytest.mark.asyncio
async def test_phase13i_profile_target_counts(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    data = caps.data

    assert data["implemented_tools"] >= 215
    assert data["planned_tools"] >= 215

    profiles = data["profiles"]
    assert profiles["minimal"] == 12
    assert profiles["core"] >= 122
    assert profiles["dynamic"] >= 155
    assert profiles["api"] == 139
    assert profiles["ui"] >= 138
    assert profiles["admin"] >= 18
    assert profiles["full"] >= 215


# =====================================================================
# CLI Tests: Subcommand Execution
# =====================================================================


def test_cli_security_commands(tmp_path: Path) -> None:
    # security apkleaks-scan
    r1 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "security", "apkleaks-scan", "--entropy", "2.0"],
    )
    assert r1.exit_code == 0
    p1 = json.loads(r1.stdout)
    assert p1["data"]["secrets_found_count"] >= 1

    # security taint-trace
    r2 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "security", "taint-trace"],
    )
    assert r2.exit_code == 0
    p2 = json.loads(r2.stdout)
    assert p2["data"]["status"] == "analyzed"

    # security mastg-run
    r3 = runner.invoke(
        app,
        ["--workspace", str(tmp_path), "--json", "security", "mastg-run", "--package", "com.app"],
    )
    assert r3.exit_code == 0
    p3 = json.loads(r3.stdout)
    assert p3["data"]["tests_executed"] >= 5


def test_cli_dynamic_rms_commands(tmp_path: Path) -> None:
    # dynamic rms-hook
    r1 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--profile",
            "dynamic",
            "--json",
            "dynamic",
            "rms-hook",
            "--category",
            "crypto",
        ],
    )
    assert r1.exit_code == 0
    p1 = json.loads(r1.stdout)
    assert p1["data"]["status"] == "ready"

    # dynamic rms-override
    r2 = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--profile",
            "dynamic",
            "--json",
            "dynamic",
            "rms-override",
            "--class",
            "com.app.AntiRoot",
            "--method",
            "isRooted",
            "--return",
            "false",
        ],
    )
    assert r2.exit_code == 0
    p2 = json.loads(r2.stdout)
    assert p2["data"]["status"] == "ready"
    assert p2["data"]["override_active"] is True
