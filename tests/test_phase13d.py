"""Phase 13D test suite: WireGuard Tunnel, Bug Bounty VRT, CTI Intel, Semantic WAF.

Validates service logic, runtime capability registration, and CLI commands
for all 6 Phase 13D tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.wireguard_tunnel import start_wireguard_tunnel, stop_wireguard_tunnel
from raa.services.api.cti_intel import check_cti_reputation, check_leaked_email_intel
from raa.services.api.semantic_waf import audit_semantic_waf
from raa.services.security.bugbounty_reporter import format_bugbounty_report

runner = CliRunner()


# =====================================================================
# Unit Tests: Services
# =====================================================================


def test_service_format_bugbounty_report() -> None:
    res = format_bugbounty_report(
        title="Account Takeover via Insecure Direct Object Reference",
        vulnerability_type="IDOR",
        severity="High",
        target="com.example.bank.ui.AccountActivity",
        description="User ID parameter in account profile fetch can be manipulated.",
        steps_to_reproduce=[
            "Intercept GET /api/v1/user/1001",
            "Change user_id to 1002",
            "Observe PII of victim user returned in response",
        ],
        impact="Full account takeover and PII disclosure of arbitrary users.",
        platform="HackerOne",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        remediation="Enforce server-side authorization checks on session token.",
        poc_code="curl -H 'Authorization: Bearer test' https://api.bank.com/user/1002",
    )
    assert res["status"] == "REPORT_GENERATED"
    assert res["platform"] == "HackerOne"
    assert res["severity"] == "High"
    assert "VRT:IDOR" in res["vrt_classification"]
    assert res["cvss_score"] == 8.1
    assert "## Summary" in res["markdown_report"]
    assert "## Steps to Reproduce" in res["markdown_report"]


def test_service_wireguard_tunnel() -> None:
    start_res = start_wireguard_tunnel(
        target_package="com.secure.banking",
        device_id="emulator-5554",
        interface_name="wg0",
        listen_port=51820,
        proxy_port=8080,
    )
    assert start_res["status"] == "TUNNEL_ACTIVE_OR_CONFIGURED"
    assert start_res["target_package"] == "com.secure.banking"
    assert len(start_res["adb_setup_commands"]) >= 3
    assert "wg0" in start_res["interface_name"]
    assert start_res["server_public_key"] is not None

    stop_res = stop_wireguard_tunnel(
        target_package="com.secure.banking",
        device_id="emulator-5554",
        interface_name="wg0",
    )
    assert stop_res["status"] == "TUNNEL_STOPPED"
    assert stop_res["restored_routing"] is True
    assert len(stop_res["teardown_commands"]) >= 3


def test_service_cti_reputation() -> None:
    res = check_cti_reputation(
        targets=["198.51.100.25", "c2-tracker.duckdns.org", "api.stripe.com"],
        threat_threshold=40,
    )
    assert res["status"] == "CTI_CHECK_COMPLETE"
    assert res["total_targets"] == 3
    assert res["flagged_targets"] >= 2

    flagged = [r for r in res["results"] if r["reputation_score"] >= 40]
    assert any("KNOWN_MALICIOUS_SUBNET" in f["categories"] for f in flagged)
    assert any("DYNAMIC_DNS_OR_TUNNEL_PROXY" in f["categories"] for f in flagged)


def test_service_leaked_email_intel() -> None:
    res = check_leaked_email_intel(
        emails=["developer@example.com", "security-lead@fintech.io"],
    )
    assert res["status"] == "EMAIL_INTEL_COMPLETE"
    assert res["total_emails"] == 2
    for finding in res["findings"]:
        assert len(finding["registered_platforms"]) >= 1
        assert finding["risk_level"] in ("LOW", "MEDIUM", "HIGH")
        assert "recommendation" in finding


def test_service_semantic_waf_audit() -> None:
    clean_res = audit_semantic_waf(
        endpoint_url="https://api.example.com/v1/products?category=electronics&limit=10",
        http_method="GET",
    )
    assert clean_res["status"] == "AUDIT_COMPLETE"
    assert clean_res["risk_level"] == "CLEAN"
    assert clean_res["blocked_by_waf"] is False

    sqli_res = audit_semantic_waf(
        endpoint_url="https://api.example.com/v1/users?id=1' OR '1'='1",
        http_method="GET",
    )
    assert sqli_res["risk_level"] == "CRITICAL"
    assert sqli_res["blocked_by_waf"] is True
    assert any(a["type"] == "SQLI_TAUTOLOGY" for a in sqli_res["anomalies"])

    cmdi_res = audit_semantic_waf(
        endpoint_url="https://api.example.com/v1/render",
        http_method="POST",
        request_body="filename=report.pdf; cat /etc/passwd",
    )
    assert cmdi_res["risk_level"] == "CRITICAL"
    assert any(a["type"] == "COMMAND_INJECTION" for a in cmdi_res["anomalies"])

    nosqli_res = audit_semantic_waf(
        endpoint_url="https://api.example.com/v1/auth/login",
        http_method="POST",
        request_body={"username": {"$ne": "admin"}, "password": {"$gt": ""}},
    )
    assert nosqli_res["risk_level"] in ("HIGH", "CRITICAL")
    assert any(a["type"] == "NOSQL_OPERATOR_INJECTION" for a in nosqli_res["anomalies"])


# =====================================================================
# Integration Tests: Runtime Invocation & Tool Registration
# =====================================================================


@pytest.mark.asyncio
async def test_phase13d_runtime_tool_invocations(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 188
    assert caps.data["planned_tools"] >= 188
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 111
    assert caps.data["profiles"]["dynamic"] >= 133
    assert caps.data["profiles"]["api"] >= 133
    assert caps.data["profiles"]["ui"] >= 133
    assert caps.data["profiles"]["admin"] >= 17
    assert caps.data["profiles"]["full"] >= 188

    # 1. sec_bugbounty_report_format (in admin & full)
    bounty_res = await runtime.invoke(
        "sec_bugbounty_report_format",
        {
            "title": "OAuth Token Exfiltration",
            "vulnerability_type": "OAuth",
            "severity": "Critical",
            "target": "com.example.app.AuthCallbackActivity",
            "description": "Callback URI validation allows wildcard host matching.",
            "steps_to_reproduce": ["Launch intent with attacker callback", "Observe token leak"],
            "impact": "Account takeover",
            "platform": "Bugcrowd",
        },
        profile="admin",
    )
    assert bounty_res.data["platform"] == "Bugcrowd"
    assert "markdown_report" in bounty_res.data

    # 2. dyn_wireguard_tunnel_start (in dynamic & full)
    wg_start = await runtime.invoke(
        "dyn_wireguard_tunnel_start",
        {"target_package": "com.test.app"},
        profile="dynamic",
    )
    assert wg_start.data["status"] == "TUNNEL_ACTIVE_OR_CONFIGURED"

    # 3. dyn_wireguard_tunnel_stop (in dynamic & full)
    wg_stop = await runtime.invoke(
        "dyn_wireguard_tunnel_stop",
        {"target_package": "com.test.app"},
        profile="dynamic",
    )
    assert wg_stop.data["status"] == "TUNNEL_STOPPED"

    # 4. net_cti_reputation_check (in api & full)
    cti_res = await runtime.invoke(
        "net_cti_reputation_check",
        {"targets": ["c2-evil.ngrok.io", "8.8.8.8"]},
        profile="api",
    )
    assert cti_res.data["status"] == "CTI_CHECK_COMPLETE"

    # 5. sec_leaked_email_intel (in core & full)
    email_res = await runtime.invoke(
        "sec_leaked_email_intel",
        {"emails": ["secops@megacorp.internal"]},
    )
    assert email_res.data["status"] == "EMAIL_INTEL_COMPLETE"

    # 6. api_semantic_waf_audit (in api & full)
    waf_res = await runtime.invoke(
        "api_semantic_waf_audit",
        {
            "endpoint_url": "https://api.example.com/v1/search?q=1; DROP TABLE users--",
            "http_method": "GET",
        },
        profile="api",
    )
    assert waf_res.data["status"] == "AUDIT_COMPLETE"
    assert waf_res.data["blocked_by_waf"] is True


# =====================================================================
# CLI Tests
# =====================================================================


def test_cli_bugbounty_report(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "security",
            "bugbounty-report",
            "Deep Link CSRF Account Deletion",
            "--type",
            "CSRF",
            "--severity",
            "High",
            "--target",
            "com.example.app.DeleteActivity",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "REPORT_GENERATED"
    assert "VRT:CSRF" in payload["vrt_classification"]


def test_cli_email_intel(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "security",
            "email-intel",
            "dev1@example.com",
            "dev2@example.com",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "EMAIL_INTEL_COMPLETE"
    assert payload["total_emails"] == 2


def test_cli_wireguard_commands(tmp_path: Path) -> None:
    start = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "wireguard-start",
            "--package",
            "com.bank.app",
        ],
    )
    assert start.exit_code == 0
    payload_start = json.loads(start.stdout)["data"]
    assert payload_start["status"] == "TUNNEL_ACTIVE_OR_CONFIGURED"

    stop = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "wireguard-stop",
            "--package",
            "com.bank.app",
        ],
    )
    assert stop.exit_code == 0
    payload_stop = json.loads(stop.stdout)["data"]
    assert payload_stop["status"] == "TUNNEL_STOPPED"


def test_cli_cti_check(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "cti-check",
            "198.51.100.12",
            "tunnel.serveo.net",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "CTI_CHECK_COMPLETE"
    assert payload["total_targets"] == 2


def test_cli_semantic_waf(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "semantic-waf",
            "https://api.example.com/api/v1/eval",
            "--method",
            "POST",
            "--body",
            "expr=__import__('os').system('id')",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "AUDIT_COMPLETE"
