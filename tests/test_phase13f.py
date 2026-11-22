"""Phase 13F Integration & Unit Tests.

Covers:
- Cloud Gateway IP Rotator & Anti-Rate-Limit Engine (api_rotating_proxy_session)
- Burp Suite MCP Bridge Configurator (dyn_burp_mcp_bridge)
- Passive AI Traffic Inspector & PII Redaction Engine (dyn_traffic_passive_audit)
- P2P Encrypted Remote Device Tunnel (dyn_p2p_device_tunnel)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.p2p_tunnel import establish_p2p_device_tunnel
from raa.services.api.burp_bridge import configure_burp_mcp_bridge
from raa.services.api.ip_rotator import create_rotating_proxy_session
from raa.services.api.traffic_audit import audit_passive_traffic, redact_sensitive_traffic

runner = CliRunner()


# =====================================================================
# Unit Tests: Service Layer
# =====================================================================


def test_service_ip_rotator() -> None:
    res = create_rotating_proxy_session(
        target_url="https://api.targetbank.com/v1",
        regions=["us-east-1", "eu-west-1", "ap-southeast-1"],
        provider="aws_api_gateway",
        max_retries=3,
        backoff_factor=2.0,
    )
    assert res["status"] == "active"
    assert res["target_url"] == "https://api.targetbank.com/v1"
    assert res["regions_count"] == 3
    assert len(res["gateway_pool"]) == 3
    assert res["rotation_policy"]["max_retries"] == 3
    assert "curl" in res["curl_sample"]


def test_service_burp_bridge() -> None:
    res = configure_burp_mcp_bridge(
        burp_api_url="http://127.0.0.1:1337",
        bridge_port=8999,
        export_tools=["api_bypass_403_test", "wasm_decompile"],
        sync_scope=["*.target.com"],
    )
    assert res["status"] == "configured"
    assert res["bridge_port"] == 8999
    assert res["exported_tools"] == ["api_bypass_403_test", "wasm_decompile"]
    assert "http://127.0.0.1:8999/mcp" in res["mcp_endpoint"]
    assert "Montoya" in res["extension_script"]


def test_service_traffic_audit() -> None:
    # Test PII redaction directly
    sample_text = (
        "User user@example.com with token Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc12345 "
        "and password 1234-5678-9012-3456"
    )
    redacted, count = redact_sensitive_traffic(sample_text)
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_CCN]" in redacted
    assert count >= 2

    # Test full passive flow audit
    mock_flows = [
        {
            "url": "https://api.target.com/users/profile?user_id=1024&token=secret_abc_123",
            "method": "GET",
            "response_headers": {"Set-Cookie": "session_id=abc; Path=/"},
            "response_body": '{"email": "analyst@test.com", "apiKey": "supersecretkey123"}',
        },
        {
            "url": "https://api.target.com/actuator/env",
            "method": "GET",
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"env": "prod"}',
        },
    ]

    res = audit_passive_traffic(
        requests=mock_flows, target_domain="api.target.com", redact_pii=True
    )
    assert res["flows_analyzed"] == 2
    assert res["findings_count"] >= 3
    assert res["total_pii_redactions"] >= 1
    categories = {f["category"] for f in res["findings"]}
    assert "Missing Security Headers" in categories
    assert "Insecure Cookie Attributes" in categories
    assert "IDOR / BOLA Parameter Exposure" in categories
    assert "Exposed Administrative Surface" in categories


def test_service_p2p_tunnel() -> None:
    res = establish_p2p_device_tunnel(
        device_id="pixel8-remote-01",
        tunnel_type="iroh_p2p",
        relay_node="relay.target.com",
        local_listen_port=55555,
    )
    assert res["status"] == "connected_ready"
    assert res["device_id"] == "pixel8-remote-01"
    assert res["local_endpoint"] == "127.0.0.1:55555"
    assert "adb connect 127.0.0.1:55555" in res["adb_connect_command"]
    assert "raa-p2p-agent" in res["on_device_agent_command"]


# =====================================================================
# Integration Tests: Runtime Invocation & Capabilities
# =====================================================================


@pytest.mark.asyncio
async def test_phase13f_runtime_tool_invocations(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 197
    assert caps.data["planned_tools"] >= 197
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 113
    assert caps.data["profiles"]["dynamic"] >= 139
    assert caps.data["profiles"]["api"] >= 139
    assert caps.data["profiles"]["ui"] >= 135
    assert caps.data["profiles"]["admin"] >= 18
    assert caps.data["profiles"]["full"] >= 197

    # 1. api_rotating_proxy_session (api, full)
    rot_res = await runtime.invoke(
        "api_rotating_proxy_session",
        {"target_url": "https://api.targetbank.com"},
        profile="api",
    )
    assert rot_res.data["status"] == "active"
    assert rot_res.data["regions_count"] >= 3

    # 2. dyn_burp_mcp_bridge (dynamic, api, full)
    burp_res = await runtime.invoke(
        "dyn_burp_mcp_bridge",
        {"burp_api_url": "http://127.0.0.1:1337", "bridge_port": 8999},
        profile="dynamic",
    )
    assert burp_res.data["status"] == "configured"
    assert burp_res.data["bridge_port"] == 8999

    # 3. dyn_traffic_passive_audit (dynamic, api, full)
    audit_res = await runtime.invoke(
        "dyn_traffic_passive_audit",
        {
            "requests": [
                {
                    "url": "https://api.target.com/admin/settings",
                    "method": "GET",
                    "response_headers": {},
                }
            ],
            "redact_pii": True,
        },
        profile="api",
    )
    assert audit_res.data["flows_analyzed"] == 1
    assert audit_res.data["findings_count"] >= 1

    # 4. dyn_p2p_device_tunnel (dynamic, full)
    tun_res = await runtime.invoke(
        "dyn_p2p_device_tunnel",
        {"device_id": "galaxy-s24-tokyo", "local_listen_port": 55555},
        profile="dynamic",
    )
    assert tun_res.data["status"] == "connected_ready"
    assert tun_res.data["device_id"] == "galaxy-s24-tokyo"


# =====================================================================
# CLI Tests
# =====================================================================


def test_cli_api_proxy_rotate(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "proxy-rotate",
            "https://target.com/api",
            "--region",
            "us-east-1",
            "--region",
            "eu-west-1",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "active"
    assert data["data"]["regions_count"] == 2


def test_cli_dynamic_burp_bridge(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "burp-bridge",
            "--burp-url",
            "http://127.0.0.1:1337",
            "--port",
            "8999",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "configured"
    assert data["data"]["bridge_port"] == 8999


def test_cli_dynamic_traffic_audit(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "traffic-audit",
            "--domain",
            "api.target.com",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["flows_analyzed"] == 0
    assert data["data"]["pii_redaction_enabled"] is True


def test_cli_dynamic_p2p_tunnel(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "p2p-tunnel",
            "pixel8-remote-tokyo",
            "--port",
            "55555",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["data"]["status"] == "connected_ready"
    assert data["data"]["device_id"] == "pixel8-remote-tokyo"
