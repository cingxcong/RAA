"""Phase 13E test suite: Search-First MCP, WASM Decompiler, 403 Bypass, Wireless Fleet & ZTNA.

Validates service logic, runtime capability registration, profile counts (193 tools),
and CLI commands for all 5 Phase 13E tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.admin.ztna_gateway import configure_ztna_gateway
from raa.services.android.adb_fleet import discover_adb_fleet
from raa.services.api.bypass_403 import generate_403_bypass_mutations
from raa.services.mcp.tool_search import search_tools
from raa.services.source.wasm_decompiler import decompile_wasm

runner = CliRunner()


# =====================================================================
# Unit Tests: Services
# =====================================================================


def test_service_search_tools(runtime: Runtime) -> None:
    res = search_tools(registry=runtime.registry, query="frida hook", limit=5)
    assert res["status"] == "SEARCH_COMPLETE"
    assert res["total_matched"] > 0
    assert len(res["tools"]) <= 5
    first = res["tools"][0]
    assert "name" in first
    assert "relevance_score" in first
    assert first["relevance_score"] > 0


def test_service_wasm_decompiler() -> None:
    # Minimal WebAssembly binary: \0asm\1\0\0\0
    dummy_wasm = b"\x00asm\x01\x00\x00\x00"
    res = decompile_wasm(wasm_bytes_or_hex=dummy_wasm)
    assert res["status"] == "DECOMPILE_COMPLETE"
    assert res["is_valid_wasm"] is True
    assert res["byte_size"] == 8
    assert "(module" in res["wat_representation"]


def test_service_bypass_403() -> None:
    res = generate_403_bypass_mutations(
        target_url="https://api.example.com/v1/admin/users",
        http_method="GET",
        base_headers={"Authorization": "Bearer token123"},
    )
    assert res["status"] == "MUTATIONS_GENERATED"
    assert res["total_mutations"] >= 20
    assert "HEADER_OVERRIDE" in res["categories_breakdown"]
    assert "PATH_TAMPERING" in res["categories_breakdown"]
    assert "METHOD_TAMPERING" in res["categories_breakdown"]
    sample = res["mutations"][0]
    assert "curl_command" in sample
    assert "https://api.example.com" in sample["url"]


def test_service_adb_fleet() -> None:
    res = discover_adb_fleet(subnet_cidr="192.168.1.0/28", max_hosts=10)
    assert res["status"] == "FLEET_DISCOVERY_COMPLETE"
    assert res["total_hosts_evaluated"] > 0
    assert res["active_devices_count"] >= 1
    device = res["discovered_devices"][0]
    assert "endpoint" in device
    assert "connect_command" in device
    assert "adb connect" in res["batch_connect_script"]


def test_service_ztna_gateway() -> None:
    res = configure_ztna_gateway(
        server_name="test-mcp-gateway",
        listen_port=9443,
        allowed_clients=["claude-code", "cursor"],
    )
    assert res["status"] == "ZTNA_GATEWAY_CONFIGURED"
    assert res["listen_port"] == 9443
    assert "https://127.0.0.1:9443/mcp" in res["gateway_url"]
    assert "raa_ztna_" in res["auth_token"]
    assert "cursor_mcp_config" in res
    assert "claude_code_command" in res


# =====================================================================
# Integration Tests: Runtime Invocation & Tool Registration
# =====================================================================


@pytest.mark.asyncio
async def test_phase13e_runtime_tool_invocations(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 193
    assert caps.data["planned_tools"] >= 193
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 113
    assert caps.data["profiles"]["dynamic"] >= 136
    assert caps.data["profiles"]["api"] >= 136
    assert caps.data["profiles"]["ui"] >= 135
    assert caps.data["profiles"]["admin"] >= 18
    assert caps.data["profiles"]["full"] >= 193

    # 1. mcp_tool_search (core, dynamic, api, ui, full)
    search_res = await runtime.invoke(
        "mcp_tool_search",
        {"query": "wasm", "limit": 3},
    )
    assert search_res.data["status"] == "SEARCH_COMPLETE"
    assert any(t["name"] == "wasm_decompile" for t in search_res.data["tools"])

    # 2. wasm_decompile (core, dynamic, api, ui, full)
    wasm_res = await runtime.invoke(
        "wasm_decompile",
        {"wasm_bytes_hex": "0061736d01000000"},
    )
    assert wasm_res.data["status"] == "DECOMPILE_COMPLETE"
    assert wasm_res.data["is_valid_wasm"] is True

    # 3. api_bypass_403_test (api, full)
    bypass_res = await runtime.invoke(
        "api_bypass_403_test",
        {"target_url": "https://api.internal/v1/metrics", "http_method": "GET"},
        profile="api",
    )
    assert bypass_res.data["status"] == "MUTATIONS_GENERATED"
    assert bypass_res.data["total_mutations"] > 10

    # 4. dyn_adb_fleet_discover (dynamic, full)
    fleet_res = await runtime.invoke(
        "dyn_adb_fleet_discover",
        {"subnet_cidr": "10.0.0.1,10.0.0.2"},
        profile="dynamic",
    )
    assert fleet_res.data["status"] == "FLEET_DISCOVERY_COMPLETE"

    # 5. admin_ztna_tunnel_config (admin, full)
    ztna_res = await runtime.invoke(
        "admin_ztna_tunnel_config",
        {"server_name": "corp-mcp", "listen_port": 8443},
        profile="admin",
    )
    assert ztna_res.data["status"] == "ZTNA_GATEWAY_CONFIGURED"


# =====================================================================
# CLI Tests
# =====================================================================


def test_cli_tools_search(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "tools",
            "search",
            "wireguard",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "SEARCH_COMPLETE"
    assert payload["total_matched"] > 0


def test_cli_wasm_decompile(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "source",
            "wasm-decompile",
            "--hex",
            "0061736d01000000",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "DECOMPILE_COMPLETE"
    assert payload["is_valid_wasm"] is True


def test_cli_bypass_403(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "bypass-403",
            "https://api.bank.com/v1/accounts/me",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "MUTATIONS_GENERATED"
    assert payload["total_mutations"] >= 15


def test_cli_fleet_discover(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "dynamic",
            "fleet-discover",
            "--subnet",
            "192.168.1.100",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "FLEET_DISCOVERY_COMPLETE"


def test_cli_ztna_config(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "admin",
            "ztna-config",
            "--name",
            "my-ztna-gateway",
            "--port",
            "8443",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)["data"]
    assert payload["status"] == "ZTNA_GATEWAY_CONFIGURED"
