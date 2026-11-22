"""Burp Suite MCP Bridge & Dynamic Interceptor Adapter.

Inspired by burp-ai-agent: connects Burp Suite directly to RAA's MCP capabilities,
allowing Burp Suite to invoke RAA reversing and bypass tools, and streaming live
traffic from Burp into RAA for autonomous vulnerability inspection.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

DEFAULT_BURP_TOOLS = [
    "api_bypass_403_test",
    "wasm_decompile",
    "api_semantic_waf_audit",
    "sec_bugbounty_report_format",
    "dyn_wireguard_tunnel_start",
    "net_cti_reputation_check",
    "sec_poc_validate",
]


def configure_burp_mcp_bridge(
    burp_api_url: str = "http://127.0.0.1:1337",
    bridge_port: int = 8999,
    export_tools: list[str] | None = None,
    sync_scope: list[str] | None = None,
    enable_active_scan_hook: bool = True,
) -> dict[str, Any]:
    """Configure a bidirectional MCP bridge between Burp Suite and RAA."""
    timestamp = int(time.time())
    active_tools = export_tools or DEFAULT_BURP_TOOLS
    scope_rules = sync_scope or ["*.example.com", "api.*"]

    digest = hashlib.sha256(f"{burp_api_url}:{bridge_port}".encode()).hexdigest()[:10]
    bridge_id = f"burp-br-{digest}"

    extension_config = {
        "extension_name": "RAA Burp MCP Bridge",
        "version": "1.8.0",
        "bridge_id": bridge_id,
        "burp_upstream_api": burp_api_url,
        "mcp_listener": f"http://127.0.0.1:{bridge_port}/mcp",
        "registered_tools_count": len(active_tools),
        "exported_tools": active_tools,
        "scope_filters": scope_rules,
        "active_scan_integration": enable_active_scan_hook,
        "auto_audit_on_traffic": True,
    }

    # Generate ready-to-import Montoya API / Jython script snippet
    extension_script = (
        f"# RAA Burp Suite Montoya MCP Bridge Connector\n"
        f"# Bridge ID: {bridge_id}\n"
        f"# Connects Burp Suite to RAA MCP server at 127.0.0.1:{bridge_port}\n"
        f"BURP_API = '{burp_api_url}'\n"
        f"RAA_MCP_URL = 'http://127.0.0.1:{bridge_port}/mcp'\n"
        f"ENABLED_TOOLS = {active_tools}\n"
    )

    return {
        "bridge_id": bridge_id,
        "status": "configured",
        "burp_api_url": burp_api_url,
        "bridge_port": bridge_port,
        "mcp_endpoint": f"http://127.0.0.1:{bridge_port}/mcp",
        "exported_tools": active_tools,
        "sync_scope": scope_rules,
        "extension_config": extension_config,
        "extension_script": extension_script,
        "created_at": timestamp,
    }
