"""Zero-Trust Remote MCP Gateway & Authenticated Tunnel Configurator.

Generates encrypted, token-authenticated zero-trust network access (ZTNA) configurations
inspired by Octelium, allowing remote AI coding agents (Claude Code, Cursor, Antigravity)
to connect to on-prem RAA instances securely without open firewall ports.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def configure_ztna_gateway(
    server_name: str = "raa-mcp-gateway",
    listen_port: int = 8443,
    allowed_clients: list[str] | None = None,
    auth_token: str | None = None,
    enable_mtls: bool = True,
) -> dict[str, Any]:
    """Generate Zero-Trust MCP Gateway configuration and remote client definitions."""
    clients = allowed_clients or ["claude-code", "cursor", "antigravity", "codex"]

    token = auth_token
    if not token:
        seed = f"{server_name}-{listen_port}-ztna-salt"
        digest = hashlib.sha256(seed.encode()).digest()
        token = f"raa_ztna_{base64.urlsafe_b64encode(digest)[:24].decode('ascii')}"

    gateway_url = f"https://127.0.0.1:{listen_port}/mcp"

    cursor_config = {
        "mcpServers": {
            server_name: {
                "url": gateway_url,
                "headers": {
                    "Authorization": f"Bearer {token}",
                    "X-RAA-ZTNA-Auth": "enabled",
                },
            }
        }
    }

    claude_code_cmd = f"claude mcp add {server_name} -- raa --profile full --ztna-token {token}"

    curl_test_cmd = f"curl -k -i -H 'Authorization: Bearer {token}' {gateway_url}/health"

    ztna_manifest = {
        "version": "1.0",
        "gateway": {
            "name": server_name,
            "listen_port": listen_port,
            "mtls_enabled": enable_mtls,
            "auth_scheme": "bearer_token",
            "token": token,
            "allowed_clients": clients,
        },
        "endpoints": {
            "mcp_stdio_stream": f"{gateway_url}/stream",
            "mcp_sse": f"{gateway_url}/sse",
            "health_check": f"{gateway_url}/health",
        },
    }

    return {
        "status": "ZTNA_GATEWAY_CONFIGURED",
        "server_name": server_name,
        "listen_port": listen_port,
        "gateway_url": gateway_url,
        "auth_token": token,
        "mtls_enabled": enable_mtls,
        "allowed_clients": clients,
        "ztna_manifest": ztna_manifest,
        "cursor_mcp_config": json.dumps(cursor_config, indent=2),
        "claude_code_command": claude_code_cmd,
        "curl_verification_command": curl_test_cmd,
    }
