"""MCP server generated from the capability registry.

The low-level server is used deliberately: tool schemas are dynamic, and a
registry-driven surface must not require one Python function per tool.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from starlette.applications import Starlette

from raa.config import ProfileName
from raa.errors import RAAError
from raa.registry.models import ToolSpec
from raa.runtime import Runtime
from raa.version import PROTOCOL_VERSION, __version__

logger = logging.getLogger(__name__)

INSTRUCTIONS = """
RAA (Reverse Android Anything) is an evidence-first Android application analysis
server. Start with capabilities_get to learn the active profile and available
tools. Create a project, ingest an APK/AAB/APKS/XAPK, start an analysis job and
poll analysis_get_status before requesting the report. Every material result
includes evidence identifiers, authority and confidence. Dynamic, network and
mutation tools require explicit project scopes and are disabled by default.
""".strip()


def build_server(
    runtime: Runtime,
    profile: ProfileName | None = None,
) -> Server:
    selected = profile or runtime.settings.profile

    async def on_list_tools(
        context: Any,
        params: Any,
    ) -> types.ListToolsResult:
        del context, params
        return await list_tools_result(runtime, selected)

    async def on_call_tool(
        context: Any,
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        del context
        return await call_tool_result(
            runtime,
            selected,
            params.name,
            params.arguments or {},
        )

    return Server(
        name="raa",
        version=__version__,
        title="RAA - Reverse Android Anything",
        description=(
            "Agent-native Android application intelligence and reverse-engineering server."
        ),
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


async def list_tools_result(
    runtime: Runtime,
    profile: ProfileName,
) -> types.ListToolsResult:
    specs = runtime.registry.for_profile(profile)
    return types.ListToolsResult(tools=[_to_mcp_tool(spec) for spec in specs])


async def call_tool_result(
    runtime: Runtime,
    profile: ProfileName,
    name: str,
    arguments: dict[str, Any],
) -> types.CallToolResult:
    try:
        envelope = await runtime.invoke(
            name,
            arguments,
            profile=profile,
            surface="mcp",
        )
        payload = envelope.model_dump(mode="json")
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(payload, indent=2, ensure_ascii=False))],
            structuredContent=payload,
            isError=False,
        )
    except RAAError as exc:
        payload = {"tool": name, "error": exc.to_dict()}
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(payload, indent=2, ensure_ascii=False))],
            structuredContent=payload,
            isError=True,
        )
    except Exception:
        logger.exception("Unhandled MCP tool failure", extra={"tool": name})
        payload = {
            "tool": name,
            "error": {
                "code": "internal_error",
                "message": "The tool failed unexpectedly.",
                "retryable": False,
            },
        }
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(payload, indent=2, ensure_ascii=False))],
            structuredContent=payload,
            isError=True,
        )


def _to_mcp_tool(spec: ToolSpec) -> types.Tool:
    description = spec.description
    if spec.scopes:
        description += "\n\nRequired scopes: " + ", ".join(sorted(spec.scopes))
    return types.Tool(
        name=spec.name,
        title=spec.title,
        description=description,
        inputSchema=spec.input_schema(),
        annotations=types.ToolAnnotations(
            title=spec.title,
            readOnlyHint=spec.annotations.read_only,
            destructiveHint=spec.annotations.destructive,
            idempotentHint=spec.annotations.idempotent,
            openWorldHint=spec.annotations.open_world,
        ),
        _meta={
            "raa": {
                "family": spec.family,
                "cost": spec.cost,
                "device_required": spec.device_required,
                "mutates_artifact": spec.mutates_artifact,
                "scopes": sorted(spec.scopes),
                "protocol_baseline": PROTOCOL_VERSION,
            }
        },
    )


async def run_stdio(runtime: Runtime, profile: ProfileName | None = None) -> None:
    server = build_server(runtime, profile)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def build_http_app(
    runtime: Runtime,
    profile: ProfileName | None = None,
    *,
    host: str = "127.0.0.1",
    path: str = "/mcp",
) -> Starlette:
    return build_server(runtime, profile).streamable_http_app(
        streamable_http_path=path,
        host=host,
    )
