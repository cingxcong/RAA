"""MCP surface tests using the registry-backed handlers directly."""

from __future__ import annotations

import json

from mcp.server.lowlevel import Server

from raa.mcp.server import build_http_app, build_server, call_tool_result, list_tools_result
from raa.runtime import Runtime


async def test_lists_tools_for_full_profile(runtime: Runtime) -> None:
    result = await list_tools_result(runtime, "full")
    names = {tool.name for tool in result.tools}
    assert len(result.tools) == 244
    assert {
        "capabilities_get",
        "artifact_ingest",
        "analysis_start",
        "recipe_run",
        "admin_doctor",
        "source_get_file",
    } <= names


async def test_minimal_profile_is_small(runtime: Runtime) -> None:
    result = await list_tools_result(runtime, "minimal")
    assert len(result.tools) == 12
    assert {tool.name for tool in result.tools} == {
        "capabilities_get",
        "project_create",
        "project_get",
        "artifact_ingest",
        "artifact_get_info",
        "analysis_start",
        "analysis_get_status",
        "analysis_get_report",
        "framework_list_detected",
        "packer_detect",
        "android_get_manifest",
        "recipe_run",
    }


async def test_tool_schema_and_annotations(runtime: Runtime) -> None:
    result = await list_tools_result(runtime, "core")
    ingest = next(tool for tool in result.tools if tool.name == "artifact_ingest")
    assert ingest.input_schema["type"] == "object"
    assert "project_id" in ingest.input_schema["properties"]
    assert ingest.annotations is not None
    assert ingest.annotations.read_only_hint is False
    assert ingest.meta is not None
    assert ingest.meta["raa"]["family"] == "artifacts"
    assert "static.read" in ingest.description


async def test_call_tool_success(runtime: Runtime) -> None:
    result = await call_tool_result(runtime, "core", "capabilities_get", {})
    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["tool"] == "capabilities_get"
    payload = json.loads(result.content[0].text)
    assert payload["data"]["name"] == "RAA"


async def test_call_tool_project_flow(runtime: Runtime) -> None:
    created = await call_tool_result(
        runtime,
        "core",
        "project_create",
        {"name": "MCP project"},
    )
    assert created.is_error is False
    project_id = created.structured_content["data"]["id"]

    fetched = await call_tool_result(
        runtime,
        "core",
        "project_get",
        {"project_id": project_id},
    )
    assert fetched.structured_content["data"]["id"] == project_id


async def test_call_tool_error_envelope(runtime: Runtime) -> None:
    result = await call_tool_result(runtime, "core", "missing_tool", {})
    assert result.is_error is True
    assert result.structured_content is not None
    assert result.structured_content["error"]["code"] == "not_found"


async def test_call_tool_profile_error(runtime: Runtime) -> None:
    result = await call_tool_result(runtime, "minimal", "project_list", {})
    assert result.is_error is True
    assert result.structured_content["error"]["code"] == "profile_denied"


async def test_call_tool_validation_error(runtime: Runtime) -> None:
    result = await call_tool_result(runtime, "core", "project_create", {"name": ""})
    assert result.is_error is True
    assert result.structured_content["error"]["code"] == "invalid_arguments"


def test_builders(runtime: Runtime) -> None:
    server = build_server(runtime)
    assert isinstance(server, Server)
    app = build_http_app(runtime)
    assert app is not None
    assert any(getattr(route, "path", "") == "/mcp" for route in app.routes)
