"""Runtime dispatch, profiles, scopes and audit tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raa.errors import InvalidArgumentsError, NotFoundError, PolicyDeniedError, ProfileDeniedError
from raa.runtime import Runtime


async def test_capabilities(runtime: Runtime) -> None:
    envelope = await runtime.invoke("capabilities_get", {})
    data = envelope.data
    assert data["name"] == "RAA"
    assert data["protocol"] == "2026-07-28"
    assert data["implemented_tools"] == 244
    assert data["planned_tools"] == 244
    assert data["profiles"]["minimal"] == 12
    assert data["profiles"]["api"] == 139
    assert data["profiles"]["full"] == 244
    assert "mcp" in data["surfaces"]
    assert envelope.request_id.startswith("req_")


async def test_project_lifecycle(runtime: Runtime) -> None:
    created = await runtime.invoke(
        "project_create",
        {"name": "  Demo project  ", "description": "notes"},
    )
    project = created.data
    assert project["name"] == "Demo project"
    assert project["scopes"] == [
        "project.read",
        "project.write",
        "static.read",
        "export.write",
    ]

    fetched = await runtime.invoke("project_get", {"project_id": project["id"]})
    assert fetched.data["id"] == project["id"]

    listed = await runtime.invoke("project_list", {})
    assert listed.data["count"] == 1


async def test_unknown_tool(runtime: Runtime) -> None:
    with pytest.raises(NotFoundError) as excinfo:
        await runtime.invoke("does_not_exist", {})
    assert excinfo.value.code == "not_found"


async def test_unknown_profile(runtime: Runtime) -> None:
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke("capabilities_get", {}, profile="turbo")


async def test_profile_gating(runtime: Runtime) -> None:
    with pytest.raises(ProfileDeniedError):
        await runtime.invoke("project_list", {}, profile="minimal")


async def test_scope_policy_denies_missing_scope(runtime: Runtime) -> None:
    created = await runtime.invoke("project_create", {"name": "Locked", "scopes": []})
    project_id = created.data["id"]
    with pytest.raises(PolicyDeniedError) as excinfo:
        await runtime.invoke("project_get", {"project_id": project_id})
    assert "project.read" in excinfo.value.details["missing_scopes"]


async def test_argument_validation(runtime: Runtime) -> None:
    with pytest.raises(InvalidArgumentsError) as excinfo:
        await runtime.invoke("project_create", {"name": "", "unexpected": True})
    errors = excinfo.value.details["errors"]
    assert any(error["loc"] == ("name",) or error["loc"] == ["name"] for error in errors)


async def test_missing_project(runtime: Runtime) -> None:
    with pytest.raises(NotFoundError):
        await runtime.invoke("project_get", {"project_id": "prj_missing"})


async def test_audit_log_hashes_arguments(runtime: Runtime) -> None:
    await runtime.invoke("project_create", {"name": "Secret Project", "description": "private"})
    log_path = runtime.workspace.audit_dir / "audit.jsonl"
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert lines
    entry = lines[-1]
    assert entry["tool"] == "project_create"
    assert entry["surface"] == "python"
    assert entry["outcome"] == "ok"
    assert "arguments_sha256" in entry
    assert entry["argument_keys"] == ["description", "name"]
    assert "Secret Project" not in log_path.read_text(encoding="utf-8")


async def test_audit_records_errors(runtime: Runtime) -> None:
    with pytest.raises(NotFoundError):
        await runtime.invoke("nope", {})
    log_path = runtime.workspace.audit_dir / "audit.jsonl"
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["outcome"] == "error"
    assert entry["error_code"] == "not_found"


async def test_admin_tools_and_profiles(runtime: Runtime) -> None:
    doctor = await runtime.invoke("admin_doctor", {})
    assert doctor.data["ok"] is True
    assert doctor.data["implemented_tools"] == 244

    with pytest.raises(ProfileDeniedError):
        await runtime.invoke("admin_engine_list", {})

    engines = await runtime.invoke("admin_engine_list", {}, profile="admin")
    assert engines.data["summary"]["catalogued"] >= 20
    assert len(engines.data["engines"]) == engines.data["summary"]["catalogued"]

    licenses = await runtime.invoke("admin_license_report", {}, profile="admin")
    assert "by_license" in licenses.data
    assert "distribution_classes" in licenses.data


async def test_policy_tool_reports_project_scopes(runtime: Runtime) -> None:
    created = await runtime.invoke("project_create", {"name": "Scoped"})
    project_id = created.data["id"]
    policy = await runtime.invoke("admin_policy_get", {"project_id": project_id})
    assert policy.data["project_scopes"] == [
        "project.read",
        "project.write",
        "static.read",
        "export.write",
    ]
    assert "admin" not in policy.data["default_project_scopes"]


async def test_envelope_metadata(runtime: Runtime) -> None:
    envelope = await runtime.invoke("capabilities_get", {}, surface="test")
    assert envelope.surface == "test"
    assert envelope.profile == "core"
    assert envelope.version == "0.1.0"
    assert envelope.meta["implemented_tools"] == 244


def test_workspace_is_created(runtime: Runtime) -> None:
    assert runtime.workspace.root.is_dir()
    for directory in (
        runtime.workspace.artifacts_dir,
        runtime.workspace.exports_dir,
        runtime.workspace.tmp_dir,
        runtime.workspace.audit_dir,
        runtime.workspace.logs_dir,
    ):
        assert directory.is_dir()


def test_database_file_is_local(runtime: Runtime) -> None:
    database = Path(runtime.database.path)
    assert database.is_file()
    assert database.parent == runtime.workspace.root
