"""Workspace path handling and policy primitives."""

from __future__ import annotations

from pathlib import Path

import pytest

from raa.errors import InvalidArgumentsError, PolicyDeniedError
from raa.policy.scopes import (
    ALL_SCOPES,
    PolicyEngine,
    normalize_scopes,
)
from raa.services.workspace import Workspace, sanitize_filename


def test_sanitize_filename_removes_path_components() -> None:
    assert sanitize_filename("../evil.apk") == "evil.apk"
    assert sanitize_filename("..\\evil.apk") == "evil.apk"
    assert sanitize_filename('bad<>:"|?*name.apk') == "bad_______name.apk"


def test_sanitize_filename_handles_reserved_names() -> None:
    assert sanitize_filename("CON") == "_CON"
    assert sanitize_filename("lpt1.apk") == "_lpt1.apk"


def test_sanitize_filename_handles_empty_input() -> None:
    assert sanitize_filename("   ") == "artifact.bin"


def test_export_path_stays_in_workspace(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    workspace.ensure()
    path = workspace.export_path("prj_demo", "../../escape.json")
    assert path.parent == workspace.exports_dir / "prj_demo"
    assert path.name == "escape.json"


def test_stored_path_rejects_escape(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    workspace.ensure()
    with pytest.raises(PolicyDeniedError):
        workspace.stored_path("../outside.bin")


def test_check_input_path_rejects_outside_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"PK")
    workspace = Workspace(tmp_path / "workspace")
    with pytest.raises(PolicyDeniedError):
        workspace.check_input_path(str(outside), [allowed])


def test_check_input_path_rejects_directories(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    with pytest.raises(InvalidArgumentsError):
        workspace.check_input_path(str(tmp_path), [tmp_path])


def test_check_input_path_rejects_missing_file(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    with pytest.raises(InvalidArgumentsError):
        workspace.check_input_path(str(tmp_path / "missing.apk"), [tmp_path])


def test_normalize_scopes_deduplicates() -> None:
    assert normalize_scopes(["project.read", "project.read", "static.read"]) == [
        "project.read",
        "static.read",
    ]


def test_normalize_scopes_rejects_unknown() -> None:
    with pytest.raises(InvalidArgumentsError) as excinfo:
        normalize_scopes(["project.read", "root.everything"])
    assert excinfo.value.details["unknown"] == ["root.everything"]


def test_policy_engine_is_fail_closed() -> None:
    engine = PolicyEngine()
    denied = engine.evaluate({"project.read", "export.write"}, {"project.read"})
    assert denied.allowed is False
    assert denied.missing == frozenset({"export.write"})
    assert "export.write" in (denied.reason or "")

    allowed = engine.evaluate({"project.read"}, {"project.read", "project.write"})
    assert allowed.allowed is True


def test_all_scopes_include_defaults() -> None:
    assert {"project.read", "project.write", "static.read", "export.write"} <= ALL_SCOPES
