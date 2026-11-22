"""Tests for Phase 10: rebuild, test generation, skills, and admin verification."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime

runner = CliRunner()


def _make_dummy_apk(path: Path) -> Path:
    """Create a minimal APK zip for testing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml",
            '<?xml version="1.0" encoding="utf-8"?>'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.example.test">'
            '<application android:debuggable="false" android:allowBackup="false">'
            '<activity android:name=".MainActivity" android:exported="true">'
            "<intent-filter>"
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/>'
            "</intent-filter>"
            "</activity>"
            "</application>"
            "</manifest>",
        )
        zf.writestr("classes.dex", b"DEX\n035\x00dummy")
    return path


@pytest.fixture
def test_apk(tmp_path: Path) -> Path:
    return _make_dummy_apk(tmp_path / "test_app.apk")


async def test_phase10_test_generate_api(runtime: Runtime, test_apk: Path) -> None:
    created = await runtime.invoke(
        "project_create",
        {
            "name": "Phase10 TestGen",
            "description": "Phase 10 test suite",
            "scopes": [
                "project.read",
                "project.write",
                "static.read",
                "export.write",
                "dynamic.device",
                "android.patch",
                "android.sign",
                "android.install",
            ],
        },
    )
    project_id = created.data["id"]

    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(test_apk)},
    )
    artifact_id = ingested.data["id"]

    # Generate API tests
    test_gen = await runtime.invoke(
        "test_generate",
        {
            "project_id": project_id,
            "artifact_id": artifact_id,
            "test_type": "api",
            "framework": "pytest",
            "operations": [
                {
                    "operation_id": "getUser",
                    "method": "GET",
                    "path": "/api/v1/user",
                    "auth": "bearer",
                }
            ],
        },
    )
    assert test_gen.data["framework"] == "pytest"
    assert "test_id" in test_gen.data
    assert len(test_gen.data["code"]) > 0
    test_id = test_gen.data["test_id"]

    # Run the generated tests (mock target)
    test_run = await runtime.invoke(
        "test_run",
        {
            "project_id": project_id,
            "test_id": test_id,
            "target_url": "http://127.0.0.1:8080",
        },
    )
    assert test_run.data["test_id"] == test_id
    assert test_run.data["status"] == "passed"
    assert test_run.data["total_tests"] >= 1


async def test_phase10_patch_and_sign(runtime: Runtime, test_apk: Path) -> None:
    created = await runtime.invoke(
        "project_create",
        {
            "name": "Phase10 Rebuild",
            "scopes": [
                "project.read",
                "project.write",
                "static.read",
                "export.write",
                "dynamic.device",
                "android.patch",
                "android.sign",
                "android.install",
            ],
        },
    )
    project_id = created.data["id"]

    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(test_apk)},
    )
    artifact_id = ingested.data["id"]

    # Dry run patch
    dry_patch = await runtime.invoke(
        "apk_patch",
        {
            "project_id": project_id,
            "artifact_id": artifact_id,
            "operation": "set_debuggable",
            "dry_run": True,
        },
    )
    assert dry_patch.data["dry_run"] is True
    assert dry_patch.data["success"] is True
    assert dry_patch.data["patched_artifact_id"] is None

    # Real patch
    real_patch = await runtime.invoke(
        "apk_patch",
        {
            "project_id": project_id,
            "artifact_id": artifact_id,
            "operation": "set_debuggable",
            "dry_run": False,
        },
    )
    assert real_patch.data["dry_run"] is False
    assert real_patch.data["success"] is True
    assert real_patch.data["patched_artifact_id"] is not None
    patched_artifact_id = real_patch.data["patched_artifact_id"]

    # Sign patched artifact
    signed = await runtime.invoke(
        "apk_sign",
        {
            "project_id": project_id,
            "artifact_id": patched_artifact_id,
        },
    )
    assert signed.data["signed_artifact_id"] is not None
    assert "v1" in signed.data["signature_schemes"]

    # Behavioral verification comparing base and patched
    verified = await runtime.invoke(
        "verify_behavior",
        {
            "project_id": project_id,
            "base_artifact_id": artifact_id,
            "patched_artifact_id": patched_artifact_id,
            "baseline_events": [{"type": "network_request", "url": "https://api.test.com"}],
            "patched_events": [{"type": "network_request", "url": "https://api.test.com"}],
        },
    )
    assert verified.data["divergence_detected"] is False
    assert len(verified.data["divergent_behaviors"]) == 0


async def test_phase10_skills_and_admin(runtime: Runtime) -> None:
    # Skill discovery tools
    skills = await runtime.invoke("skill_list", {})
    assert skills.data["count"] >= 1
    first_skill_id = skills.data["skills"][0]["id"]

    skill_detail = await runtime.invoke("skill_get", {"skill_id": first_skill_id})
    assert skill_detail.data["id"] == first_skill_id
    assert "content" in skill_detail.data

    # Admin tools
    verify_report = await runtime.invoke("admin_engine_verify", {}, profile="admin")
    assert "verified_count" in verify_report.data
    assert verify_report.data["verified_count"] >= 1

    audit_query = await runtime.invoke("admin_audit_query", {"limit": 10}, profile="admin")
    assert "entries" in audit_query.data
    assert "total" in audit_query.data


def test_phase10_cli_subcommands(tmp_path: Path, test_apk: Path) -> None:
    # CLI project create
    res = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "--json",
            "project",
            "create",
            "CLI Phase 10",
            "--scope",
            "project.read",
            "--scope",
            "project.write",
            "--scope",
            "static.read",
            "--scope",
            "export.write",
            "--scope",
            "dynamic.device",
            "--scope",
            "android.patch",
        ],
    )
    assert res.exit_code == 0
    import json

    project_id = json.loads(res.stdout)["data"]["id"]

    # CLI artifact ingest
    res_ingest = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "--json",
            "artifact",
            "ingest",
            project_id,
            str(test_apk),
        ],
    )
    assert res_ingest.exit_code == 0
    artifact_id = json.loads(res_ingest.stdout)["data"]["id"]

    # CLI test generate
    res_test = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "--json",
            "test",
            "generate",
            project_id,
            artifact_id,
            "--type",
            "api",
            "--framework",
            "pytest",
        ],
    )
    assert res_test.exit_code == 0
    test_id = json.loads(res_test.stdout)["data"]["test_id"]

    # CLI test run
    res_run = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "--json",
            "test",
            "run",
            project_id,
            test_id,
        ],
    )
    assert res_run.exit_code == 0

    # CLI rebuild patch (dry run)
    res_patch = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "--json",
            "rebuild",
            "patch",
            project_id,
            artifact_id,
            "--operation",
            "set_debuggable",
            "--dry-run",
        ],
    )
    assert res_patch.exit_code == 0
    assert json.loads(res_patch.stdout)["data"]["dry_run"] is True

    # CLI admin verify
    res_admin = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "-p",
            "admin",
            "--json",
            "admin",
            "verify",
        ],
    )
    assert res_admin.exit_code == 0

    # CLI admin audit
    res_audit = runner.invoke(
        app,
        [
            "-w",
            str(tmp_path),
            "-p",
            "admin",
            "--json",
            "admin",
            "audit",
            "--limit",
            "5",
        ],
    )
    assert res_audit.exit_code == 0
