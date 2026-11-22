"""End-to-end artifact, analysis, evidence and recipe tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from raa.errors import InvalidArgumentsError, NotFoundError, StateError
from raa.runtime import Runtime


async def _create_project(runtime: Runtime, name: str = "Triage") -> str:
    created = await runtime.invoke("project_create", {"name": name})
    return created.data["id"]


async def _ingest(runtime: Runtime, project_id: str, path: Path) -> dict:
    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project_id, "path": str(path)},
    )
    return {"data": ingested.data, "evidence_ids": ingested.evidence_ids}


async def _analyze(runtime: Runtime, project_id: str, artifact_id: str) -> tuple[str, dict]:
    started = await runtime.invoke(
        "analysis_start",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    assert job.status.value == "completed"
    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job.id},
    )
    return job.id, report.data


async def test_ingest_hashes_and_records_evidence(
    runtime: Runtime,
    apk_path: Path,
) -> None:
    project_id = await _create_project(runtime)
    ingested = await _ingest(runtime, project_id, apk_path)
    artifact = ingested["data"]

    assert artifact["project_id"] == project_id
    assert artifact["artifact_type"] == "apk"
    assert artifact["filename"] == "sample.apk"
    assert artifact["sha256"] == hashlib.sha256(apk_path.read_bytes()).hexdigest()
    assert artifact["size_bytes"] == apk_path.stat().st_size
    assert len(ingested["evidence_ids"]) == 2

    info = await runtime.invoke(
        "artifact_get_info",
        {"project_id": project_id, "artifact_id": artifact["id"]},
    )
    assert info.data["sha256"] == artifact["sha256"]

    listed = await runtime.invoke("artifact_list", {"project_id": project_id})
    assert listed.data["count"] == 1

    evidence = await runtime.invoke(
        "evidence_list",
        {"project_id": project_id, "artifact_id": artifact["id"]},
    )
    kinds = {item["kind"] for item in evidence.data["items"]}
    assert {"artifact.hash", "artifact.container"} <= kinds


async def test_missing_artifact_input_is_rejected(runtime: Runtime, tmp_path: Path) -> None:
    project_id = await _create_project(runtime)
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "artifact_ingest",
            {"project_id": project_id, "path": str(tmp_path / "missing.apk")},
        )


async def test_artifact_belongs_to_project(runtime: Runtime, apk_path: Path) -> None:
    first = await _create_project(runtime, "First")
    second = await _create_project(runtime, "Second")
    ingested = await _ingest(runtime, first, apk_path)
    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "artifact_get_info",
            {"project_id": second, "artifact_id": ingested["data"]["id"]},
        )


async def test_full_analysis_flow(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    ingested = await _ingest(runtime, project_id, apk_path)
    artifact = ingested["data"]

    job_id, report = await _analyze(runtime, project_id, artifact["id"])

    assert report["artifact_type"] == "apk"
    assert report["sha256"] == artifact["sha256"]
    assert report["summary"]["dex_count"] == 2
    assert report["summary"]["native_library_count"] == 2
    assert report["summary"]["abis"] == ["arm64-v8a"]
    assert report["signature"]["status"] == "signed_v1"
    assert "flutter" in {item["id"] for item in report["frameworks"]}
    assert report["findings"]
    assert report["evidence_ids"]
    assert report["coverage"]["limitations"]

    status = await runtime.invoke(
        "analysis_get_status",
        {"project_id": project_id, "job_id": job_id},
    )
    assert status.data["status"] == "completed"
    assert status.data["progress"] == 1.0

    dex = await runtime.invoke(
        "android_list_dex",
        {"project_id": project_id, "job_id": job_id},
    )
    assert dex.data["count"] == 2

    native = await runtime.invoke(
        "android_list_native_libraries",
        {"project_id": project_id, "job_id": job_id},
    )
    assert native.data["abis"] == ["arm64-v8a"]
    assert native.data["count"] == 2

    certificate = await runtime.invoke(
        "android_get_certificate_info",
        {"project_id": project_id, "job_id": job_id},
    )
    assert certificate.data["v1_certificates"] == ["META-INF/CERT.RSA"]

    frameworks = await runtime.invoke(
        "framework_list_detected",
        {"project_id": project_id, "job_id": job_id},
    )
    assert frameworks.data["count"] >= 1

    packers = await runtime.invoke(
        "packer_detect",
        {"project_id": project_id, "job_id": job_id},
    )
    assert packers.data["count"] == 0
    assert packers.data["method"] == "filename heuristic"

    evidence_id = report["evidence_ids"][0]
    evidence = await runtime.invoke(
        "evidence_get",
        {"project_id": project_id, "evidence_id": evidence_id},
    )
    assert evidence.data["authority"] in {
        "shipped_artifact",
        "controlled_replay",
        "historical_reference",
        "external_service",
        "analyst_inference",
    }
    assert evidence.data["confidence"] in {"observed", "derived", "inferred"}


async def test_analysis_stage_subset(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    started = await runtime.invoke(
        "analysis_start",
        {
            "project_id": project_id,
            "artifact_id": artifact["id"],
            "stages": ["container", "inventory"],
        },
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job.id},
    )
    assert report.data["stages"] == ["container", "inventory"]


async def test_unknown_stage_is_rejected(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "analysis_start",
            {
                "project_id": project_id,
                "artifact_id": artifact["id"],
                "stages": ["container", "magic"],
            },
        )


async def test_cannot_cancel_completed_job(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    job_id, _ = await _analyze(runtime, project_id, artifact["id"])
    with pytest.raises(StateError):
        await runtime.invoke(
            "analysis_cancel",
            {"project_id": project_id, "job_id": job_id},
        )


async def test_artifact_member_listing(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    listing = await runtime.invoke(
        "artifact_list_files",
        {
            "project_id": project_id,
            "artifact_id": artifact["id"],
            "pattern": "lib/*/*.so",
        },
    )
    assert listing.data["total"] == 2
    assert all(item["name"].endswith(".so") for item in listing.data["items"])


async def test_report_exports(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    job_id, _ = await _analyze(runtime, project_id, artifact["id"])

    markdown = await runtime.invoke(
        "report_generate",
        {
            "project_id": project_id,
            "job_id": job_id,
            "format": "markdown",
            "filename": "report.md",
        },
    )
    markdown_path = Path(markdown.data["path"])
    assert markdown_path.is_file()
    content = markdown_path.read_text(encoding="utf-8")
    assert "# RAA analysis report" in content
    assert "## Findings" in content
    assert artifact["sha256"] in content

    exported_json = await runtime.invoke(
        "report_generate",
        {"project_id": project_id, "job_id": job_id, "format": "json"},
    )
    json_path = Path(exported_json.data["path"])
    assert json_path.is_file()
    assert json_path.suffix == ".json"


async def test_policy_denies_export_without_scope(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    job_id, _ = await _analyze(runtime, project_id, artifact["id"])

    # Narrowing scopes after analysis must also gate export.
    from raa.utils.time import utc_now

    project = runtime.projects.get_or_raise(project_id)
    project.scopes = ["project.read", "static.read"]
    project.updated_at = utc_now()
    runtime.projects.repository.update(project)

    from raa.errors import PolicyDeniedError

    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "report_generate",
            {"project_id": project_id, "job_id": job_id},
        )


async def test_recipe_triage_from_path(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    result = await runtime.invoke(
        "recipe_run",
        {
            "recipe_id": "triage",
            "arguments": {"project_id": project_id, "path": str(apk_path)},
        },
    )
    data = result.data
    assert data["artifact"]["artifact_type"] == "apk"
    assert data["report"]["summary"]["dex_count"] == 2
    assert data["job"]["status"] == "completed"
    assert data["evidence_ids"]
    assert len(data["evidence_ids"]) == len(set(data["evidence_ids"]))


async def test_recipe_triage_from_artifact(runtime: Runtime, apk_path: Path) -> None:
    project_id = await _create_project(runtime)
    artifact = (await _ingest(runtime, project_id, apk_path))["data"]
    result = await runtime.invoke(
        "recipe_run",
        {
            "recipe_id": "triage",
            "arguments": {"project_id": project_id, "artifact_id": artifact["id"]},
        },
    )
    assert result.data["report"]["artifact_id"] == artifact["id"]


async def test_recipe_validation_and_listing(runtime: Runtime) -> None:
    recipes = await runtime.invoke("recipe_list", {})
    assert recipes.data["count"] == 2
    assert {recipe["id"] for recipe in recipes.data["recipes"]} == {
        "triage",
        "project_overview",
    }

    described = await runtime.invoke("recipe_describe", {"recipe_id": "triage"})
    assert "project_id" in described.data["input_schema"]["properties"]

    project_id = await _create_project(runtime)
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "recipe_run",
            {
                "recipe_id": "triage",
                "arguments": {"project_id": project_id},
            },
        )

    overview = await runtime.invoke(
        "recipe_run",
        {"recipe_id": "project_overview", "arguments": {"project_id": project_id}},
    )
    assert overview.data["project"]["id"] == project_id
    assert overview.data["artifact_count"] == 0
