"""Phase 2 deliverables tests: source_get_file, discovery, network security and cross-checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from raa.errors import InvalidArgumentsError, NotFoundError
from raa.runtime import Runtime
from raa.services.android.network_security import decode_network_security_config
from tests.conftest import make_apk


async def _project_and_artifact(runtime: Runtime, path: Path) -> tuple[str, str]:
    project = await runtime.invoke("project_create", {"name": "Phase 2 Test"})
    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project.data["id"], "path": str(path)},
    )
    return project.data["id"], ingested.data["id"]


async def _run_analysis(runtime: Runtime, project_id: str, artifact_id: str) -> str:
    started = await runtime.invoke(
        "analysis_start",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    assert job.status.value == "completed"
    return job.id


async def test_source_get_file_from_archive(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    res = await runtime.invoke(
        "source_get_file",
        {
            "project_id": project_id,
            "job_id": job_id,
            "file_path": "META-INF/MANIFEST.MF",
        },
    )
    assert res.data["source"] == "archive"
    assert "Manifest-Version" in res.data["text"]
    assert res.data["byte_count"] > 0
    assert res.data["truncated"] is False


async def test_source_get_file_traversal_rejected(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "source_get_file",
            {
                "project_id": project_id,
                "job_id": job_id,
                "file_path": "../../../etc/passwd",
            },
        )


async def test_source_get_file_missing_rejected(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "source_get_file",
            {
                "project_id": project_id,
                "job_id": job_id,
                "file_path": "nonexistent/file.txt",
            },
        )


async def test_source_get_file_from_workspace(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    # Export a report so a file exists in exports
    exported = await runtime.invoke(
        "report_generate",
        {
            "project_id": project_id,
            "job_id": job_id,
            "format": "markdown",
            "filename": "sample_rep.md",
        },
    )
    rel_path = Path(exported.data["path"]).relative_to(runtime.workspace.root).as_posix()

    res = await runtime.invoke(
        "source_get_file",
        {
            "project_id": project_id,
            "job_id": job_id,
            "file_path": rel_path,
        },
    )
    assert res.data["source"] == "workspace"
    assert "raa analysis report" in res.data["text"].lower()


async def test_endpoint_and_storage_discovery_in_report(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    data = report.data
    assert "endpoints" in data
    assert "storage" in data

    endpoints = data["endpoints"]
    assert any(u == "https://api.example.com/v1" for u in endpoints["urls"])
    assert any(dl == "https://example.com/app" for dl in endpoints["deep_links"])
    assert "https" in endpoints["schemes"]

    storage = data["storage"]
    assert isinstance(storage["storage_technologies"], list)
    assert isinstance(storage["sqlite_databases"], list)
    assert isinstance(storage["shared_preferences"], list)


def test_discover_storage_unit() -> None:
    from raa.services.android.dex import DexIndex, ParsedDex
    from raa.services.android.discovery import discover_storage

    dex = ParsedDex(
        name="classes.dex",
        size_bytes=100,
        version="035",
        checksum="0",
        checksum_valid=True,
        signature_valid=True,
        strings=[
            "user_preferences.xml",
            "app_data.db",
            "android.database.sqlite.SQLiteOpenHelper",
            "androidx.room.RoomDatabase",
            "EncryptedSharedPreferences",
        ],
        classes=[],
    )
    dex_index = DexIndex(files=[dex])
    discovery = discover_storage(None, dex_index)
    assert "app_data.db" in discovery.sqlite_databases
    assert "user_preferences.xml" in discovery.shared_preferences
    assert "SQLite" in discovery.storage_technologies
    assert "Android Room" in discovery.storage_technologies
    assert "EncryptedSharedPreferences" in discovery.storage_technologies


def test_network_security_config_xml_parsing() -> None:
    sample_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
"""
    decoded = decode_network_security_config(sample_xml)
    assert decoded["has_user_certificates"] is True
    assert decoded["has_pinning"] is True
    assert decoded["has_cleartext_traffic_permitted"] is True
    assert len(decoded["domain_configs"]) == 1
    domain = decoded["domain_configs"][0]
    assert domain["domains"][0]["domain"] == "api.example.com"
    assert domain["domains"][0]["include_subdomains"] is True
    assert domain["pin_set"]["pins"][0]["digest"] == "SHA-256"


async def test_android_get_network_config_with_xml(runtime: Runtime, tmp_path: Path) -> None:
    net_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
    apk = make_apk(
        tmp_path / "net_test.apk",
        entries={"res/xml/network_security_config.xml": net_xml},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    res = await runtime.invoke(
        "android_get_network_config",
        {"project_id": project_id, "job_id": job_id},
    )
    assert res.data["network_security_config"] is not None
    assert res.data["network_config_decoded"] is True
    assert res.data["trust_anchors_known"] is True
    assert "config" in res.data
    config = res.data["config"]
    assert config["base_config"]["cleartext_traffic_permitted"] is False
