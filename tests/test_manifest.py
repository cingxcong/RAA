"""Binary manifest decoding and manifest-backed tool tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from raa.config import Settings
from raa.errors import InvalidArtifactError, LimitExceededError, StateError, UnsupportedError
from raa.runtime import Runtime
from raa.services.android.axml import parse_binary_xml
from raa.services.android.manifest import decode_manifest, manifest_findings, parse_manifest
from tests.axml_builder import (
    Attr,
    Node,
    android,
    build_sample_manifest,
    encode_binary_xml,
    plain,
)
from tests.conftest import make_apk


def test_sample_manifest_is_decoded() -> None:
    manifest = parse_manifest(build_sample_manifest())

    assert manifest.package == "com.example.demo"
    assert manifest.version_code == 42
    assert manifest.version_name == "1.2.3"
    assert manifest.compile_sdk == 34
    assert manifest.min_sdk == 23
    assert manifest.target_sdk == 33

    requested = {permission.name for permission in manifest.requested_permissions}
    assert requested == {"android.permission.INTERNET", "android.permission.CAMERA"}
    assert manifest.declared_permissions[0].name == "com.example.demo.permission.CUSTOM"
    assert manifest.declared_permissions[0].protection_level == "signature"
    assert manifest.features[0].name == "android.hardware.camera"
    assert manifest.features[0].required is False

    application = manifest.application
    assert application.debuggable is True
    assert application.allow_backup is True
    assert application.uses_cleartext_traffic is True
    assert application.effective_cleartext_traffic is True
    assert application.network_security_config == "@xml/network_security_config"

    components = {component.name: component for component in manifest.components}
    assert set(components) == {
        ".MainActivity",
        ".DeepLinkActivity",
        ".LegacyActivity",
        ".ProtectedActivity",
        ".AliasActivity",
        ".SyncService",
        ".BootReceiver",
        ".FileProvider",
    }
    assert components[".MainActivity"].kind == "activity"
    assert components[".MainActivity"].launcher is True
    assert components[".MainActivity"].exported_source == "explicit"
    assert components[".AliasActivity"].kind == "activity_alias"
    assert components[".AliasActivity"].target_activity == ".MainActivity"
    assert components[".FileProvider"].authorities == "com.example.demo.files"
    assert components[".FileProvider"].grant_uri_permissions is True

    # targetSdk 33 requires an explicit exported flag with intent filters.
    legacy = components[".LegacyActivity"]
    assert legacy.exported is None
    assert legacy.effective_exported is False
    assert legacy.exported_source == "default_false"

    assert len(manifest.exported_components) == 4
    assert manifest.deep_links[0].scheme == "https"
    assert manifest.deep_links[0].host == "example.com"
    assert manifest.deep_links[0].path_prefix == "/app"
    assert manifest.deep_links[0].auto_verify is True


def test_utf16_string_pool_is_decoded() -> None:
    manifest = parse_manifest(build_sample_manifest(utf8=False))
    assert manifest.package == "com.example.demo"
    assert len(manifest.components) == 8


def test_findings_cover_manifest_security_flags() -> None:
    manifest = parse_manifest(build_sample_manifest())
    findings = {finding.id: finding for finding in manifest_findings(manifest)}

    assert findings["finding_manifest_debuggable"].severity == "high"
    assert findings["finding_manifest_cleartext_traffic"].severity == "medium"
    assert findings["finding_manifest_allow_backup"].severity == "low"
    assert findings["finding_exported_without_permission"].severity == "high"
    assert "finding_manifest_missing_exported" in findings


def _single_activity_manifest(
    *,
    target_sdk: int,
    application_attributes: list[Attr] | None = None,
    activity_attributes: list[Attr] | None = None,
) -> bytes:
    intent_filter = Node(
        "intent-filter",
        [],
        [
            Node("action", [android("name", "android.intent.action.VIEW")]),
            Node("category", [android("name", "android.intent.category.DEFAULT")]),
        ],
    )
    root = Node(
        "manifest",
        [plain("package", "com.example.edge")],
        [
            Node("uses-sdk", [android("targetSdkVersion", target_sdk)]),
            Node(
                "application",
                application_attributes or [],
                [
                    Node(
                        "activity",
                        [android("name", ".Edge")] + (activity_attributes or []),
                        [intent_filter],
                    )
                ],
            ),
        ],
    )
    return encode_binary_xml(root)


def test_exported_defaults_before_and_after_sdk_31() -> None:
    legacy = parse_manifest(_single_activity_manifest(target_sdk=30))
    modern = parse_manifest(_single_activity_manifest(target_sdk=31))

    assert legacy.components[0].exported is None
    assert legacy.components[0].effective_exported is True
    assert legacy.components[0].exported_source == "intent_filter_legacy"

    assert modern.components[0].exported is None
    assert modern.components[0].effective_exported is False
    assert modern.components[0].exported_source == "default_false"


def test_disabled_components_are_not_exported_surface() -> None:
    manifest = parse_manifest(
        _single_activity_manifest(
            target_sdk=33,
            activity_attributes=[
                android("exported", True),
                android("enabled", False),
            ],
        )
    )

    assert manifest.components[0].effective_exported is True
    assert manifest.components[0].enabled is False
    assert manifest.exported_components == []


def test_cleartext_default_follows_target_sdk() -> None:
    legacy = parse_manifest(_single_activity_manifest(target_sdk=27))
    modern = parse_manifest(_single_activity_manifest(target_sdk=28))

    assert legacy.application.uses_cleartext_traffic is None
    assert legacy.application.effective_cleartext_traffic is True
    assert modern.application.uses_cleartext_traffic is None
    assert modern.application.effective_cleartext_traffic is False


def test_malformed_manifest_is_rejected() -> None:
    with pytest.raises(InvalidArtifactError):
        parse_manifest(b"\x03\x00\x08\x00" + b"\x00" * 16)

    with pytest.raises(InvalidArtifactError):
        parse_manifest(build_sample_manifest()[:200])

    with pytest.raises(InvalidArtifactError):
        parse_binary_xml(b"\x00\x00\x08\x00" + b"\x00" * 16)


def test_binary_xml_limits_are_enforced() -> None:
    data = build_sample_manifest()
    with pytest.raises(LimitExceededError):
        parse_binary_xml(data, max_elements=2)
    with pytest.raises(LimitExceededError):
        parse_binary_xml(data, max_depth=2)
    with pytest.raises(LimitExceededError):
        parse_binary_xml(data, max_strings=1)


def test_member_and_container_limits(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "sample.apk")
    with pytest.raises(LimitExceededError):
        decode_manifest(apk, "apk", max_bytes=512)
    with pytest.raises(UnsupportedError):
        decode_manifest(tmp_path / "sample.aab", "aab", max_bytes=1024)


async def _project_and_artifact(runtime: Runtime, path: Path) -> tuple[str, str]:
    project = await runtime.invoke("project_create", {"name": "Manifest"})
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


async def test_manifest_is_part_of_reports_and_evidence(
    runtime: Runtime,
    apk_path: Path,
) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert "manifest" in report.data["stages"]
    assert report.data["manifest"]["package"] == "com.example.demo"
    assert report.data["manifest_error"] is None
    assert report.data["summary"]["package"] == "com.example.demo"
    assert report.data["summary"]["exported_component_count"] == 4
    assert report.data["summary"]["deep_link_count"] == 1

    evidence = await runtime.invoke(
        "evidence_list",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    kinds = {item["kind"] for item in evidence.data["items"]}
    assert "manifest.parsed" in kinds


async def test_manifest_tools(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    manifest = await runtime.invoke("android_get_manifest", base)
    assert manifest.data["package"] == "com.example.demo"
    assert manifest.data["target_sdk"] == 33

    components = await runtime.invoke("android_list_components", base)
    assert components.data["total"] == 8
    exported = await runtime.invoke(
        "android_list_components",
        {**base, "exported_only": True},
    )
    assert exported.data["total"] == 4
    providers = await runtime.invoke(
        "android_list_components",
        {**base, "kind": "provider"},
    )
    assert providers.data["total"] == 1
    assert providers.data["components"][0]["authorities"] == "com.example.demo.files"

    permissions = await runtime.invoke("android_list_permissions", base)
    assert permissions.data["requested_count"] == 2
    assert permissions.data["declared_count"] == 1
    assert len(permissions.data["features"]) == 1

    surface = await runtime.invoke("android_get_exported_surface", base)
    assert surface.data["count"] == 4
    assert surface.data["unprotected_count"] == 3
    assert surface.data["deep_link_count"] == 1

    network = await runtime.invoke("android_get_network_config", base)
    assert network.data["uses_cleartext_traffic"] is True
    assert network.data["network_security_config"] == "@xml/network_security_config"
    assert network.data["network_config_decoded"] is False
    assert network.data["limitations"]


async def test_manifest_stage_can_be_skipped(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    started = await runtime.invoke(
        "analysis_start",
        {
            "project_id": project_id,
            "artifact_id": artifact_id,
            "stages": ["container", "inventory"],
        },
    )
    job = await runtime.analysis.wait(project_id, started.data["id"])
    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job.id},
    )
    assert report.data["manifest"] is None
    assert report.data["manifest_error"] == "Manifest stage was not selected."

    with pytest.raises(StateError):
        await runtime.invoke(
            "android_get_manifest",
            {"project_id": project_id, "job_id": job.id},
        )


async def test_broken_manifest_degrades_to_finding(runtime: Runtime, tmp_path: Path) -> None:
    apk = make_apk(
        tmp_path / "broken.apk",
        include_manifest=False,
        entries={"AndroidManifest.xml": b"\x03\x00\x08\x00" + b"\x00" * 16},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["manifest"] is None
    assert "invalid" in report.data["manifest_error"].lower()
    finding_ids = {finding["id"] for finding in report.data["findings"]}
    assert "finding_manifest_unavailable" in finding_ids
    assert any(
        "manifest" in limitation.lower() for limitation in report.data["coverage"]["limitations"]
    )

    with pytest.raises(StateError):
        await runtime.invoke(
            "android_get_manifest",
            {"project_id": project_id, "job_id": job_id},
        )


def test_manifest_limits_are_configurable(tmp_path: Path) -> None:
    settings = Settings(
        workspace=tmp_path / "workspace",
        allowed_input_roots=[tmp_path],
        max_manifest_bytes=1024,
    )
    assert settings.max_manifest_bytes == 1024
