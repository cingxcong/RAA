"""Resource-table decoding, analysis integration and tool tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from raa.errors import (
    InvalidArgumentsError,
    InvalidArtifactError,
    LimitExceededError,
    NotFoundError,
    StateError,
)
from raa.runtime import Runtime
from raa.services.android.arsc import parse_resource_table
from tests.arsc_builder import (
    ResourceTableSpec,
    ResourceTypeSpec,
    SimpleEntry,
    build_resource_table,
    build_sample_resource_table,
)
from tests.conftest import make_apk

_STRING = 0x03
_REFERENCE = 0x01


def _entry(table, type_name: str, name: str, config: str = "default"):
    for entry in table.entries:
        if entry.type == type_name and entry.name == name and entry.config == config:
            return entry
    raise AssertionError(f"missing resource {type_name}/{name}/{config}")


def test_parse_sample_resource_table() -> None:
    table = parse_resource_table(build_sample_resource_table())

    assert table.packages == ["com.example.demo"]
    assert table.skipped_compact_entries == 0
    assert table.skipped_unsupported_chunks == 0
    assert len(table.entries) == 13

    summary = table.summary()
    assert summary.packages == ["com.example.demo"]
    assert summary.entry_count == 10
    assert summary.value_count == 13
    assert summary.config_count == 3
    types = {item.type: item for item in summary.types}
    assert set(types) == {
        "bool",
        "color",
        "dimen",
        "integer",
        "layout",
        "string",
        "style",
    }
    assert types["string"].entry_count == 4
    assert types["string"].value_count == 7
    assert types["string"].default_count == 4
    assert types["string"].config_count == 3


def test_simple_values_and_string_variants() -> None:
    table = parse_resource_table(build_sample_resource_table())

    default_name = _entry(table, "string", "app_name")
    assert default_name.resource_id == 0x7F010000
    assert default_name.value is not None
    assert default_name.value.value == "Demo App"
    assert default_name.is_default is True

    french_name = _entry(table, "string", "app_name", "fr-rFR")
    assert french_name.value is not None
    assert french_name.value.value == "Bienvenue"
    assert french_name.is_default is False

    hdpi_name = _entry(table, "string", "app_name", "hdpi")
    assert hdpi_name.value is not None
    assert hdpi_name.value.value == "Bienvenue"

    title = _entry(table, "string", "title")
    assert title.value is not None
    assert title.value.value == "Bienvenue"

    boolean = _entry(table, "bool", "enabled")
    assert boolean.value is not None
    assert boolean.value.value is True

    integer = _entry(table, "integer", "max_retries")
    assert integer.value is not None
    assert integer.value.value == 5

    color = _entry(table, "color", "accent")
    assert color.value is not None
    assert color.value.value == "#ff3366cc"

    dimension = _entry(table, "dimen", "margin")
    assert dimension.value is not None
    assert dimension.value.value == "16dp"


def test_file_references_and_complex_entries() -> None:
    table = parse_resource_table(build_sample_resource_table())

    layout = _entry(table, "layout", "main")
    info = layout.variant_info()
    assert info.file_reference == "res/layout/main.xml"
    assert info.value is not None
    assert info.value.type == "string"

    style = _entry(table, "style", "AppTheme")
    info = style.variant_info()
    assert info.complex is True
    assert info.value is None
    assert info.map_count == 3
    assert len(info.maps) == 3
    values = {item.name: item.value.value for item in info.maps}
    assert values["0x01010098"] == "@0x7f030000"
    assert values["0x01010036"] == "8dp"
    assert values["0x0101000e"] is True


def test_utf16_string_pools() -> None:
    table = parse_resource_table(build_sample_resource_table(utf8_strings=False))
    assert len(table.entries) == 13
    entry = _entry(table, "string", "app_name")
    assert entry.value is not None
    assert entry.value.value == "Demo App"


def test_sparse_type_offsets() -> None:
    spec = ResourceTableSpec(
        strings=["zero", "two", "three"],
        types=[
            ResourceTypeSpec(
                1,
                "string",
                [
                    SimpleEntry(0, "zero", _STRING, 0),
                    SimpleEntry(2, "two", _STRING, 1),
                    SimpleEntry(3, "three", _STRING, 2),
                ],
                flags=0x01,
            )
        ],
    )
    table = parse_resource_table(build_resource_table(spec))
    assert [(entry.entry_index, entry.name) for entry in table.entries] == [
        (0, "zero"),
        (2, "two"),
        (3, "three"),
    ]


def test_offset16_type_offsets() -> None:
    spec = ResourceTableSpec(
        strings=["zero", "two"],
        types=[
            ResourceTypeSpec(
                1,
                "string",
                [
                    SimpleEntry(0, "zero", _STRING, 0),
                    SimpleEntry(2, "two", _STRING, 1),
                ],
                flags=0x02,
            )
        ],
    )
    table = parse_resource_table(build_resource_table(spec))
    assert [(entry.entry_index, entry.name) for entry in table.entries] == [
        (0, "zero"),
        (2, "two"),
    ]


def test_invalid_tables_are_rejected() -> None:
    with pytest.raises(InvalidArtifactError):
        parse_resource_table(b"")
    with pytest.raises(InvalidArtifactError):
        parse_resource_table(b"\x02\x00\x0c\x00" + b"\x00" * 4)
    with pytest.raises(InvalidArtifactError):
        parse_resource_table(b"\x03\x00\x0c\x00" + b"\x00" * 8)


def test_entry_limit_is_enforced() -> None:
    with pytest.raises(LimitExceededError):
        parse_resource_table(build_sample_resource_table(), max_entries=2)
    with pytest.raises(LimitExceededError):
        parse_resource_table(build_sample_resource_table(), max_strings=1)
    with pytest.raises(LimitExceededError):
        parse_resource_table(build_sample_resource_table(), max_configs=1)
    with pytest.raises(LimitExceededError):
        parse_resource_table(build_sample_resource_table(), max_map_entries=2)


async def _project_and_artifact(runtime: Runtime, path: Path) -> tuple[str, str]:
    project = await runtime.invoke("project_create", {"name": "Resources"})
    ingested = await runtime.invoke(
        "artifact_ingest",
        {"project_id": project.data["id"], "path": str(path)},
    )
    return project.data["id"], ingested.data["id"]


async def _run_analysis(
    runtime: Runtime,
    project_id: str,
    artifact_id: str,
    stages: list[str] | None = None,
) -> str:
    arguments = {"project_id": project_id, "artifact_id": artifact_id}
    if stages is not None:
        arguments["stages"] = stages
    started = await runtime.invoke("analysis_start", arguments)
    job = await runtime.analysis.wait(project_id, started.data["id"])
    assert job.status.value == "completed"
    return job.id


async def test_resources_are_part_of_reports_and_evidence(
    runtime: Runtime,
    apk_path: Path,
) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert "resources" in report.data["stages"]
    assert report.data["resource_error"] is None
    summary = report.data["resource_summary"]
    assert summary["entry_count"] == 10
    assert summary["value_count"] == 13
    assert summary["config_count"] == 3
    assert report.data["summary"]["resource_entry_count"] == 10
    assert report.data["summary"]["resource_type_count"] == 7

    evidence = await runtime.invoke(
        "evidence_list",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    kinds = {item["kind"] for item in evidence.data["items"]}
    assert "resources.inventory" in kinds

    exported = await runtime.invoke(
        "report_generate",
        {"project_id": project_id, "job_id": job_id, "format": "markdown"},
    )
    markdown = Path(exported.data["path"]).read_text(encoding="utf-8")
    assert "## Resources" in markdown
    assert "| string | 4 | 7 | 4 |" in markdown


async def test_resource_tools(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    listed = await runtime.invoke("android_list_resources", base)
    assert listed.data["total"] == 10
    assert listed.data["count"] == 10
    assert listed.data["summary"]["entry_count"] == 10
    assert listed.data["limitations"]

    strings = await runtime.invoke(
        "android_list_resources",
        {**base, "type": "string"},
    )
    assert strings.data["total"] == 4
    assert {item["name"] for item in strings.data["resources"]} == {
        "app_name",
        "title",
        "main_layout",
        "optional",
    }

    page = await runtime.invoke(
        "android_list_resources",
        {**base, "limit": 2, "offset": 2},
    )
    assert page.data["count"] == 2
    assert page.data["total"] == 10

    filtered = await runtime.invoke(
        "android_list_resources",
        {**base, "name": "app_name"},
    )
    assert filtered.data["total"] == 1
    assert filtered.data["resources"][0]["variant_count"] == 3
    assert filtered.data["resources"][0]["default_value"]["value"] == "Demo App"

    french = await runtime.invoke(
        "android_list_resources",
        {**base, "config": "fr-rFR"},
    )
    assert french.data["total"] == 2
    assert {item["name"] for item in french.data["resources"]} == {
        "app_name",
        "title",
    }

    by_name = await runtime.invoke(
        "android_get_resource",
        {**base, "name": "app_name"},
    )
    assert by_name.data["resource_id"] == "0x7f010000"
    assert by_name.data["variant_count"] == 3
    assert {item["config"] for item in by_name.data["variants"]} == {
        "default",
        "fr-rFR",
        "hdpi",
    }

    by_id = await runtime.invoke(
        "android_get_resource",
        {**base, "resource_id": "0x7f020000"},
    )
    assert by_id.data["type"] == "layout"
    assert by_id.data["name"] == "main"
    assert by_id.data["file_references"] == ["res/layout/main.xml"]

    style = await runtime.invoke(
        "android_get_resource",
        {**base, "name": "AppTheme"},
    )
    assert style.data["variants"][0]["complex"] is True
    assert style.data["variants"][0]["map_count"] == 3

    single = await runtime.invoke(
        "android_get_resource",
        {**base, "name": "app_name", "config": "fr-rFR"},
    )
    assert single.data["variant_count"] == 1
    assert single.data["variants"][0]["value"]["value"] == "Bienvenue"


async def test_resource_tool_validation(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke("android_get_resource", base)
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "android_get_resource",
            {**base, "resource_id": "0x7f010000", "name": "app_name"},
        )
    with pytest.raises(InvalidArgumentsError):
        await runtime.invoke(
            "android_get_resource",
            {**base, "resource_id": "not-a-number"},
        )
    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "android_get_resource",
            {**base, "name": "missing"},
        )
    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "android_get_resource",
            {**base, "name": "app_name", "config": "night"},
        )


async def test_ambiguous_resource_name_requires_type(
    runtime: Runtime,
    tmp_path: Path,
) -> None:
    spec = ResourceTableSpec(
        strings=["shared string", "res/layout/shared.xml"],
        types=[
            ResourceTypeSpec(1, "string", [SimpleEntry(0, "shared", _STRING, 0)]),
            ResourceTypeSpec(2, "layout", [SimpleEntry(0, "shared", _STRING, 1)]),
        ],
    )
    apk = make_apk(
        tmp_path / "ambiguous.apk",
        entries={"resources.arsc": build_resource_table(spec)},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    with pytest.raises(InvalidArgumentsError) as error:
        await runtime.invoke("android_get_resource", {**base, "name": "shared"})
    assert "ambiguous" in error.value.message.lower()
    assert error.value.details["resource_ids"] == ["0x7f010000", "0x7f020000"]

    resolved = await runtime.invoke(
        "android_get_resource",
        {**base, "name": "shared", "type": "layout"},
    )
    assert resolved.data["type"] == "layout"
    assert resolved.data["resource_id"] == "0x7f020000"


async def test_missing_resources_degrade_to_finding(
    runtime: Runtime,
    tmp_path: Path,
) -> None:
    apk = make_apk(tmp_path / "no-resources.apk", include_resources=False)
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["resource_summary"] is None
    assert report.data["resource_error"]
    finding_ids = {finding["id"] for finding in report.data["findings"]}
    assert "finding_resources_unavailable" in finding_ids
    assert any(
        "resources" in limitation.lower() for limitation in report.data["coverage"]["limitations"]
    )

    with pytest.raises(StateError):
        await runtime.invoke(
            "android_list_resources",
            {"project_id": project_id, "job_id": job_id},
        )


async def test_broken_resources_degrade_to_finding(
    runtime: Runtime,
    tmp_path: Path,
) -> None:
    apk = make_apk(
        tmp_path / "broken-resources.apk",
        entries={"resources.arsc": b"\x02\x00\x0c\x00" + b"\x00" * 8},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["resource_summary"] is None
    assert report.data["resource_error"]
    assert "finding_resources_unavailable" in {finding["id"] for finding in report.data["findings"]}


async def test_resource_stage_can_be_skipped(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(
        runtime,
        project_id,
        artifact_id,
        stages=["container", "inventory"],
    )
    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["resource_summary"] is None
    assert report.data["resource_error"] == "Resources stage was not selected."

    with pytest.raises(StateError):
        await runtime.invoke(
            "android_list_resources",
            {"project_id": project_id, "job_id": job_id},
        )


def test_reference_value_type() -> None:
    spec = ResourceTableSpec(
        strings=[],
        types=[
            ResourceTypeSpec(
                1,
                "string",
                [SimpleEntry(0, "reference", _REFERENCE, 0x7F020000)],
            )
        ],
    )
    table = parse_resource_table(build_resource_table(spec))
    entry = _entry(table, "string", "reference")
    assert entry.value is not None
    info = entry.variant_info().value
    assert info is not None
    assert info.type == "reference"
    assert info.value == "@0x7f020000"
