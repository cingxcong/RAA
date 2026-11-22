"""DEX metadata indexing, analysis integration and source-tool tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from raa.errors import (
    InvalidArgumentsError,
    InvalidArtifactError,
    LimitExceededError,
    NotFoundError,
    StateError,
    UnsupportedError,
)
from raa.runtime import Runtime
from raa.services.android.dex import decode_dex_index, parse_dex
from tests.conftest import make_apk
from tests.dex_builder import (
    DexClassSpec,
    build_dex,
    build_sample_dex,
    build_sample_dex2,
)


def _class(dex, name: str):
    for item in dex.classes:
        if item.name == name:
            return item
    raise AssertionError(f"missing class {name}")


def test_parse_sample_dex() -> None:
    dex = parse_dex(build_sample_dex())

    assert dex.version == "035"
    assert dex.checksum_valid is True
    assert dex.signature_valid is True
    assert [item.name for item in dex.classes] == [
        "com.example.demo.ClickListener",
        "com.example.demo.MainActivity",
    ]
    assert dex.summary().class_count == 2
    assert dex.summary().method_count == 4
    assert dex.summary().field_count == 2

    activity = _class(dex, "com.example.demo.MainActivity")
    assert activity.descriptor == "Lcom/example/demo/MainActivity;"
    assert activity.superclass == "android.app.Activity"
    assert activity.interfaces == ["com.example.demo.ClickListener"]
    assert activity.source_file == "MainActivity.java"
    assert activity.info().access == ["public"]
    assert [(field.name, field.descriptor) for field in activity.fields] == [
        ("TAG", "Ljava/lang/String;"),
        ("count", "I"),
    ]
    methods = {method.name: method for method in activity.methods}
    assert methods["<init>"].descriptor == "()V"
    assert methods["<init>"].access_flags == 0x10001
    assert methods["<init>"].code_offset is not None
    assert methods["helper"].descriptor == "(ILjava/lang/String;)Ljava/lang/String;"
    assert methods["helper"].access_flags == 0x9
    assert methods["onCreate"].descriptor == "(Landroid/os/Bundle;)V"

    interface = _class(dex, "com.example.demo.ClickListener")
    assert interface.superclass is None
    assert interface.info().access == ["public", "interface", "abstract"]
    assert interface.methods[0].name == "onClick"


def test_unicode_strings_round_trip() -> None:
    dex = parse_dex(
        build_dex([], extra_strings=("caf\u00e9", "\u65e5\u672c\u8a9e")),
    )
    assert "caf\u00e9" in dex.strings
    assert "\u65e5\u672c\u8a9e" in dex.strings


def test_checksum_mismatch_is_reported_not_fatal() -> None:
    data = bytearray(build_sample_dex())
    data[-1] ^= 0x01
    dex = parse_dex(bytes(data))
    assert dex.checksum_valid is False
    assert dex.signature_valid is False
    assert len(dex.classes) == 2


def test_multidex_index(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "multi.apk")
    index = decode_dex_index(apk, "apk", max_bytes=1024 * 1024)

    assert [item.name for item in index.files] == ["classes.dex", "classes2.dex"]
    summary = index.summary()
    assert summary.file_count == 2
    assert summary.class_count == 3
    assert summary.method_count == 6
    assert summary.field_count == 3
    assert summary.multi_dex is True
    assert not index.errors
    assert "https://api.example.com/v1" in index.files[1].strings


def test_nested_dex_is_ignored(tmp_path: Path) -> None:
    apk = make_apk(
        tmp_path / "nested.apk",
        entries={"base/dex/classes.dex": build_sample_dex2()},
    )
    index = decode_dex_index(apk, "apk", max_bytes=1024 * 1024)
    assert [item.name for item in index.files] == ["classes.dex", "classes2.dex"]


def test_no_dex_is_an_explicit_limitation(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "no-dex.apk", include_dex=False)
    index = decode_dex_index(apk, "apk", max_bytes=1024 * 1024)
    assert index.summary().file_count == 0
    assert any("No root-level classes.dex" in item for item in index.limitations)


def test_non_apk_containers_are_rejected(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "sample.apk")
    with pytest.raises(UnsupportedError):
        decode_dex_index(apk, "aab", max_bytes=1024 * 1024)


def test_invalid_dex_files_are_rejected() -> None:
    with pytest.raises(InvalidArtifactError):
        parse_dex(b"")
    with pytest.raises(InvalidArtifactError):
        parse_dex(b"not a dex file")
    with pytest.raises(UnsupportedError):
        parse_dex(b"cdex001\x00" + b"\x00" * 120)
    data = bytearray(build_sample_dex())
    struct.pack_into("<I", data, 0x20, 0xFFFFFF)
    with pytest.raises(InvalidArtifactError):
        parse_dex(bytes(data))


def test_corrupt_offsets_are_rejected() -> None:
    data = bytearray(build_sample_dex())
    string_off = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<I", data, string_off, 0xFFFFFFFF)
    with pytest.raises(InvalidArtifactError):
        parse_dex(bytes(data))

    data = bytearray(build_sample_dex())
    class_off = struct.unpack_from("<I", data, 0x64)[0]
    struct.pack_into("<I", data, class_off + 24, 0xFFFFFFFF)
    with pytest.raises(InvalidArtifactError):
        parse_dex(bytes(data))


def test_invalid_mutf8_is_rejected() -> None:
    data = bytearray(build_sample_dex())
    string_off = struct.unpack_from("<I", data, 0x3C)[0]
    target = struct.unpack_from("<I", data, string_off)[0]
    cursor = target
    while data[cursor] & 0x80:
        cursor += 1
    cursor += 1
    data[cursor] = 0xC0
    data[cursor + 1] = 0x00
    with pytest.raises(InvalidArtifactError):
        parse_dex(bytes(data))


def test_dex_limits_are_enforced() -> None:
    sample = build_sample_dex()
    with pytest.raises(LimitExceededError):
        parse_dex(sample, max_strings=1)
    with pytest.raises(LimitExceededError):
        parse_dex(sample, max_classes=1)
    with pytest.raises(LimitExceededError):
        parse_dex(sample, max_members=1)


def test_oversized_member_fails_per_file(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "big.apk")
    index = decode_dex_index(apk, "apk", max_bytes=100)
    assert index.summary().file_count == 2
    assert index.summary().class_count == 0
    assert len(index.errors) == 2


async def _project_and_artifact(runtime: Runtime, path: Path) -> tuple[str, str]:
    project = await runtime.invoke("project_create", {"name": "DEX"})
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


async def test_dex_index_is_part_of_reports_and_evidence(
    runtime: Runtime,
    apk_path: Path,
) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert "code" in report.data["stages"]
    assert report.data["dex_error"] is None
    summary = report.data["dex_summary"]
    assert summary["file_count"] == 2
    assert summary["class_count"] == 3
    assert summary["method_count"] == 6
    assert summary["field_count"] == 3
    assert summary["multi_dex"] is True
    assert report.data["summary"]["dex_class_count"] == 3
    assert report.data["summary"]["dex_method_count"] == 6

    evidence = await runtime.invoke(
        "evidence_list",
        {"project_id": project_id, "artifact_id": artifact_id},
    )
    kinds = {item["kind"] for item in evidence.data["items"]}
    assert "code.index" in kinds

    exported = await runtime.invoke(
        "report_generate",
        {"project_id": project_id, "job_id": job_id, "format": "markdown"},
    )
    markdown = Path(exported.data["path"]).read_text(encoding="utf-8")
    assert "## Code" in markdown
    assert "| `classes.dex` | 035 | 2" in markdown
    assert "| `classes2.dex` | 035 | 1" in markdown


async def test_source_search(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    classes = await runtime.invoke(
        "source_search",
        {**base, "query": "ApiClient", "kind": "class"},
    )
    assert classes.data["total"] == 1
    assert classes.data["results"][0]["class"] == "com.example.demo.network.ApiClient"
    assert classes.data["results"][0]["dex_file"] == "classes2.dex"

    methods = await runtime.invoke(
        "source_search",
        {**base, "query": "onCreate", "kind": "method"},
    )
    assert methods.data["total"] == 1
    result = methods.data["results"][0]
    assert result["class"] == "com.example.demo.MainActivity"
    assert result["descriptor"] == "(Landroid/os/Bundle;)V"
    assert result["has_code"] is True

    strings = await runtime.invoke(
        "source_search",
        {**base, "query": "api.example.com", "kind": "string"},
    )
    assert strings.data["total"] == 1
    assert strings.data["results"][0]["value"] == "https://api.example.com/v1"

    case_insensitive = await runtime.invoke(
        "source_search",
        {**base, "query": "mainactivity", "kind": "class"},
    )
    assert case_insensitive.data["total"] == 1
    case_sensitive = await runtime.invoke(
        "source_search",
        {**base, "query": "mainactivity", "kind": "class", "case_sensitive": True},
    )
    assert case_sensitive.data["total"] == 0

    first_page = await runtime.invoke(
        "source_search",
        {**base, "query": "com.example", "limit": 2},
    )
    assert first_page.data["count"] == 2
    assert first_page.data["total"] > 2
    assert first_page.data["has_more"] is True
    second_page = await runtime.invoke(
        "source_search",
        {**base, "query": "com.example", "limit": 2, "offset": 2},
    )
    assert second_page.data["count"] >= 1
    assert second_page.data["results"] != first_page.data["results"]


async def test_source_get_class(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    activity = await runtime.invoke(
        "source_get_class",
        {**base, "class_name": "com.example.demo.MainActivity"},
    )
    data = activity.data
    assert data["descriptor"] == "Lcom/example/demo/MainActivity;"
    assert data["superclass"] == "android.app.Activity"
    assert data["interfaces"] == ["com.example.demo.ClickListener"]
    assert data["source_file"] == "MainActivity.java"
    assert data["field_total"] == 2
    assert data["method_total"] == 3
    assert {item["name"] for item in data["methods"]} == {
        "<init>",
        "helper",
        "onCreate",
    }
    assert data["truncated"] is False

    by_descriptor = await runtime.invoke(
        "source_get_class",
        {**base, "class_name": "Lcom/example/demo/ClickListener;"},
    )
    assert by_descriptor.data["name"] == "com.example.demo.ClickListener"
    assert "abstract" in by_descriptor.data["access"]

    limited = await runtime.invoke(
        "source_get_class",
        {**base, "class_name": "com.example.demo.MainActivity", "limit": 1},
    )
    assert limited.data["field_count"] == 1
    assert limited.data["method_count"] == 1
    assert limited.data["truncated"] is True

    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "source_get_class",
            {**base, "class_name": "com.example.demo.Missing"},
        )


async def test_ambiguous_simple_class_name(runtime: Runtime, tmp_path: Path) -> None:
    data = build_dex(
        [
            DexClassSpec(name="La/Foo;", superclass=None),
            DexClassSpec(name="Lb/Foo;", superclass=None),
        ]
    )
    apk = make_apk(
        tmp_path / "ambiguous.apk",
        include_dex=False,
        entries={"classes.dex": data},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    with pytest.raises(InvalidArgumentsError) as error:
        await runtime.invoke("source_get_class", {**base, "class_name": "Foo"})
    assert "ambiguous" in error.value.message.lower()
    candidates = error.value.details["candidates"]
    assert {item["class"] for item in candidates} == {"a.Foo", "b.Foo"}


async def test_missing_dex_returns_empty_index(runtime: Runtime, tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "no-dex.apk", include_dex=False)
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["dex_summary"]["file_count"] == 0
    assert report.data["dex_error"] is None

    search = await runtime.invoke("source_search", {**base, "query": "anything"})
    assert search.data["total"] == 0
    assert any("No root-level" in item for item in search.data["limitations"])


async def test_broken_dex_degrades_to_finding(runtime: Runtime, tmp_path: Path) -> None:
    apk = make_apk(
        tmp_path / "broken-dex.apk",
        include_dex=False,
        entries={"classes.dex": b"not-a-dex"},
    )
    project_id, artifact_id = await _project_and_artifact(runtime, apk)
    job_id = await _run_analysis(runtime, project_id, artifact_id)

    report = await runtime.invoke(
        "analysis_get_report",
        {"project_id": project_id, "job_id": job_id},
    )
    assert report.data["dex_summary"]["file_count"] == 1
    assert report.data["dex_summary"]["files"][0]["error"]
    assert "finding_dex_file_errors" in {finding["id"] for finding in report.data["findings"]}

    search = await runtime.invoke(
        "source_search",
        {"project_id": project_id, "job_id": job_id, "query": "anything"},
    )
    assert search.data["total"] == 0
    assert search.warnings


async def test_code_stage_can_be_skipped(runtime: Runtime, apk_path: Path) -> None:
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
    assert report.data["dex_summary"] is None
    assert report.data["dex_error"] == "Code stage was not selected."

    with pytest.raises(StateError):
        await runtime.invoke(
            "source_search",
            {"project_id": project_id, "job_id": job_id, "query": "anything"},
        )


def test_reference_index_is_bounded_and_opt_in() -> None:
    default = parse_dex(build_sample_dex())
    assert default.references == []

    dex = parse_dex(build_sample_dex(), include_references=True)
    assert not dex.reference_warnings
    assert len(dex.references) == 7
    kinds = {item.kind for item in dex.references}
    assert kinds == {
        "method_call",
        "field_access",
        "type_reference",
        "string_reference",
    }
    call = next(item for item in dex.references if item.kind == "method_call")
    assert call.from_class == "com.example.demo.MainActivity"
    assert call.from_method == "<init>"
    assert call.target_name == "helper"
    assert call.opcode == 0x71
    assert call.offset == 0
    field = next(item for item in dex.references if item.kind == "field_access")
    assert field.target == "com.example.demo.MainActivity#TAG:Ljava/lang/String;"
    assert field.opcode == 0x62
    strings = [item.value for item in dex.references if item.kind == "string_reference"]
    assert strings == ["demo-start", "demo-start"]

    limited = parse_dex(build_sample_dex(), include_references=True, max_references=2)
    assert len(limited.references) == 2
    assert any("configured limit" in item for item in limited.reference_warnings)

    tiny = parse_dex(build_sample_dex(), include_references=True, max_instruction_units=1)
    assert tiny.references == []
    assert len(tiny.reference_warnings) == 4


def test_reference_index_across_multidex(tmp_path: Path) -> None:
    apk = make_apk(tmp_path / "refs.apk")
    index = decode_dex_index(apk, "apk", max_bytes=1024 * 1024, include_references=True)
    assert len(index.references) == 9
    assert {item.dex_file for item in index.references} == {"classes.dex", "classes2.dex"}
    assert any(
        item.kind == "string_reference" and item.value == "https://api.example.com/v1"
        for item in index.references
    )
    assert all("Reference indexing stopped" not in item for item in index.summary().limitations)


async def test_source_find_references(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}

    calls = await runtime.invoke(
        "source_find_references",
        {**base, "query": "helper", "kind": "method_call"},
    )
    assert calls.data["total"] == 1
    item = calls.data["references"][0]
    assert item["from_class"] == "com.example.demo.MainActivity"
    assert item["from_method"] == "<init>"
    assert item["target_name"] == "helper"
    assert item["offset"] == 0

    fields = await runtime.invoke(
        "source_find_references",
        {**base, "query": "TAG", "kind": "field_access"},
    )
    assert fields.data["total"] == 1
    assert fields.data["references"][0]["target_descriptor"] == "Ljava/lang/String;"

    wrong_kind = await runtime.invoke(
        "source_find_references",
        {**base, "query": "TAG", "kind": "method_call"},
    )
    assert wrong_kind.data["total"] == 0

    case_sensitive = await runtime.invoke(
        "source_find_references",
        {**base, "query": "tag", "kind": "field_access", "case_sensitive": True},
    )
    assert case_sensitive.data["total"] == 0

    paged = await runtime.invoke(
        "source_find_references",
        {**base, "query": "java.lang.String", "kind": "type_reference", "limit": 1},
    )
    assert paged.data["count"] == 1
    assert paged.data["total"] == 2
    assert paged.data["has_more"] is True

    missing_stage = await runtime.invoke(
        "analysis_start",
        {
            "project_id": project_id,
            "artifact_id": artifact_id,
            "stages": ["container"],
        },
    )
    bare_job = await runtime.analysis.wait(project_id, missing_stage.data["id"])
    with pytest.raises(StateError):
        await runtime.invoke(
            "source_find_references",
            {
                "project_id": project_id,
                "job_id": bare_job.id,
                "query": "helper",
            },
        )


async def test_source_callers_and_callees(runtime: Runtime, apk_path: Path) -> None:
    project_id, artifact_id = await _project_and_artifact(runtime, apk_path)
    job_id = await _run_analysis(runtime, project_id, artifact_id)
    base = {"project_id": project_id, "job_id": job_id}
    activity = "com.example.demo.MainActivity"

    callers = await runtime.invoke(
        "source_get_callers",
        {**base, "class_name": activity, "method_name": "helper"},
    )
    assert callers.data["total"] == 1
    assert callers.data["call_site_total"] == 1
    assert callers.data["callers"][0]["method"] == "<init>"
    assert callers.data["callers"][0]["call_site_count"] == 1

    callees = await runtime.invoke(
        "source_get_callees",
        {**base, "class_name": activity, "method_name": "<init>"},
    )
    assert callees.data["total"] == 1
    target = callees.data["callees"][0]
    assert target["method"] == "helper"
    assert target["external"] is False
    assert target["call_site_count"] == 1

    no_calls = await runtime.invoke(
        "source_get_callees",
        {**base, "class_name": activity, "method_name": "onCreate"},
    )
    assert no_calls.data["total"] == 0
    assert "No method calls" in no_calls.data["note"]

    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "source_get_callers",
            {**base, "class_name": activity, "method_name": "missing"},
        )

    with pytest.raises(NotFoundError):
        await runtime.invoke(
            "source_get_callees",
            {
                **base,
                "class_name": activity,
                "method_name": "helper",
                "descriptor": "()V",
            },
        )
