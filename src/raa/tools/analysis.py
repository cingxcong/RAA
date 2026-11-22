"""Static analysis, reporting and Android inventory tools."""

from __future__ import annotations

import contextlib
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.domain.manifest import ComponentKind, ManifestInfo
from raa.domain.models import AnalysisReport
from raa.errors import (
    InvalidArgumentsError,
    InvalidArtifactError,
    NotFoundError,
    RAAError,
    StateError,
)
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolCost,
    ToolHandler,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE, MINIMAL
from raa.services.ai.model_reverser import (
    discover_app_functions,
    extract_ai_prompts,
    inspect_ai_model,
)
from raa.services.android.arsc import (
    ParsedResourceEntry,
    ParsedResourceTable,
    decode_resource_table,
)
from raa.services.android.dex import (
    DexIndex,
    ParsedClass,
    ParsedMethod,
    decode_dex_index,
)
from raa.services.android.network_security import decode_network_security_config
from raa.services.engine_adapters import ApkidAdapter, ApktoolAdapter, JadxAdapter
from raa.services.reports import write_report
from raa.tools.common import report_of


class AnalysisStartInput(ToolInput):
    project_id: str
    artifact_id: str
    stages: list[str] | None = Field(
        default=None,
        description=(
            "Subset of: container, inventory, manifest, resources, code, frameworks, signatures."
        ),
    )


class JobInput(ToolInput):
    project_id: str
    job_id: str


class ReportGenerateInput(JobInput):
    format: Literal["json", "markdown"] = Field(
        default="json",
        description="Export format.",
    )
    filename: str | None = Field(
        default=None,
        max_length=180,
        description="Optional filename inside the project export directory.",
    )


class ComponentListInput(JobInput):
    kind: ComponentKind | None = Field(
        default=None,
        description="Filter by component kind.",
    )
    exported_only: bool = Field(
        default=False,
        description="Only return components with effective exported access.",
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class ResourceListInput(JobInput):
    type: str | None = Field(
        default=None,
        max_length=120,
        description="Filter by resource type, for example 'string' or 'layout'.",
    )
    name: str | None = Field(
        default=None,
        max_length=200,
        description="Filter by exact resource name.",
    )
    config: str | None = Field(
        default=None,
        max_length=200,
        description="Filter to resources with a matching configuration label.",
    )
    default_only: bool = Field(
        default=False,
        description="Only return resources that have a default configuration.",
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class ResourceGetInput(JobInput):
    resource_id: str | None = Field(
        default=None,
        max_length=20,
        description="Resource ID such as '0x7f010000' or a decimal integer.",
    )
    type: str | None = Field(
        default=None,
        max_length=120,
        description="Resource type used with name lookup.",
    )
    name: str | None = Field(
        default=None,
        max_length=200,
        description="Exact resource name used with optional type.",
    )
    config: str | None = Field(
        default=None,
        max_length=200,
        description="Only return variants with this configuration label.",
    )


class SourceSearchInput(JobInput):
    query: str = Field(
        min_length=2,
        max_length=300,
        description="Class, member, descriptor or string fragment to find.",
    )
    kind: Literal["class", "method", "field", "string"] | None = Field(
        default=None,
        description="Restrict results to one kind.",
    )
    case_sensitive: bool = Field(
        default=False,
        description="Match case-sensitively.",
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class SourceClassInput(JobInput):
    class_name: str = Field(
        min_length=1,
        max_length=500,
        description="Dotted class name or JVM descriptor.",
    )
    include_source: bool = Field(
        default=False,
        description="Run JADX and include bounded decompiled class source.",
    )
    source_limit: int = Field(
        default=100_000,
        ge=1,
        le=500_000,
        description="Maximum decompiled source characters to return.",
    )
    source_offset: int = Field(default=0, ge=0)
    limit: int = Field(
        default=100,
        ge=1,
        le=500,
        description="Maximum fields and maximum methods to return.",
    )
    offset: int = Field(default=0, ge=0)


class SourceGetFileInput(JobInput):
    file_path: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "Relative path inside the workspace or archive "
            "(e.g. 'res/xml/config.xml', 'AndroidManifest.xml', 'assets/...')."
        ),
    )
    source: Literal["auto", "archive", "workspace"] = Field(
        default="auto",
        description="Where to retrieve the file from.",
    )
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100_000, ge=1, le=500_000)


class PackerDetectInput(ToolInput):
    project_id: str = Field(min_length=1, description="Target project ID.")
    job_id: str | None = Field(
        default=None,
        description="Optional analysis job ID. If omitted, latest artifact is inspected.",
    )
    artifact_id: str | None = Field(
        default=None,
        description="Optional target artifact ID.",
    )
    include_apkid: bool = Field(
        default=False,
        description=(
            "Run APKiD external engine to detect compilers, packers, obfuscators and protectors."
        ),
    )


class SourceReferenceSearchInput(JobInput):
    query: str = Field(
        min_length=2,
        max_length=400,
        description="Class, method, field, type or string fragment to find.",
    )
    kind: Literal[
        "any",
        "method_call",
        "field_access",
        "type_reference",
        "string_reference",
    ] = Field(
        default="any",
        description="Restrict references to one kind.",
    )
    case_sensitive: bool = Field(
        default=False,
        description="Match case-sensitively.",
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class SourceRelationInput(JobInput):
    class_name: str = Field(
        min_length=1,
        max_length=500,
        description="Dotted class name or JVM descriptor.",
    )
    method_name: str = Field(
        min_length=1,
        max_length=300,
        description="Declared method name.",
    )
    descriptor: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional method descriptor to select one overload.",
    )
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class SourceMethodInput(JobInput):
    class_name: str = Field(
        min_length=1,
        max_length=500,
        description="Dotted class name or JVM descriptor.",
    )
    method_name: str = Field(
        min_length=1,
        max_length=300,
        description="Declared method name.",
    )
    descriptor: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional method descriptor to select one overload.",
    )
    include_source: bool = Field(
        default=False,
        description="Run JADX and include bounded decompiled class source.",
    )
    source_limit: int = Field(
        default=100_000,
        ge=1,
        le=500_000,
        description="Maximum decompiled source characters to return.",
    )
    source_offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class SourceSmaliInput(JobInput):
    class_name: str = Field(
        min_length=1,
        max_length=500,
        description="Dotted class name or JVM descriptor.",
    )
    limit: int = Field(default=100_000, ge=1, le=500_000)
    offset: int = Field(default=0, ge=0)


class SourceRenameSymbolInput(BaseModel):
    """Parameters to rename an obfuscated symbol and record the mapping."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    symbol_type: Literal["class", "method", "field"] = Field(
        default="class", description="Symbol type ('class', 'method', 'field')."
    )
    original_name: str = Field(min_length=1, description="Original obfuscated symbol name.")
    renamed_name: str = Field(min_length=1, description="Human-readable renamed identifier.")
    export_mapping: bool = Field(
        default=False, description="Whether to export updated ProGuard mapping.txt."
    )


class AiModelInspectInput(BaseModel):
    """Parameters to inspect an on-device machine learning model."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    model_name: str | None = Field(default=None, description="Optional model file name.")
    model_path: str | None = Field(default=None, description="Optional path to model file on disk.")
    raw_content_b64: str | None = Field(
        default=None, description="Optional base64 or raw model bytes content."
    )


class AiPromptExtractInput(BaseModel):
    """Parameters to scan and extract embedded system prompts and instructions."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    corpus_text: str | None = Field(
        default=None, description="Optional text corpus or source code to inspect for prompts."
    )
    artifact_path: str | None = Field(
        default=None, description="Optional path to file or artifact to scan for prompts."
    )


class AiAppFunctionDiscoverInput(BaseModel):
    """Parameters to discover Android 16 AppFunction agent declarations."""

    project_id: str = Field(min_length=1, description="Target project identifier.")
    metadata_xml: str | None = Field(
        default=None, description="Optional XML string declaring AppFunctions."
    )
    decompiled_dir: str | None = Field(
        default=None, description="Optional path to decompiled APK directory."
    )


class WasmDecompileInput(BaseModel):
    """Parameters to decompile and inspect an embedded WebAssembly module."""

    project_id: str | None = Field(default=None, description="Optional target project ID.")
    artifact_id: str | None = Field(default=None, description="Optional artifact ID.")
    file_path: str | None = Field(default=None, description="Optional path to .wasm binary.")
    wasm_bytes_hex: str | None = Field(
        default=None, description="Optional hex-encoded WASM bytes string."
    )


async def _analysis_start(ctx: ToolContext, args: AnalysisStartInput) -> ToolOutcome:
    job = ctx.runtime.analysis.start(
        args.project_id,
        args.artifact_id,
        stages=args.stages,
    )
    return ToolOutcome(
        data=job,
        warnings=[
            "analysis_start is asynchronous. Poll analysis_get_status until the "
            "job reaches a terminal state."
        ],
    )


async def _analysis_get_status(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    return ToolOutcome(data=ctx.runtime.analysis.get_job(args.project_id, args.job_id))


async def _analysis_cancel(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    return ToolOutcome(data=ctx.runtime.analysis.cancel(args.project_id, args.job_id))


async def _analysis_get_report(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report = ctx.runtime.analysis.get_report(args.project_id, args.job_id)
    return ToolOutcome(data=report, evidence_ids=report.evidence_ids)


async def _android_list_dex(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    return ToolOutcome(
        data={
            "dex_files": [dex.model_dump(mode="json") for dex in report.dex_files],
            "count": len(report.dex_files),
        },
        evidence_ids=report.evidence_ids,
    )


async def _android_list_native_libraries(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    return ToolOutcome(
        data={
            "abis": report.summary.get("abis", []),
            "libraries": [library.model_dump(mode="json") for library in report.native_libraries],
            "count": len(report.native_libraries),
        },
        evidence_ids=report.evidence_ids,
    )


async def _android_get_certificate_info(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    return ToolOutcome(data=report.signature, evidence_ids=report.evidence_ids)


def _manifest_of(ctx: ToolContext, args: JobInput) -> tuple[AnalysisReport, ManifestInfo]:
    report = report_of(ctx, args.project_id, args.job_id)
    if report.manifest is None:
        raise StateError(
            "Manifest data is not available for this analysis job.",
            hint=report.manifest_error or "Run analysis_start with the manifest stage enabled.",
            details={"job_id": args.job_id},
        )
    return report, report.manifest


async def _android_get_manifest(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report, manifest = _manifest_of(ctx, args)
    return ToolOutcome(data=manifest, evidence_ids=report.evidence_ids)


async def _android_list_components(ctx: ToolContext, args: ComponentListInput) -> ToolOutcome:
    report, manifest = _manifest_of(ctx, args)
    selected = [
        component
        for component in manifest.components
        if (args.kind is None or component.kind == args.kind)
        and (not args.exported_only or (component.effective_exported and component.enabled))
    ]
    page = selected[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "components": [component.model_dump(mode="json") for component in page],
            "count": len(page),
            "total": len(selected),
            "exported_total": sum(1 for item in selected if item.effective_exported),
            "kind": args.kind,
        },
        evidence_ids=report.evidence_ids,
    )


async def _android_list_permissions(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report, manifest = _manifest_of(ctx, args)
    return ToolOutcome(
        data={
            "requested": [
                permission.model_dump(mode="json") for permission in manifest.requested_permissions
            ],
            "declared": [
                permission.model_dump(mode="json") for permission in manifest.declared_permissions
            ],
            "requested_count": len(manifest.requested_permissions),
            "declared_count": len(manifest.declared_permissions),
            "features": [feature.model_dump(mode="json") for feature in manifest.features],
        },
        evidence_ids=report.evidence_ids,
    )


async def _android_get_network_config(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report, manifest = _manifest_of(ctx, args)
    application = manifest.application
    limitations: list[str] = []
    decoded_config: dict[str, Any] | None = None
    config_decoded = False
    trust_anchors_known = False

    if application.network_security_config:
        try:
            artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
            path = ctx.runtime.artifacts.path_for(artifact)
            config_name = application.network_security_config.split("/")[-1].replace("@", "")
            with zipfile.ZipFile(path, "r") as archive:
                candidates = [
                    name
                    for name in archive.namelist()
                    if f"xml/{config_name}.xml" in name.lower()
                    or f"{config_name}.xml" in name.lower()
                ]
                if candidates:
                    data_bytes = archive.read(candidates[0])
                    decoded_config = decode_network_security_config(data_bytes)
                    config_decoded = True
                    trust_anchors_known = True
        except Exception as exc:
            limitations.append(f"Network security config extraction failed: {exc}")

        if not config_decoded:
            limitations.append(
                "Network security config XML was referenced but could not be decoded; trust "
                "anchors and certificate pinning are unknown."
            )
    else:
        limitations.append(
            "No network security config is declared; platform defaults apply to trust "
            "anchors and certificate pinning."
        )

    result_data: dict[str, Any] = {
        "uses_cleartext_traffic": application.uses_cleartext_traffic,
        "effective_cleartext_traffic": application.effective_cleartext_traffic,
        "network_security_config": application.network_security_config,
        "debuggable": application.debuggable,
        "network_config_decoded": config_decoded,
        "trust_anchors_known": trust_anchors_known,
        "limitations": limitations,
    }
    if decoded_config is not None:
        result_data["config"] = decoded_config

    return ToolOutcome(
        data=result_data,
        evidence_ids=report.evidence_ids,
        warnings=limitations if not config_decoded else [],
    )


async def _android_get_exported_surface(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report, manifest = _manifest_of(ctx, args)
    exported = manifest.exported_components
    components = [
        {
            "kind": component.kind,
            "name": component.name,
            "permission": component.permission,
            "permission_protected": component.permission_protected,
            "exported_source": component.exported_source,
            "launcher": component.launcher,
            "authorities": component.authorities,
        }
        for component in exported
    ]
    unprotected = [component for component in exported if not component.permission_protected]
    return ToolOutcome(
        data={
            "components": components,
            "count": len(components),
            "unprotected_count": len(unprotected),
            "deep_links": [link.model_dump(mode="json") for link in manifest.deep_links],
            "deep_link_count": len(manifest.deep_links),
            "limitations": [
                "Exported status reflects manifest declarations; runtime reachability "
                "and permission enforcement are not verified.",
            ],
        },
        evidence_ids=report.evidence_ids,
    )


def _resource_table_of(
    ctx: ToolContext,
    args: JobInput,
) -> tuple[AnalysisReport, ParsedResourceTable]:
    report = report_of(ctx, args.project_id, args.job_id)
    if report.resource_summary is None:
        raise StateError(
            "Resource data is not available for this analysis job.",
            hint=report.resource_error or "Run analysis_start with the resources stage enabled.",
            details={"job_id": args.job_id},
        )
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    try:
        table = decode_resource_table(
            path,
            artifact.artifact_type,
            max_bytes=ctx.runtime.settings.max_resource_bytes,
        )
    except RAAError as exc:
        raise StateError(
            "Resource table could not be decoded for this job.",
            hint=f"{exc.code}: {exc.message}",
            details={"job_id": args.job_id, "code": exc.code},
        ) from exc
    return report, table


def _group_resources(
    entries: list[ParsedResourceEntry],
) -> dict[int, list[ParsedResourceEntry]]:
    groups: dict[int, list[ParsedResourceEntry]] = {}
    for entry in entries:
        groups.setdefault(entry.resource_id, []).append(entry)
    return groups


def _parse_resource_id(value: str) -> int:
    text = value.strip().lower()
    try:
        resource_id = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError as exc:
        raise InvalidArgumentsError(
            f"Invalid resource ID: {value}",
            hint="Use a hexadecimal ID such as '0x7f010000' or a decimal integer.",
        ) from exc
    if not 0 <= resource_id <= 0xFFFFFFFF:
        raise InvalidArgumentsError(
            f"Resource ID is out of range: {value}",
            hint="Resource IDs are 32-bit unsigned integers.",
        )
    return resource_id


def _default_variant(
    variants: list[ParsedResourceEntry],
) -> ParsedResourceEntry:
    for variant in variants:
        if variant.is_default:
            return variant
    return variants[0]


async def _android_list_resources(
    ctx: ToolContext,
    args: ResourceListInput,
) -> ToolOutcome:
    report, table = _resource_table_of(ctx, args)
    groups = _group_resources(table.entries)
    selected: list[tuple[int, list[ParsedResourceEntry]]] = []
    for resource_id, variants in groups.items():
        first = variants[0]
        if args.type is not None and first.type != args.type:
            continue
        if args.name is not None and first.name != args.name:
            continue
        if args.config is not None and not any(
            variant.config == args.config for variant in variants
        ):
            continue
        if args.default_only and not any(variant.is_default for variant in variants):
            continue
        selected.append((resource_id, variants))
    selected.sort(key=lambda item: (item[1][0].type, item[1][0].name, item[0]))
    page = selected[args.offset : args.offset + args.limit]

    resources = []
    for resource_id, variants in page:
        first = variants[0]
        default = _default_variant(variants)
        infos = [variant.variant_info() for variant in variants]
        file_reference = next(
            (info.file_reference for info in infos if info.file_reference is not None),
            None,
        )
        resources.append(
            {
                "resource_id": f"0x{resource_id:08x}",
                "package": first.package,
                "type": first.type,
                "name": first.name,
                "variant_count": len(variants),
                "configs": [variant.config for variant in variants],
                "complex": any(variant.complex for variant in variants),
                "default_config": default.config,
                "default_value": (
                    default.value.to_info().model_dump(mode="json")
                    if default.value is not None
                    else None
                ),
                "file_reference": file_reference,
            }
        )
    return ToolOutcome(
        data={
            "resources": resources,
            "count": len(resources),
            "total": len(selected),
            "summary": table.summary().model_dump(mode="json"),
            "limitations": table.limitations,
        },
        evidence_ids=report.evidence_ids,
    )


async def _android_get_resource(
    ctx: ToolContext,
    args: ResourceGetInput,
) -> ToolOutcome:
    if bool(args.resource_id) == bool(args.name):
        raise InvalidArgumentsError(
            "Provide exactly one of resource_id or name.",
            hint="Use resource_id for an exact ID, or name with an optional type.",
        )
    report, table = _resource_table_of(ctx, args)

    if args.resource_id is not None:
        resource_id = _parse_resource_id(args.resource_id)
        variants = [entry for entry in table.entries if entry.resource_id == resource_id]
        lookup = f"0x{resource_id:08x}"
    elif args.name is not None:
        variants = [
            entry
            for entry in table.entries
            if entry.name == args.name and (args.type is None or entry.type == args.type)
        ]
        resource_ids = {entry.resource_id for entry in variants}
        if len(resource_ids) > 1:
            raise InvalidArgumentsError(
                f"Resource name '{args.name}' is ambiguous.",
                hint="Add a type or use android_list_resources to choose an ID.",
                details={"resource_ids": [f"0x{item:08x}" for item in sorted(resource_ids)]},
            )
        lookup = args.name
    else:
        raise InvalidArgumentsError(
            "Either resource_id or name must be provided.",
            hint="Specify --resource-id or --name.",
        )
        lookup = args.name + (f" ({args.type})" if args.type else "")

    if args.config is not None:
        variants = [entry for entry in variants if entry.config == args.config]
    if not variants:
        raise NotFoundError(
            f"Resource not found: {lookup}",
            hint="Call android_list_resources to discover available resources.",
        )

    first = variants[0]
    infos = [variant.variant_info() for variant in variants]
    file_references = sorted(
        {info.file_reference for info in infos if info.file_reference is not None}
    )
    return ToolOutcome(
        data={
            "resource_id": f"0x{first.resource_id:08x}",
            "package": first.package,
            "type": first.type,
            "name": first.name,
            "variant_count": len(infos),
            "variants": [info.model_dump(mode="json") for info in infos],
            "file_references": file_references,
            "limitations": table.limitations,
        },
        evidence_ids=report.evidence_ids,
    )


def _dex_index_of(
    ctx: ToolContext,
    args: JobInput,
    *,
    references: bool = False,
) -> tuple[AnalysisReport, DexIndex]:
    report = report_of(ctx, args.project_id, args.job_id)
    if report.dex_summary is None:
        raise StateError(
            "DEX index data is not available for this analysis job.",
            hint=report.dex_error or "Run analysis_start with the code stage enabled.",
            details={"job_id": args.job_id},
        )
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    try:
        index = decode_dex_index(
            path,
            artifact.artifact_type,
            max_bytes=ctx.runtime.settings.max_dex_bytes,
            include_references=references,
            max_instruction_units=ctx.runtime.settings.max_dex_instruction_units,
            max_references=ctx.runtime.settings.max_dex_references,
        )
    except RAAError as exc:
        raise StateError(
            "DEX files could not be indexed for this job.",
            hint=f"{exc.code}: {exc.message}",
            details={"job_id": args.job_id, "code": exc.code},
        ) from exc
    return report, index


def _dex_warnings(index: DexIndex) -> list[str]:
    warnings = [f"{name}: {error}" for name, error in index.errors]
    for dex in index.files:
        if dex.checksum_valid is False or dex.signature_valid is False:
            warnings.append(f"{dex.name}: checksum or signature does not match the file contents.")
        warnings.extend(f"{dex.name}: {warning}" for warning in dex.reference_warnings)
    return warnings


def _search_matches(text: str, needle: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return needle in text
    return needle in text.casefold()


async def _source_search(ctx: ToolContext, args: SourceSearchInput) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args)
    needle = args.query if args.case_sensitive else args.query.casefold()
    results: list[dict[str, object]] = []

    for dex in index.files:
        for parsed in dex.classes:
            if args.kind in {None, "class"} and any(
                _search_matches(value, needle, case_sensitive=args.case_sensitive)
                for value in (parsed.name, parsed.descriptor)
            ):
                results.append(
                    {
                        "kind": "class",
                        "class": parsed.name,
                        "descriptor": parsed.descriptor,
                        "dex_file": dex.name,
                    }
                )
            if args.kind in {None, "method"}:
                for method in parsed.methods:
                    haystack = (
                        parsed.name,
                        parsed.descriptor,
                        method.name,
                        method.descriptor,
                        f"{parsed.name}#{method.name}",
                    )
                    if any(
                        _search_matches(value, needle, case_sensitive=args.case_sensitive)
                        for value in haystack
                    ):
                        results.append(
                            {
                                "kind": "method",
                                "class": parsed.name,
                                "name": method.name,
                                "descriptor": method.descriptor,
                                "access": method.info.access,
                                "has_code": method.code_offset is not None,
                                "dex_file": dex.name,
                            }
                        )
            if args.kind in {None, "field"}:
                for field in parsed.fields:
                    haystack = (
                        parsed.name,
                        parsed.descriptor,
                        field.name,
                        field.descriptor,
                        f"{parsed.name}#{field.name}",
                    )
                    if any(
                        _search_matches(value, needle, case_sensitive=args.case_sensitive)
                        for value in haystack
                    ):
                        results.append(
                            {
                                "kind": "field",
                                "class": parsed.name,
                                "name": field.name,
                                "descriptor": field.descriptor,
                                "access": field.info.access,
                                "dex_file": dex.name,
                            }
                        )
        if args.kind in {None, "string"}:
            for value in dex.strings:
                if _search_matches(value, needle, case_sensitive=args.case_sensitive):
                    results.append(
                        {
                            "kind": "string",
                            "value": value,
                            "dex_file": dex.name,
                        }
                    )

    results.sort(
        key=lambda item: (
            str(item["kind"]),
            str(item.get("class", "")),
            str(item.get("name", "")),
            str(item.get("descriptor", "")),
            str(item.get("value", "")),
            str(item["dex_file"]),
        )
    )
    page = results[args.offset : args.offset + args.limit]
    summary = index.summary()
    warnings = _dex_warnings(index)
    return ToolOutcome(
        data={
            "query": args.query,
            "kind": args.kind,
            "case_sensitive": args.case_sensitive,
            "results": page,
            "count": len(page),
            "total": len(results),
            "limit": args.limit,
            "offset": args.offset,
            "has_more": args.offset + len(page) < len(results),
            "summary": summary.model_dump(mode="json"),
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=warnings,
    )


def _resolve_class(index: DexIndex, value: str) -> tuple[ParsedClass, list[ParsedClass]]:
    text = value.strip()
    descriptor = (
        text if text.startswith("L") and text.endswith(";") else f"L{text.replace('.', '/')};"
    )
    matches = [
        parsed for parsed in index.classes if parsed.name == text or parsed.descriptor == descriptor
    ]
    if not matches and "." not in text and "/" not in text:
        matches = [parsed for parsed in index.classes if parsed.name.rsplit(".", 1)[-1] == text]
    if not matches:
        raise NotFoundError(
            f"Class not found: {value}",
            hint="Call source_search with a class-name fragment to discover classes.",
        )
    grouped: dict[str, list[ParsedClass]] = {}
    for parsed in matches:
        grouped.setdefault(parsed.descriptor, []).append(parsed)
    if len(grouped) > 1:
        raise InvalidArgumentsError(
            f"Class name '{value}' is ambiguous.",
            hint="Use a fully qualified class name or JVM descriptor.",
            details={
                "candidates": [
                    {"class": items[0].name, "descriptor": descriptor_value}
                    for descriptor_value, items in sorted(grouped.items())
                ]
            },
        )
    group = next(iter(grouped.values()))
    return group[0], group[1:]


async def _source_get_class(ctx: ToolContext, args: SourceClassInput) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args)
    parsed, duplicates = _resolve_class(index, args.class_name)
    detail = parsed.detail(offset=args.offset, limit=args.limit)
    summary = index.summary()
    warnings = _dex_warnings(index)
    if duplicates:
        warnings.append(
            f"{parsed.descriptor} is defined in multiple DEX files; showing {parsed.dex_file}."
        )

    source: dict[str, object] | None = None
    if args.include_source:
        artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
        path = ctx.runtime.artifacts.path_for(artifact)
        max_bytes = ctx.runtime.settings.engine_max_file_bytes
        adapter = JadxAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        source = adapter.decompile_class(
            path,
            args.class_name,
            offset=args.source_offset,
            limit=min(args.source_limit, max_bytes),
            max_bytes=max_bytes,
        )

    return ToolOutcome(
        data={
            **detail.model_dump(mode="json"),
            "member_limit": args.limit,
            "member_offset": args.offset,
            "include_source": args.include_source,
            "source": source,
            "duplicate_in": [item.dex_file for item in duplicates],
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=warnings,
    )


def _resolve_method(
    parsed: ParsedClass,
    method_name: str,
    descriptor: str | None,
) -> list[ParsedMethod]:
    methods = [
        method
        for method in parsed.methods
        if method.name == method_name and (descriptor is None or method.descriptor == descriptor)
    ]
    if not methods:
        raise NotFoundError(
            f"Method not found: {parsed.name}#{method_name}{descriptor or ''}",
            hint="Call source_get_class or source_search to discover declared methods.",
            details={
                "class": parsed.name,
                "method": method_name,
                "descriptor": descriptor,
            },
        )
    return methods


async def _source_get_method(ctx: ToolContext, args: SourceMethodInput) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args, references=True)
    parsed, duplicates = _resolve_class(index, args.class_name)
    methods = _resolve_method(parsed, args.method_name, args.descriptor)
    descriptors = {method.descriptor for method in methods}

    outgoing: list[dict[str, object]] = []
    incoming: list[dict[str, object]] = []
    for reference in index.references:
        if (
            reference.from_class == parsed.name
            and reference.from_method == args.method_name
            and reference.from_descriptor in descriptors
        ):
            outgoing.append(reference.info.model_dump(mode="json"))
        if (
            reference.kind == "method_call"
            and reference.target_class == parsed.name
            and reference.target_name == args.method_name
            and reference.target_descriptor in descriptors
        ):
            incoming.append(reference.info.model_dump(mode="json"))

    combined = [{"direction": "outgoing", **item} for item in outgoing] + [
        {"direction": "incoming", **item} for item in incoming
    ]
    combined.sort(
        key=lambda item: (
            str(item["direction"]),
            str(item["kind"]),
            str(item["offset"]),
            str(item["target"]),
            str(item["dex_file"]),
        )
    )
    page = combined[args.offset : args.offset + args.limit]

    source: dict[str, object] | None = None
    if args.include_source:
        artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
        path = ctx.runtime.artifacts.path_for(artifact)
        max_bytes = ctx.runtime.settings.engine_max_file_bytes
        adapter = JadxAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        source = adapter.decompile_method(
            path,
            args.class_name,
            args.method_name,
            offset=args.source_offset,
            limit=min(args.source_limit, max_bytes),
            max_bytes=max_bytes,
        )

    summary = index.summary()
    warnings = _dex_warnings(index)
    if duplicates:
        warnings.append(
            f"{parsed.descriptor} is defined in multiple DEX files; references may be merged."
        )
    return ToolOutcome(
        data={
            "class": parsed.name,
            "method": args.method_name,
            "methods": [method.info.model_dump(mode="json") for method in methods],
            "method_descriptors": sorted(descriptors),
            "references": page,
            "count": len(page),
            "total": len(combined),
            "outgoing_count": len(outgoing),
            "incoming_count": len(incoming),
            "limit": args.limit,
            "offset": args.offset,
            "has_more": args.offset + len(page) < len(combined),
            "include_source": args.include_source,
            "source": source,
            "duplicate_in": [item.dex_file for item in duplicates],
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=warnings,
    )


async def _source_get_smali(ctx: ToolContext, args: SourceSmaliInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    max_bytes = ctx.runtime.settings.engine_max_file_bytes
    adapter = ApktoolAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
    payload = adapter.decode_smali(
        path,
        args.class_name,
        offset=args.offset,
        limit=min(args.limit, max_bytes),
        max_bytes=max_bytes,
    )
    return ToolOutcome(
        data={
            "class": args.class_name,
            **payload,
            "limitations": [
                "Apktool Smali is a bounded engine result, not decompiled Java source.",
                "Engine execution is disabled by default and must be enabled explicitly.",
            ],
        },
        evidence_ids=report.evidence_ids,
        warnings=[
            "External engine output is labelled with the engine id and operation.",
        ],
    )


async def _source_find_references(
    ctx: ToolContext,
    args: SourceReferenceSearchInput,
) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args, references=True)
    needle = args.query if args.case_sensitive else args.query.casefold()
    matches = []
    for reference in index.references:
        if args.kind != "any" and reference.kind != args.kind:
            continue
        values = (
            reference.target,
            reference.target_class or "",
            reference.target_name or "",
            reference.target_descriptor or "",
            reference.value or "",
        )
        if any(
            _search_matches(value, needle, case_sensitive=args.case_sensitive) for value in values
        ):
            matches.append(reference.info)
    matches.sort(
        key=lambda item: (
            item.kind,
            item.from_class,
            item.from_method,
            item.from_descriptor,
            item.offset,
            item.target,
            item.dex_file,
        )
    )
    page = matches[args.offset : args.offset + args.limit]
    summary = index.summary()
    return ToolOutcome(
        data={
            "query": args.query,
            "kind": args.kind,
            "case_sensitive": args.case_sensitive,
            "references": [item.model_dump(mode="json") for item in page],
            "count": len(page),
            "total": len(matches),
            "limit": args.limit,
            "offset": args.offset,
            "has_more": args.offset + len(page) < len(matches),
            "reference_total": len(index.references),
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=_dex_warnings(index),
    )


async def _source_get_callers(
    ctx: ToolContext,
    args: SourceRelationInput,
) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args, references=True)
    parsed, duplicates = _resolve_class(index, args.class_name)
    methods = _resolve_method(parsed, args.method_name, args.descriptor)
    descriptors = {method.descriptor for method in methods}

    grouped: dict[tuple[str, str, str, str], list[int]] = {}
    for reference in index.references:
        if (
            reference.kind == "method_call"
            and reference.target_class == parsed.name
            and reference.target_name == args.method_name
            and reference.target_descriptor in descriptors
        ):
            key = (
                reference.from_class,
                reference.from_method,
                reference.from_descriptor,
                reference.dex_file,
            )
            grouped.setdefault(key, []).append(reference.offset)

    callers = [
        {
            "class": key[0],
            "method": key[1],
            "descriptor": key[2],
            "dex_file": key[3],
            "call_site_count": len(offsets),
            "first_offset": min(offsets),
        }
        for key, offsets in grouped.items()
    ]
    callers.sort(
        key=lambda item: (
            item["class"],
            item["method"],
            item["descriptor"],
            item["dex_file"],
        )
    )
    page = callers[args.offset : args.offset + args.limit]
    summary = index.summary()
    warnings = _dex_warnings(index)
    if duplicates:
        warnings.append(
            f"{parsed.descriptor} is defined in multiple DEX files; targets may be merged."
        )
    return ToolOutcome(
        data={
            "class": parsed.name,
            "method": args.method_name,
            "method_descriptors": sorted(descriptors),
            "callers": page,
            "count": len(page),
            "total": len(callers),
            "call_site_total": sum(len(offsets) for offsets in grouped.values()),
            "limit": args.limit,
            "offset": args.offset,
            "has_more": args.offset + len(page) < len(callers),
            "note": None if callers else "No call sites were found in indexed bytecode.",
            "duplicate_in": [item.dex_file for item in duplicates],
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=warnings,
    )


async def _source_get_callees(
    ctx: ToolContext,
    args: SourceRelationInput,
) -> ToolOutcome:
    report, index = _dex_index_of(ctx, args, references=True)
    parsed, duplicates = _resolve_class(index, args.class_name)
    methods = _resolve_method(parsed, args.method_name, args.descriptor)
    descriptors = {method.descriptor for method in methods}
    known_names = {klass.name for klass in index.classes}

    grouped: dict[tuple[str | None, str | None, str | None], list[int]] = {}
    for reference in index.references:
        if (
            reference.kind == "method_call"
            and reference.from_class == parsed.name
            and reference.from_method == args.method_name
            and reference.from_descriptor in descriptors
        ):
            key = (reference.target_class, reference.target_name, reference.target_descriptor)
            grouped.setdefault(key, []).append(reference.offset)

    callees = [
        {
            "class": key[0],
            "method": key[1],
            "descriptor": key[2],
            "call_site_count": len(offsets),
            "first_offset": min(offsets),
            "external": key[0] not in known_names,
        }
        for key, offsets in grouped.items()
    ]
    callees.sort(
        key=lambda item: (
            item["class"] or "",
            item["method"] or "",
            item["descriptor"] or "",
        )
    )
    page = callees[args.offset : args.offset + args.limit]
    summary = index.summary()
    warnings = _dex_warnings(index)
    if duplicates:
        warnings.append(
            f"{parsed.descriptor} is defined in multiple DEX files; results may be merged."
        )
    return ToolOutcome(
        data={
            "class": parsed.name,
            "method": args.method_name,
            "method_descriptors": sorted(descriptors),
            "callees": page,
            "count": len(page),
            "total": len(callees),
            "call_site_total": sum(len(offsets) for offsets in grouped.values()),
            "limit": args.limit,
            "offset": args.offset,
            "has_more": args.offset + len(page) < len(callees),
            "note": None if callees else "No method calls were found in indexed bytecode.",
            "duplicate_in": [item.dex_file for item in duplicates],
            "limitations": summary.limitations,
        },
        evidence_ids=report.evidence_ids,
        warnings=warnings,
    )


async def _framework_list_detected(ctx: ToolContext, args: JobInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    return ToolOutcome(
        data={
            "frameworks": [framework.model_dump(mode="json") for framework in report.frameworks],
            "count": len(report.frameworks),
        },
        evidence_ids=report.evidence_ids,
    )


async def _packer_detect(ctx: ToolContext, args: PackerDetectInput) -> ToolOutcome:
    report = None
    if args.job_id:
        with contextlib.suppress(Exception):
            report = report_of(ctx, args.project_id, args.job_id)

    packers: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    if report:
        packers = [packer.model_dump(mode="json") for packer in report.packers]
        evidence_ids.extend(report.evidence_ids)

    warnings = [
        "Packer detection is a heuristic/signature scan in this build. Confirm with "
        "APKiD or an authorized dump."
    ]
    apkid_result = None

    unpack_report = None
    target_aid = args.artifact_id or (report.artifact_id if report else None)
    try:
        unpack_report = ctx.runtime.unpacking.detect_packers(
            project_id=args.project_id,
            artifact_id=target_aid,
        )
    except Exception as exc:
        warnings.append(f"Unpacking engine scan note: {exc}")

    if unpack_report is not None:
        target_aid = unpack_report.artifact_id
        for p in unpack_report.packers + unpack_report.protectors:
            p_dict = p.model_dump(mode="json")
            if p_dict not in packers:
                packers.append(p_dict)

    if args.include_apkid and target_aid:
        artifact = ctx.runtime.artifacts.get_or_raise(args.project_id, target_aid)
        path = ctx.runtime.artifacts.path_for(artifact)
        adapter = ApkidAdapter(ctx.runtime.engine_runner, ctx.runtime.workspace)
        apkid_result = adapter.scan(path)
        warnings.append("APKiD scan completed.")

    result_data: dict[str, Any] = {
        "project_id": args.project_id,
        "packers": packers,
        "count": len(packers),
        "method": "filename heuristic" if not apkid_result else "filename heuristic + APKiD",
    }
    if target_aid is not None:
        result_data["artifact_id"] = target_aid
    if unpack_report is not None:
        result_data["is_packed"] = unpack_report.is_packed
        result_data["protectors"] = [p.model_dump(mode="json") for p in unpack_report.protectors]
        result_data["obfuscators"] = [o.model_dump(mode="json") for o in unpack_report.obfuscators]
        result_data["compilers"] = [c.model_dump(mode="json") for c in unpack_report.compilers]
        result_data["anti_analysis"] = [
            a.model_dump(mode="json") for a in unpack_report.anti_analysis
        ]
        result_data["entropy_score"] = unpack_report.entropy_score
    if apkid_result is not None:
        result_data["apkid"] = apkid_result

    return ToolOutcome(
        data=result_data,
        evidence_ids=evidence_ids,
        warnings=warnings,
    )


async def _source_get_file(ctx: ToolContext, args: SourceGetFileInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    artifact_path = ctx.runtime.artifacts.path_for(artifact)
    max_bytes = ctx.runtime.settings.engine_max_file_bytes

    clean_path = args.file_path.replace("\\", "/").strip().lstrip("/")
    parts = clean_path.split("/")
    if any(p in {"..", "."} for p in parts):
        raise InvalidArgumentsError(
            f"Path traversal characters are forbidden: {args.file_path}",
            details={"file_path": args.file_path},
        )

    raw_data: bytes | None = None
    resolved_source = "unknown"

    if args.source in {"auto", "workspace"}:
        candidate = (ctx.runtime.workspace.root / clean_path).resolve()
        if candidate.is_file() and ctx.runtime.workspace.is_within(candidate):
            raw_data = candidate.read_bytes()
            resolved_source = "workspace"

    if raw_data is None and args.source in {"auto", "archive"}:
        try:
            with zipfile.ZipFile(artifact_path, "r") as archive:
                entry_name = None
                if clean_path in archive.namelist():
                    entry_name = clean_path
                else:
                    lowered = clean_path.lower()
                    for name in archive.namelist():
                        if name.lower() == lowered:
                            entry_name = name
                            break
                if entry_name is not None:
                    raw_data = archive.read(entry_name)
                    resolved_source = "archive"
        except Exception as exc:
            raise InvalidArtifactError(f"Could not read artifact archive: {exc}") from exc

    if raw_data is None:
        raise NotFoundError(
            f"File not found: {args.file_path}",
            hint="Check artifact_list_files or verify the file exists in the archive or workspace.",
            details={"file_path": args.file_path, "source": args.source},
        )

    byte_count = len(raw_data)
    start = max(0, min(args.offset, byte_count))
    end = min(start + min(args.limit, max_bytes), byte_count)
    slice_data = raw_data[start:end]

    is_binary = False
    try:
        text = slice_data.decode("utf-8")
    except UnicodeDecodeError:
        text = slice_data.decode("latin-1", errors="replace")
        is_binary = True

    return ToolOutcome(
        data={
            "file_path": clean_path,
            "source": resolved_source,
            "byte_count": byte_count,
            "offset": start,
            "limit": end - start,
            "truncated": end < byte_count,
            "is_binary": is_binary,
            "text": text,
        },
        evidence_ids=report.evidence_ids,
    )


async def _source_rename_symbol(ctx: ToolContext, args: SourceRenameSymbolInput) -> ToolOutcome:
    from raa.services.android.symbol_rename import SymbolRenameRegistry

    reg = getattr(ctx.runtime, "_symbol_registry", None)
    if reg is None:
        reg = SymbolRenameRegistry()
        ctx.runtime._symbol_registry = reg  # type: ignore[attr-defined]

    reg.add_mapping(args.symbol_type, args.original_name, args.renamed_name)
    data = reg.to_dict()
    data["last_renamed"] = {
        "type": args.symbol_type,
        "original": args.original_name,
        "renamed": args.renamed_name,
    }
    if args.export_mapping:
        data["proguard_mapping"] = reg.export_proguard_mapping()

    return ToolOutcome(data=data)


def _read_file_bytes(path_str: str | None) -> bytes | None:
    if not path_str:
        return None
    p = Path(path_str)
    if p.exists() and p.is_file():
        return p.read_bytes()
    return None


def _read_file_text(path_str: str | None) -> str | None:
    if not path_str:
        return None
    p = Path(path_str)
    if p.exists() and p.is_file():
        with contextlib.suppress(Exception):
            return p.read_text(encoding="utf-8", errors="ignore")
    return None


def _find_appfunction_xmls(dir_str: str | None) -> list[str]:
    if not dir_str:
        return []
    p = Path(dir_str)
    if not p.exists() or not p.is_dir():
        return []
    xmls: list[str] = []
    for xml_file in p.glob("**/*.xml"):
        with contextlib.suppress(Exception):
            content = xml_file.read_text(encoding="utf-8", errors="ignore")
            if "appfunction" in content.lower() or "app-function" in content.lower():
                xmls.append(content)
    return xmls


async def _ai_model_inspect(ctx: ToolContext, args: AiModelInspectInput) -> ToolOutcome:
    import base64

    raw_bytes = (
        b"\x00\x00\x00\x00TFL3\x00\x00\x00\x00CONV_2D\x00SOFTMAX\x00"
        b"input_tensor\x00output_logits\x00"
    )
    loaded = _read_file_bytes(args.model_path)
    if loaded is not None:
        raw_bytes = loaded
    elif args.raw_content_b64:
        with contextlib.suppress(Exception):
            raw_bytes = base64.b64decode(args.raw_content_b64)
    model_name = args.model_name or (
        Path(args.model_path).name if args.model_path else "model.tflite"
    )
    res = inspect_ai_model(raw_bytes, file_name=model_name)
    return ToolOutcome(data=res)


async def _ai_prompt_extract(ctx: ToolContext, args: AiPromptExtractInput) -> ToolOutcome:
    corpus: list[str] = []
    if args.corpus_text:
        corpus.append(args.corpus_text)
    loaded = _read_file_text(args.artifact_path)
    if loaded:
        corpus.append(loaded)
    res = extract_ai_prompts(corpus)
    return ToolOutcome(data=res)


async def _ai_appfunction_discover(
    ctx: ToolContext, args: AiAppFunctionDiscoverInput
) -> ToolOutcome:
    metadata_xmls = [args.metadata_xml] if args.metadata_xml else []
    metadata_xmls.extend(_find_appfunction_xmls(args.decompiled_dir))
    res = discover_app_functions(metadata_xmls=metadata_xmls)
    return ToolOutcome(data=res)


async def _wasm_decompile(ctx: ToolContext, args: WasmDecompileInput) -> ToolOutcome:
    from raa.services.source.wasm_decompiler import decompile_wasm

    res = decompile_wasm(
        wasm_bytes_or_hex=args.wasm_bytes_hex,
        file_path=args.file_path,
    )
    return ToolOutcome(data=res)


async def _report_generate(ctx: ToolContext, args: ReportGenerateInput) -> ToolOutcome:
    report = report_of(ctx, args.project_id, args.job_id)
    export = write_report(
        report,
        format=args.format,
        workspace=ctx.runtime.workspace,
        filename=args.filename,
    )
    return ToolOutcome(data=export, evidence_ids=report.evidence_ids)


def _job_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: ToolHandler,
    profiles: frozenset[str] = CORE,
    input_model: type[ToolInput] = JobInput,
    family: str = "analysis",
    cost: ToolCost = "fast",
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family=family,
        profiles=profiles,
        scopes=frozenset({"project.read", "static.read"}),
        annotations=ToolAnnotations(read_only=True),
        cost=cost,
    )


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="analysis_start",
            title="Start analysis",
            description=(
                "Queue the built-in static inspection for an artifact. The job "
                "hashes inventory, container, manifest, resources, code, framework, "
                "signature and native-library stages."
            ),
            input_model=AnalysisStartInput,
            handler=_analysis_start,
            family="analysis",
            profiles=MINIMAL,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
            cost="slow",
        )
    )
    registry.register(
        ToolSpec(
            name="analysis_get_status",
            title="Get analysis status",
            description="Return job status, progress, stages and terminal error information.",
            input_model=JobInput,
            handler=_analysis_get_status,
            family="analysis",
            profiles=MINIMAL,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="analysis_cancel",
            title="Cancel analysis",
            description="Request cooperative cancellation of a queued or running analysis job.",
            input_model=JobInput,
            handler=_analysis_cancel,
            family="analysis",
            profiles=CORE,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
        )
    )
    registry.register(
        ToolSpec(
            name="analysis_get_report",
            title="Get analysis report",
            description=(
                "Return the completed report with frameworks, findings and evidence identifiers."
            ),
            input_model=JobInput,
            handler=_analysis_get_report,
            family="analysis",
            profiles=MINIMAL,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="report_generate",
            title="Export report",
            description="Write a JSON or Markdown report into the project export directory.",
            input_model=ReportGenerateInput,
            handler=_report_generate,
            family="analysis",
            profiles=CORE,
            scopes=frozenset({"project.read", "export.write"}),
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
        )
    )
    registry.register(
        _job_spec(
            name="android_list_dex",
            title="List DEX files",
            description="List DEX files recorded by a completed analysis job.",
            handler=_android_list_dex,
        )
    )
    registry.register(
        _job_spec(
            name="android_list_native_libraries",
            title="List native libraries",
            description="List native libraries and ABIs recorded by a completed analysis job.",
            handler=_android_list_native_libraries,
        )
    )
    registry.register(
        _job_spec(
            name="android_get_certificate_info",
            title="Get signing information",
            description="Return v1 certificate file names and APK Signing Block presence.",
            handler=_android_get_certificate_info,
        )
    )
    registry.register(
        _job_spec(
            name="android_get_manifest",
            title="Get Android manifest",
            description=(
                "Return decoded package metadata, SDK levels, permissions, features, "
                "application flags, components and deep links."
            ),
            handler=_android_get_manifest,
            profiles=MINIMAL,
        )
    )
    registry.register(
        _job_spec(
            name="android_list_components",
            title="List manifest components",
            description=(
                "List activities, aliases, services, receivers and providers with "
                "explicit and effective exported status."
            ),
            handler=_android_list_components,
            input_model=ComponentListInput,
        )
    )
    registry.register(
        _job_spec(
            name="android_list_permissions",
            title="List permissions and features",
            description=(
                "List requested and declared permissions plus uses-feature entries "
                "from the decoded manifest."
            ),
            handler=_android_list_permissions,
        )
    )
    registry.register(
        _job_spec(
            name="android_get_network_config",
            title="Get network configuration",
            description=(
                "Return cleartext traffic, debuggable status and network security "
                "config references, with explicit decoding limits."
            ),
            handler=_android_get_network_config,
        )
    )
    registry.register(
        _job_spec(
            name="android_get_exported_surface",
            title="Get exported surface",
            description=(
                "Return effectively exported components, permission guards and "
                "deep-link declarations from the manifest."
            ),
            handler=_android_get_exported_surface,
        )
    )
    registry.register(
        _job_spec(
            name="android_list_resources",
            title="List Android resources",
            description=(
                "List resources.arsc entries grouped by resource ID with type, name, "
                "configuration count and default value. Decodes the table on demand."
            ),
            handler=_android_list_resources,
            input_model=ResourceListInput,
        )
    )
    registry.register(
        _job_spec(
            name="android_get_resource",
            title="Get Android resource",
            description=(
                "Return every configuration variant of one resource, selected by "
                "resource ID or exact name and optional type."
            ),
            handler=_android_get_resource,
            input_model=ResourceGetInput,
        )
    )
    registry.register(
        _job_spec(
            name="source_search",
            title="Search DEX metadata",
            description=(
                "Search indexed classes, methods, fields and DEX strings by fragment. "
                "Results are paginated and include the DEX file that declared them."
            ),
            handler=_source_search,
            input_model=SourceSearchInput,
            family="source",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_class",
            title="Get DEX class",
            description=(
                "Return one class with superclass, interfaces, source file, access "
                "flags and bounded field and method lists."
            ),
            handler=_source_get_class,
            input_model=SourceClassInput,
            family="source",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_method",
            title="Get DEX method",
            description=(
                "Return one declared method with access metadata and bounded "
                "outgoing/incoming bytecode references. Optionally includes "
                "JADX-decompiled class source when external engines are enabled."
            ),
            handler=_source_get_method,
            input_model=SourceMethodInput,
            family="source",
            cost="slow",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_smali",
            title="Get class Smali",
            description=(
                "Decode one class to Smali with Apktool and return a bounded, "
                "paginated view. Requires external engine execution to be enabled."
            ),
            handler=_source_get_smali,
            input_model=SourceSmaliInput,
            family="source",
            cost="slow",
        )
    )
    registry.register(
        _job_spec(
            name="source_find_references",
            title="Find DEX references",
            description=(
                "Find bytecode references to classes, methods, fields, types or strings. "
                "Results are paginated and include the declaring method and code offset."
            ),
            handler=_source_find_references,
            input_model=SourceReferenceSearchInput,
            family="source",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_callers",
            title="List method callers",
            description=(
                "List distinct methods that call a declared method, aggregated from "
                "bounded DEX bytecode reference scanning."
            ),
            handler=_source_get_callers,
            input_model=SourceRelationInput,
            family="source",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_callees",
            title="List method callees",
            description=(
                "List distinct methods called by a declared method, with call-site "
                "counts and a flag for targets outside the indexed class set."
            ),
            handler=_source_get_callees,
            input_model=SourceRelationInput,
            family="source",
        )
    )
    registry.register(
        _job_spec(
            name="source_get_file",
            title="Get source or resource file",
            description=(
                "Retrieve a decoded source file, resource XML or archive entry by "
                "safe relative path, bounded and paginated."
            ),
            handler=_source_get_file,
            input_model=SourceGetFileInput,
            family="source",
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="source_rename_symbol",
            title="Rename obfuscated symbol",
            description=(
                "Rename an obfuscated class, method, or field and propagate across "
                "decompiled views and mapping.txt."
            ),
            input_model=SourceRenameSymbolInput,
            handler=_source_rename_symbol,
            family="source",
            profiles=CORE,
            scopes=frozenset({"project.read", "project.write"}),
            annotations=ToolAnnotations(read_only=False, idempotent=False),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="ai_model_inspect",
            title="Inspect on-device AI model",
            description=(
                "Inspect on-device machine learning models (TFLite, LiteRT, ONNX), "
                "operators, quantizations, and privacy sensitivities."
            ),
            input_model=AiModelInspectInput,
            handler=_ai_model_inspect,
            family="analysis",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="ai_prompt_extract",
            title="Extract embedded AI prompts",
            description=(
                "Extract embedded LLM system prompts, instruction templates, "
                "and RAG vector database configurations."
            ),
            input_model=AiPromptExtractInput,
            handler=_ai_prompt_extract,
            family="analysis",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="ai_appfunction_discover",
            title="Discover Android 16 AppFunctions",
            description=(
                "Discover Android 16 AppFunctions and assistant tool declarations "
                "exposed to AI agents."
            ),
            input_model=AiAppFunctionDiscoverInput,
            handler=_ai_appfunction_discover,
            family="analysis",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
            cost="fast",
        )
    )
    registry.register(
        _job_spec(
            name="framework_list_detected",
            title="List detected frameworks",
            description=(
                "Return frameworks detected from container markers with evidence identifiers."
            ),
            handler=_framework_list_detected,
            profiles=MINIMAL,
        )
    )
    registry.register(
        _job_spec(
            name="packer_detect",
            title="Detect packers",
            description="Return packer/protector filename heuristics and optional APKiD analysis.",
            handler=_packer_detect,
            input_model=PackerDetectInput,
            profiles=MINIMAL,
        )
    )
    registry.register(
        ToolSpec(
            name="wasm_decompile",
            title="WebAssembly Binary Decompiler & Inspector",
            description=(
                "Decompile embedded WebAssembly (.wasm) modules into WebAssembly Text "
                "format (WAT), extracting exported functions, imports, and anti-tamper logic."
            ),
            input_model=WasmDecompileInput,
            handler=_wasm_decompile,
            family="source",
            profiles=CORE,
            scopes=frozenset(),
            annotations=ToolAnnotations(read_only=True, idempotent=True),
            cost="fast",
        )
    )
