"""Native binary inspection and JNI mapping tools."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.errors import NotFoundError
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE
from raa.services.android.dex import decode_dex_index
from raa.services.android.elf import extract_elf_symbols, parse_elf_header
from raa.services.android.jni import map_jni_methods
from raa.services.inspection import read_archive_member


class JobInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project ID.")
    job_id: str = Field(min_length=1, description="Completed analysis job ID.")


class NativeAnalyzeInput(JobInput):
    library_path: str = Field(
        min_length=1,
        description="Path to .so file within the APK (e.g. 'lib/arm64-v8a/libflutter.so').",
    )


class NativeGetSymbolsInput(JobInput):
    library_path: str = Field(
        min_length=1,
        description="Path to .so file within the APK.",
    )
    kind: Literal["all", "exported", "imported", "jni"] = Field(
        default="all",
        description="Filter symbols by kind.",
    )
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class JniMapInput(JobInput):
    status: Literal["all", "bound", "dynamic", "unresolved"] = Field(
        default="all",
        description="Filter JNI bindings by binding status.",
    )
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class NativeListLibrariesInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project ID.")
    artifact_id: str | None = Field(default=None, description="Optional target artifact ID.")


def _get_job_context(ctx: ToolContext, project_id: str, job_id: str) -> tuple[Any, Path, list[str]]:
    report = ctx.runtime.analysis.get_report(project_id, job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    archive_names: list[str] = list(report.summary.get("archive_names", []))
    if not archive_names and path.is_file():
        try:
            with zipfile.ZipFile(path) as zf:
                archive_names = zf.namelist()
        except Exception:
            archive_names = []
    return report, path, archive_names


async def _native_analyze_library(ctx: ToolContext, args: NativeAnalyzeInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    target = next(
        (
            name
            for name in archive_names
            if name == args.library_path or name.endswith(args.library_path)
        ),
        None,
    )
    if not target:
        raise NotFoundError(f"Native library '{args.library_path}' was not found in the APK.")

    content = read_archive_member(path, target, max_bytes=8 * 1024 * 1024)
    header = parse_elf_header(content, target)
    if header is None:
        raise NotFoundError(f"File '{target}' is not a valid ELF binary.")

    extract_elf_symbols(content, target, max_symbols=10)
    return ToolOutcome(
        data=header.model_dump(mode="json"),
        evidence_ids=report.evidence_ids,
    )


async def _native_get_symbols(ctx: ToolContext, args: NativeGetSymbolsInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    target = next(
        (
            name
            for name in archive_names
            if name == args.library_path or name.endswith(args.library_path)
        ),
        None,
    )
    if not target:
        raise NotFoundError(f"Native library '{args.library_path}' was not found in the APK.")

    content = read_archive_member(path, target, max_bytes=8 * 1024 * 1024)
    summary = extract_elf_symbols(content, target, max_symbols=5000)

    if args.kind == "exported":
        selected = summary.exported_symbols
    elif args.kind == "imported":
        selected = summary.imported_symbols
    elif args.kind == "jni":
        selected = summary.jni_symbols
    else:
        selected = summary.exported_symbols + summary.imported_symbols

    page = selected[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "library": summary.library,
            "abi": summary.abi,
            "kind": args.kind,
            "symbols": [s.model_dump(mode="json") for s in page],
            "count": len(page),
            "total": len(selected),
            "has_jni_on_load": summary.has_jni_on_load,
        },
        evidence_ids=report.evidence_ids,
    )


async def _jni_map(ctx: ToolContext, args: JniMapInput) -> ToolOutcome:
    report, path, archive_names = _get_job_context(ctx, args.project_id, args.job_id)
    artifact = ctx.runtime.artifacts.get_or_raise(report.project_id, report.artifact_id)
    dex_index = decode_dex_index(
        path,
        artifact.artifact_type,
        max_bytes=ctx.runtime.settings.max_dex_bytes,
    )
    native_libs = [name for name in archive_names if name.endswith(".so")]
    mapping = map_jni_methods(path, dex_index, native_libs)

    if args.status == "all":
        selected = mapping.bindings
    else:
        selected = [b for b in mapping.bindings if b.status == args.status]

    page = selected[args.offset : args.offset + args.limit]
    return ToolOutcome(
        data={
            "bindings": [b.model_dump(mode="json") for b in page],
            "count": len(page),
            "total": len(selected),
            "total_native_methods": mapping.total_native_methods,
            "bound_count": mapping.bound_count,
            "dynamic_count": mapping.dynamic_count,
            "unresolved_count": mapping.unresolved_count,
            "libraries_searched": mapping.libraries_searched,
            "limitations": mapping.limitations,
        },
        evidence_ids=report.evidence_ids,
    )


async def _native_list_libraries(ctx: ToolContext, args: NativeListLibrariesInput) -> ToolOutcome:
    report = ctx.runtime.unpacking.inventory_native(
        project_id=args.project_id,
        artifact_id=args.artifact_id,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


def _native_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family="native",
        profiles=CORE,
        scopes=frozenset({"project.read", "static.read"}),
        annotations=ToolAnnotations(read_only=True, idempotent=True),
        cost="fast",
    )


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        _native_spec(
            name="native_list_libraries",
            title="List native libraries",
            description="Catalogue all native shared objects (.so) across all ABIs in an APK.",
            handler=_native_list_libraries,
            input_model=NativeListLibrariesInput,
        )
    )
    registry.register(
        _native_spec(
            name="native_analyze_library",
            title="Analyze native library",
            description=(
                "Inspect ELF header, architecture, machine, bitness, endianness, and sections."
            ),
            handler=_native_analyze_library,
            input_model=NativeAnalyzeInput,
        )
    )
    registry.register(
        _native_spec(
            name="native_get_symbols",
            title="Get native symbols",
            description=(
                "Extract exported, imported, and JNI symbols from an ELF shared library (.so)."
            ),
            handler=_native_get_symbols,
            input_model=NativeGetSymbolsInput,
        )
    )
    registry.register(
        _native_spec(
            name="jni_map",
            title="Map JNI methods",
            description=(
                "Correlate declared Java/Kotlin native methods to native library "
                "symbols and JNI_OnLoad."
            ),
            handler=_jni_map,
            input_model=JniMapInput,
        )
    )
