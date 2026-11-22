"""Artifact ingestion and inventory tools."""

from __future__ import annotations

from pydantic import Field

from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE, MINIMAL
from raa.services.inspection import list_archive_members


class ArtifactIngestInput(ToolInput):
    project_id: str = Field(description="Project that will own the artifact.")
    path: str = Field(
        description=("Path to an APK/AAB/APKS/XAPK inside the workspace or an allowed input root.")
    )


class ArtifactGetInfoInput(ToolInput):
    project_id: str
    artifact_id: str


class ArtifactListInput(ToolInput):
    project_id: str
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class ArtifactListFilesInput(ToolInput):
    project_id: str
    artifact_id: str
    pattern: str | None = Field(
        default=None,
        max_length=300,
        description="Optional case-insensitive glob such as 'lib/*/*.so'.",
    )
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


async def _artifact_ingest(ctx: ToolContext, args: ArtifactIngestInput) -> ToolOutcome:
    ingested = ctx.runtime.artifacts.ingest_path(args.project_id, args.path)
    return ToolOutcome(
        data=ingested.artifact,
        evidence_ids=[record.id for record in ingested.evidence],
    )


async def _artifact_get_info(ctx: ToolContext, args: ArtifactGetInfoInput) -> ToolOutcome:
    artifact = ctx.runtime.artifacts.get_or_raise(args.project_id, args.artifact_id)
    return ToolOutcome(data=artifact)


async def _artifact_list(ctx: ToolContext, args: ArtifactListInput) -> ToolOutcome:
    artifacts = ctx.runtime.artifacts.list(
        args.project_id,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(
        data={
            "items": [artifact.model_dump(mode="json") for artifact in artifacts],
            "count": len(artifacts),
            "limit": args.limit,
            "offset": args.offset,
        }
    )


async def _artifact_list_files(
    ctx: ToolContext,
    args: ArtifactListFilesInput,
) -> ToolOutcome:
    artifact = ctx.runtime.artifacts.get_or_raise(args.project_id, args.artifact_id)
    path = ctx.runtime.artifacts.path_for(artifact)
    items, total = list_archive_members(
        path,
        pattern=args.pattern,
        limit=args.limit,
        offset=args.offset,
        max_entries=ctx.runtime.settings.max_archive_entries,
    )
    return ToolOutcome(
        data={
            "artifact_id": artifact.id,
            "items": items,
            "total": total,
            "limit": args.limit,
            "offset": args.offset,
        }
    )


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="artifact_ingest",
            title="Ingest artifact",
            description=(
                "Copy an APK/AAB/APKS/XAPK into the project workspace, hash it, "
                "classify the container and record evidence. Paths outside allowed "
                "input roots are rejected."
            ),
            input_model=ArtifactIngestInput,
            handler=_artifact_ingest,
            family="artifacts",
            profiles=MINIMAL,
            scopes=frozenset({"project.write", "static.read"}),
            annotations=ToolAnnotations(
                read_only=False,
                destructive=False,
                idempotent=False,
            ),
        )
    )
    registry.register(
        ToolSpec(
            name="artifact_get_info",
            title="Get artifact info",
            description="Return hash, size, container type and storage metadata for an artifact.",
            input_model=ArtifactGetInfoInput,
            handler=_artifact_get_info,
            family="artifacts",
            profiles=MINIMAL,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="artifact_list",
            title="List artifacts",
            description="List artifacts in a project.",
            input_model=ArtifactListInput,
            handler=_artifact_list,
            family="artifacts",
            profiles=CORE,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="artifact_list_files",
            title="List artifact files",
            description=(
                "List archive members with sizes and compression metadata. "
                "No extraction or path traversal is permitted."
            ),
            input_model=ArtifactListFilesInput,
            handler=_artifact_list_files,
            family="artifacts",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
