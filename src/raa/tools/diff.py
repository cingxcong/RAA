"""Artifact comparison, semantic diffing, and noise filtering MCP tools."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.policy.scopes import EXPORT_WRITE, PROJECT_READ, STATIC_READ
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE

# --- Input Models ---


class ArtifactCompareInput(BaseModel):
    """Parameters to start a version diff between two artifacts."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    base_artifact_id: str = Field(min_length=1, description="Baseline artifact ID.")
    target_artifact_id: str = Field(min_length=1, description="Comparison target artifact ID.")
    categories: list[str] | None = Field(
        default=None,
        description="Optional categories filter (manifest, code, resource, native, api, ui).",
    )


class DiffListChangesInput(BaseModel):
    """Parameters to retrieve paginated changes from a diff report."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    diff_id: str = Field(min_length=1, description="Diff comparison ID.")
    category: str | None = Field(
        default=None,
        description="Filter by category (manifest, code, resource, native, api, ui, file).",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")


class DiffGetInput(BaseModel):
    """Parameters to inspect a single change item in detail."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    diff_id: str = Field(min_length=1, description="Diff comparison ID.")
    change_id: str = Field(min_length=1, description="Change item ID.")


class DiffExportInput(BaseModel):
    """Parameters to export a full diff report."""

    project_id: str = Field(min_length=1, description="Target project ID.")
    diff_id: str = Field(min_length=1, description="Diff comparison ID.")
    format: Literal["json", "markdown", "unified"] = Field(
        default="json",
        description="Export format (json, markdown, unified).",
    )


# --- Tool Spec Helper ---


def _diff_spec(
    *,
    name: str,
    title: str,
    description: str,
    handler: Any,
    input_model: type[BaseModel],
    profiles: frozenset[str] = CORE,
    scopes: frozenset[str] = frozenset({PROJECT_READ, STATIC_READ}),
    read_only: bool = True,
    idempotent: bool = True,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        handler=handler,
        family="diff",
        profiles=profiles,
        scopes=scopes,
        annotations=ToolAnnotations(read_only=read_only, idempotent=idempotent),
        cost="fast",
    )


# --- Handlers ---


async def _artifact_compare(ctx: ToolContext, args: ArtifactCompareInput) -> ToolOutcome:
    report = ctx.runtime.diff.compare(
        project_id=args.project_id,
        base_artifact_id=args.base_artifact_id,
        target_artifact_id=args.target_artifact_id,
        categories=args.categories,
    )
    return ToolOutcome(data=report.model_dump(mode="json"))


async def _diff_list_changes(ctx: ToolContext, args: DiffListChangesInput) -> ToolOutcome:
    payload = ctx.runtime.diff.list_changes(
        project_id=args.project_id,
        diff_id=args.diff_id,
        category=args.category,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(data=payload)


async def _diff_get(ctx: ToolContext, args: DiffGetInput) -> ToolOutcome:
    change = ctx.runtime.diff.get_change(
        project_id=args.project_id,
        diff_id=args.diff_id,
        change_id=args.change_id,
    )
    return ToolOutcome(data=change.model_dump(mode="json"))


async def _diff_export(ctx: ToolContext, args: DiffExportInput) -> ToolOutcome:
    rendered = ctx.runtime.diff.export(
        project_id=args.project_id,
        diff_id=args.diff_id,
        format_type=args.format,
    )
    return ToolOutcome(
        data={
            "project_id": args.project_id,
            "diff_id": args.diff_id,
            "format": args.format,
            "content": rendered,
        }
    )


# --- Registration ---


def register(registry: CapabilityRegistry) -> None:
    """Register all Phase 9 diff tools."""
    registry.register(
        _diff_spec(
            name="artifact_compare",
            title="Compare artifacts",
            description="Semantic version diff between two APK artifacts with noise filtering.",
            handler=_artifact_compare,
            input_model=ArtifactCompareInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _diff_spec(
            name="diff_list_changes",
            title="List diff changes",
            description="Retrieve paginated changes by category from a completed diff comparison.",
            handler=_diff_list_changes,
            input_model=DiffListChangesInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _diff_spec(
            name="diff_get",
            title="Get diff change detail",
            description="Inspect change item in detail with unified diff and noise reasoning.",
            handler=_diff_get,
            input_model=DiffGetInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ}),
            read_only=True,
            idempotent=True,
        )
    )
    registry.register(
        _diff_spec(
            name="diff_export",
            title="Export diff report",
            description="Export full diff comparison as JSON, Markdown, or unified diff.",
            handler=_diff_export,
            input_model=DiffExportInput,
            profiles=CORE,
            scopes=frozenset({PROJECT_READ, STATIC_READ, EXPORT_WRITE}),
            read_only=False,
            idempotent=False,
        )
    )
