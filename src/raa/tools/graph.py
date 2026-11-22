"""AAIR and source graph MCP tools."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE


class JobInput(BaseModel):
    project_id: str = Field(min_length=1, description="Target project ID.")
    job_id: str = Field(min_length=1, description="Completed analysis job ID.")


class SourceHierarchyInput(JobInput):
    class_name: str = Field(
        min_length=1,
        description="Target class name (e.g. 'com.example.MainActivity' or descriptor).",
    )
    direction: Literal["up", "down", "both"] = Field(
        default="both",
        description=(
            "Hierarchy traversal direction: 'up' (superclasses/interfaces), "
            "'down' (subclasses/implementers), or 'both'."
        ),
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")


class SourceXrefsInput(JobInput):
    symbol: str = Field(
        min_length=1,
        description="Symbol, class, method, field or entity ID to find cross-references for.",
    )
    kind: str | None = Field(
        default=None,
        description=(
            "Optional edge/xref kind filter (e.g. 'CALLS', 'REFERENCES', "
            "'TRIGGERS_ENDPOINT', 'ACCESSES_STORAGE')."
        ),
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")


class GraphQueryInput(JobInput):
    root_id: str | None = Field(
        default=None,
        description="Optional starting entity ID. If omitted, queries top-level entities.",
    )
    edge_kinds: list[str] | None = Field(
        default=None,
        description="Optional list of edge kinds to traverse (e.g. ['CALLS']).",
    )
    target_kinds: list[str] | None = Field(
        default=None,
        description="Optional list of entity kinds to filter targets (e.g. ['endpoint', 'table']).",
    )
    max_depth: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Maximum traversal depth from the root node (bounded between 1 and 5).",
    )
    direction: Literal["outgoing", "incoming", "both"] = Field(
        default="outgoing",
        description="Edge traversal direction: 'outgoing', 'incoming', or 'both'.",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")


class GraphNeighborhoodInput(JobInput):
    entity_id: str = Field(
        min_length=1,
        description="Target entity ID to inspect local neighborhood around (e.g. 'endpoint:HTTP:https://api.example.com/v1/users').",
    )
    radius: int = Field(
        default=1,
        ge=1,
        le=3,
        description="Neighborhood radius / max depth (bounded between 1 and 3).",
    )
    edge_kinds: list[str] | None = Field(
        default=None,
        description="Optional list of edge kinds to filter neighboring relationships.",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Page limit.")
    offset: int = Field(default=0, ge=0, description="Page offset.")


async def _source_get_hierarchy(
    ctx: ToolContext,
    input_data: SourceHierarchyInput,
) -> ToolOutcome:
    res = ctx.runtime.aair.get_hierarchy(
        project_id=input_data.project_id,
        job_id=input_data.job_id,
        class_name=input_data.class_name,
        direction=input_data.direction,
        limit=input_data.limit,
        offset=input_data.offset,
    )
    return ToolOutcome(data=res, evidence_ids=res.get("evidence_ids", []))


async def _source_get_xrefs(
    ctx: ToolContext,
    input_data: SourceXrefsInput,
) -> ToolOutcome:
    res = ctx.runtime.aair.get_xrefs(
        project_id=input_data.project_id,
        job_id=input_data.job_id,
        symbol=input_data.symbol,
        kind=input_data.kind,
        limit=input_data.limit,
        offset=input_data.offset,
    )
    return ToolOutcome(data=res, evidence_ids=res.get("evidence_ids", []))


async def _graph_query(
    ctx: ToolContext,
    input_data: GraphQueryInput,
) -> ToolOutcome:
    res = ctx.runtime.aair.query_graph(
        project_id=input_data.project_id,
        job_id=input_data.job_id,
        root_id=input_data.root_id,
        edge_kinds=input_data.edge_kinds,
        target_kinds=input_data.target_kinds,
        max_depth=input_data.max_depth,
        direction=input_data.direction,
        limit=input_data.limit,
        offset=input_data.offset,
    )
    return ToolOutcome(data=res, evidence_ids=res.get("evidence_ids", []))


async def _graph_get_neighborhood(
    ctx: ToolContext,
    input_data: GraphNeighborhoodInput,
) -> ToolOutcome:
    res = ctx.runtime.aair.get_neighborhood(
        project_id=input_data.project_id,
        job_id=input_data.job_id,
        entity_id=input_data.entity_id,
        radius=input_data.radius,
        edge_kinds=input_data.edge_kinds,
        limit=input_data.limit,
        offset=input_data.offset,
    )
    return ToolOutcome(data=res, evidence_ids=res.get("evidence_ids", []))


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="source_get_hierarchy",
            title="Get class inheritance and interface hierarchy",
            description="Traverse superclasses, interfaces, and subclasses for a declared class.",
            input_model=SourceHierarchyInput,
            handler=_source_get_hierarchy,
            family="source",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="source_get_xrefs",
            title="Get cross-references to a symbol",
            description=(
                "Retrieve cross-references and callers to a class, method, field, "
                "or entity with kind and confidence."
            ),
            input_model=SourceXrefsInput,
            handler=_source_get_xrefs,
            family="source",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="graph_query",
            title="Query application intelligence graph",
            description="Bounded, paginated traversal of the AAIR entity and relationship graph.",
            input_model=GraphQueryInput,
            handler=_graph_query,
            family="source",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True),
            cost="fast",
        )
    )
    registry.register(
        ToolSpec(
            name="graph_get_neighborhood",
            title="Get local neighborhood around an entity",
            description="Retrieve bounded local graph neighborhood around an AAIR entity.",
            input_model=GraphNeighborhoodInput,
            handler=_graph_get_neighborhood,
            family="source",
            profiles=CORE,
            scopes=frozenset({"project.read", "static.read"}),
            annotations=ToolAnnotations(read_only=True),
            cost="fast",
        )
    )
