"""Evidence retrieval tools."""

from __future__ import annotations

from pydantic import Field

from raa.errors import NotFoundError
from raa.registry.models import (
    CapabilityRegistry,
    ToolAnnotations,
    ToolContext,
    ToolInput,
    ToolOutcome,
    ToolSpec,
)
from raa.registry.profiles import CORE


class EvidenceGetInput(ToolInput):
    project_id: str
    evidence_id: str


class EvidenceListInput(ToolInput):
    project_id: str
    artifact_id: str | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


async def _evidence_get(ctx: ToolContext, args: EvidenceGetInput) -> ToolOutcome:
    record = ctx.runtime.evidence.get_or_raise(args.evidence_id)
    if record.project_id != args.project_id:
        raise NotFoundError(f"Evidence not found in project {args.project_id}: {args.evidence_id}")
    return ToolOutcome(data=record, evidence_ids=[record.id])


async def _evidence_list(ctx: ToolContext, args: EvidenceListInput) -> ToolOutcome:
    items = ctx.runtime.evidence.list(
        args.project_id,
        artifact_id=args.artifact_id,
        limit=args.limit,
        offset=args.offset,
    )
    return ToolOutcome(
        data={
            "items": [record.model_dump(mode="json") for record in items],
            "count": len(items),
            "limit": args.limit,
            "offset": args.offset,
        },
        evidence_ids=[record.id for record in items],
    )


def register(registry: CapabilityRegistry) -> None:
    registry.register(
        ToolSpec(
            name="evidence_get",
            title="Get evidence",
            description=(
                "Retrieve one immutable evidence record with authority, "
                "representation and confidence."
            ),
            input_model=EvidenceGetInput,
            handler=_evidence_get,
            family="evidence",
            profiles=CORE,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
    registry.register(
        ToolSpec(
            name="evidence_list",
            title="List evidence",
            description="List evidence records in a project, optionally filtered by artifact.",
            input_model=EvidenceListInput,
            handler=_evidence_list,
            family="evidence",
            profiles=CORE,
            scopes=frozenset({"project.read"}),
            annotations=ToolAnnotations(read_only=True),
        )
    )
