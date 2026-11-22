"""Immutable evidence records."""

from __future__ import annotations

from typing import Any

from raa.domain.models import (
    Authority,
    Confidence,
    EvidenceRecord,
    Representation,
)
from raa.errors import NotFoundError
from raa.storage.repositories import EvidenceRepository
from raa.utils.ids import new_id
from raa.utils.time import utc_now


class EvidenceService:
    def __init__(self, repository: EvidenceRepository) -> None:
        self.repository = repository

    def add(
        self,
        *,
        project_id: str,
        kind: str,
        summary: str,
        payload: dict[str, Any],
        source_tool: str,
        artifact_id: str | None = None,
        authority: Authority = Authority.SHIPPED_ARTIFACT,
        representation: Representation = Representation.ORIGINAL,
        confidence: Confidence = Confidence.OBSERVED,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            id=new_id("ev"),
            project_id=project_id,
            artifact_id=artifact_id,
            kind=kind,
            summary=summary,
            authority=authority,
            representation=representation,
            confidence=confidence,
            source_tool=source_tool,
            payload=payload,
            created_at=utc_now(),
        )
        return self.repository.create(record)

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self.repository.get(evidence_id)

    def get_or_raise(self, evidence_id: str) -> EvidenceRecord:
        record = self.get(evidence_id)
        if record is None:
            raise NotFoundError(
                f"Evidence not found: {evidence_id}",
                hint="Use evidence_list with a project_id to discover evidence identifiers.",
            )
        return record

    def list(
        self,
        project_id: str,
        *,
        artifact_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        return self.repository.list(
            project_id,
            artifact_id=artifact_id,
            limit=limit,
            offset=offset,
        )
