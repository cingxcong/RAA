"""Artifact ingestion and lookup."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from raa.config import Settings
from raa.domain.models import Artifact, Authority, Confidence, EvidenceRecord, Representation
from raa.errors import InvalidArtifactError, LimitExceededError, NotFoundError
from raa.services.containers import detect_artifact_type, media_type_for
from raa.services.evidence import EvidenceService
from raa.services.projects import ProjectService
from raa.services.workspace import Workspace, sanitize_filename
from raa.storage.repositories import ArtifactRepository
from raa.utils.ids import new_id
from raa.utils.time import utc_now


@dataclass(slots=True)
class IngestResult:
    artifact: Artifact
    evidence: list[EvidenceRecord]


class ArtifactService:
    def __init__(
        self,
        *,
        settings: Settings,
        workspace: Workspace,
        repository: ArtifactRepository,
        projects: ProjectService,
        evidence: EvidenceService,
    ) -> None:
        self.settings = settings
        self.workspace = workspace
        self.repository = repository
        self.projects = projects
        self.evidence = evidence

    def ingest_path(self, project_id: str, raw_path: str) -> IngestResult:
        project = self.projects.get_or_raise(project_id)
        source = self.workspace.check_input_path(
            raw_path,
            self.settings.resolved_input_roots(),
        )

        size_bytes = source.stat().st_size
        if size_bytes <= 0:
            raise InvalidArtifactError("The artifact is empty.")
        if size_bytes > self.settings.max_input_bytes:
            raise LimitExceededError(
                "Artifact exceeds the configured input limit.",
                hint="Raise RAA_MAX_INPUT_BYTES or provide a smaller artifact.",
                details={
                    "size_bytes": size_bytes,
                    "max_input_bytes": self.settings.max_input_bytes,
                },
            )

        artifact_type = detect_artifact_type(source, self.settings.max_archive_entries)
        artifact_id = new_id("art")
        filename = sanitize_filename(source.name)
        destination = self.workspace.artifact_dir(project.id, artifact_id) / filename
        sha256, copied_bytes = _copy_and_hash(source, destination)
        if copied_bytes != size_bytes:
            destination.unlink(missing_ok=True)
            raise InvalidArtifactError(
                "Artifact size changed while it was being ingested.",
                hint="Retry with a stable local copy of the file.",
            )

        artifact = Artifact(
            id=artifact_id,
            project_id=project.id,
            filename=filename,
            media_type=media_type_for(artifact_type),
            size_bytes=copied_bytes,
            sha256=sha256,
            stored_path=self.workspace.relative(destination),
            artifact_type=artifact_type,
            created_at=utc_now(),
        )
        self.repository.create(artifact)

        hash_evidence = self.evidence.add(
            project_id=project.id,
            artifact_id=artifact.id,
            kind="artifact.hash",
            summary=f"SHA-256 of {filename}",
            payload={"sha256": sha256, "size_bytes": copied_bytes},
            source_tool="artifact_ingest",
            authority=Authority.SHIPPED_ARTIFACT,
            representation=Representation.ORIGINAL,
            confidence=Confidence.OBSERVED,
        )
        container_evidence = self.evidence.add(
            project_id=project.id,
            artifact_id=artifact.id,
            kind="artifact.container",
            summary=f"Container classified as {artifact_type}",
            payload={
                "artifact_type": artifact_type,
                "media_type": artifact.media_type,
                "filename": filename,
            },
            source_tool="artifact_ingest",
            authority=Authority.SHIPPED_ARTIFACT,
            representation=Representation.ORIGINAL,
            confidence=Confidence.OBSERVED,
        )
        return IngestResult(artifact=artifact, evidence=[hash_evidence, container_evidence])

    def get(self, artifact_id: str) -> Artifact | None:
        return self.repository.get(artifact_id)

    def get_or_raise(self, project_id: str, artifact_id: str) -> Artifact:
        self.projects.get_or_raise(project_id)
        artifact = self.repository.get(artifact_id)
        if artifact is None or artifact.project_id != project_id:
            raise NotFoundError(
                f"Artifact not found in project {project_id}: {artifact_id}",
                hint="Call artifact_list to discover valid artifact identifiers.",
            )
        return artifact

    def list(self, project_id: str, limit: int = 100, offset: int = 0) -> list[Artifact]:
        self.projects.get_or_raise(project_id)
        return self.repository.list(project_id, limit=limit, offset=offset)

    def path_for(self, artifact: Artifact) -> Path:
        return self.workspace.stored_path(artifact.stored_path)


def _copy_and_hash(source: Path, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as reader, destination.open("wb") as writer:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                writer.write(chunk)
                total += len(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), total
