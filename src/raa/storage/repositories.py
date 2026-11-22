"""Repositories keep SQL out of services and tools."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from raa.domain.models import (
    AnalysisJob,
    Artifact,
    EvidenceRecord,
    JobStatus,
    Project,
)
from raa.storage.database import Database
from raa.utils.time import from_iso, to_iso


def _project(row: sqlite3.Row) -> Project:
    return Project(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        scopes=json.loads(row["scopes"]),
        created_at=from_iso(row["created_at"]),
        updated_at=from_iso(row["updated_at"]),
    )


def _artifact(row: sqlite3.Row) -> Artifact:
    return Artifact(
        id=row["id"],
        project_id=row["project_id"],
        filename=row["filename"],
        media_type=row["media_type"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        stored_path=row["stored_path"],
        artifact_type=row["artifact_type"],
        created_at=from_iso(row["created_at"]),
    )


def _evidence(row: sqlite3.Row) -> EvidenceRecord:
    return EvidenceRecord(
        id=row["id"],
        project_id=row["project_id"],
        artifact_id=row["artifact_id"],
        kind=row["kind"],
        summary=row["summary"],
        authority=row["authority"],
        representation=row["representation"],
        confidence=row["confidence"],
        source_tool=row["source_tool"],
        payload=json.loads(row["payload"]),
        created_at=from_iso(row["created_at"]),
    )


def _job(row: sqlite3.Row) -> AnalysisJob:
    return AnalysisJob(
        id=row["id"],
        project_id=row["project_id"],
        artifact_id=row["artifact_id"],
        tool=row["tool"],
        status=JobStatus(row["status"]),
        progress=row["progress"],
        stages=json.loads(row["stages"]),
        error=row["error"],
        created_at=from_iso(row["created_at"]),
        updated_at=from_iso(row["updated_at"]),
    )


class ProjectRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, project: Project) -> Project:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO projects (id, name, description, scopes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    project.id,
                    project.name,
                    project.description,
                    json.dumps(project.scopes),
                    to_iso(project.created_at),
                    to_iso(project.updated_at),
                ),
            )
        return project

    def get(self, project_id: str) -> Project | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        return _project(row) if row else None

    def list(self, limit: int = 100, offset: int = 0) -> list[Project]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [_project(row) for row in rows]

    def update(self, project: Project) -> Project:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE projects
                SET name = ?, description = ?, scopes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    project.name,
                    project.description,
                    json.dumps(project.scopes),
                    to_iso(project.updated_at),
                    project.id,
                ),
            )
        return project


class ArtifactRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, artifact: Artifact) -> Artifact:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO artifacts (
                    id, project_id, filename, media_type, size_bytes, sha256,
                    stored_path, artifact_type, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.id,
                    artifact.project_id,
                    artifact.filename,
                    artifact.media_type,
                    artifact.size_bytes,
                    artifact.sha256,
                    artifact.stored_path,
                    artifact.artifact_type,
                    to_iso(artifact.created_at),
                ),
            )
        return artifact

    def get(self, artifact_id: str) -> Artifact | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
        return _artifact(row) if row else None

    def list(self, project_id: str, limit: int = 100, offset: int = 0) -> list[Artifact]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM artifacts
                WHERE project_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (project_id, limit, offset),
            ).fetchall()
        return [_artifact(row) for row in rows]


class EvidenceRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, evidence: EvidenceRecord) -> EvidenceRecord:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence (
                    id, project_id, artifact_id, kind, summary, authority,
                    representation, confidence, source_tool, payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.id,
                    evidence.project_id,
                    evidence.artifact_id,
                    evidence.kind,
                    evidence.summary,
                    evidence.authority.value,
                    evidence.representation.value,
                    evidence.confidence.value,
                    evidence.source_tool,
                    json.dumps(evidence.payload, ensure_ascii=False, default=str),
                    to_iso(evidence.created_at),
                ),
            )
        return evidence

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        return _evidence(row) if row else None

    def list(
        self,
        project_id: str,
        *,
        artifact_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        query = "SELECT * FROM evidence WHERE project_id = ?"
        parameters: list[Any] = [project_id]
        if artifact_id:
            query += " AND artifact_id = ?"
            parameters.append(artifact_id)
        query += " ORDER BY created_at ASC LIMIT ? OFFSET ?"
        parameters.extend([limit, offset])
        with self.database.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_evidence(row) for row in rows]


class JobRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, job: AnalysisJob) -> AnalysisJob:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, project_id, artifact_id, tool, status, progress,
                    stages, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id,
                    job.project_id,
                    job.artifact_id,
                    job.tool,
                    job.status.value,
                    job.progress,
                    json.dumps(job.stages),
                    to_iso(job.created_at),
                    to_iso(job.updated_at),
                ),
            )
        return job

    def get(self, job_id: str) -> AnalysisJob | None:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return _job(row) if row else None

    def update(
        self,
        job: AnalysisJob,
        *,
        result: dict[str, Any] | None = None,
    ) -> AnalysisJob:
        with self.database.connect() as connection:
            if result is None:
                connection.execute(
                    """
                    UPDATE jobs
                    SET status = ?, progress = ?, error = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        job.status.value,
                        job.progress,
                        job.error,
                        to_iso(job.updated_at),
                        job.id,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE jobs
                    SET status = ?, progress = ?, error = ?, result = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        job.status.value,
                        job.progress,
                        job.error,
                        json.dumps(result, ensure_ascii=False, default=str),
                        to_iso(job.updated_at),
                        job.id,
                    ),
                )
        return job

    def get_result(self, job_id: str) -> dict[str, Any] | None:
        with self.database.connect() as connection:
            row = connection.execute("SELECT result FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row or row["result"] is None:
            return None
        result: dict[str, Any] = json.loads(row["result"])
        return result

    def list(self, project_id: str, limit: int = 100, offset: int = 0) -> list[AnalysisJob]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                WHERE project_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (project_id, limit, offset),
            ).fetchall()
        return [_job(row) for row in rows]
