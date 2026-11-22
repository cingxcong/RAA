"""Typed domain model for projects, artifacts, evidence and reports."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.domain.dex import DexSummary
from raa.domain.manifest import ManifestInfo
from raa.domain.resources import ResourceSummary


class Authority(StrEnum):
    """Where a claim originated."""

    SHIPPED_ARTIFACT = "shipped_artifact"
    CONTROLLED_REPLAY = "controlled_replay"
    HISTORICAL_REFERENCE = "historical_reference"
    EXTERNAL_SERVICE = "external_service"
    ANALYST_INFERENCE = "analyst_inference"


class Representation(StrEnum):
    """How the evidence content is expressed."""

    ORIGINAL = "original"
    DECOMPILED = "decompiled"
    DISASSEMBLED = "disassembled"
    PSEUDOCODE = "pseudocode"
    RUNTIME_OBSERVED = "runtime_observed"
    INFERRED = "inferred"
    GENERATED = "generated"


class Confidence(StrEnum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}


class Project(BaseModel):
    id: str
    name: str
    description: str = ""
    scopes: list[str]
    created_at: datetime
    updated_at: datetime


class Artifact(BaseModel):
    id: str
    project_id: str
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    stored_path: str
    artifact_type: str
    created_at: datetime


class EvidenceRecord(BaseModel):
    id: str
    project_id: str
    artifact_id: str | None = None
    kind: str
    summary: str
    authority: Authority
    representation: Representation
    confidence: Confidence
    source_tool: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class AnalysisJob(BaseModel):
    id: str
    project_id: str
    artifact_id: str
    tool: str = "analysis"
    status: JobStatus
    progress: float = Field(default=0.0, ge=0.0, le=1.0)
    stages: list[str] = Field(default_factory=list)
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class FrameworkFinding(BaseModel):
    id: str
    name: str
    category: str
    confidence: Confidence
    markers: list[str] = Field(default_factory=list)
    notes: str | None = None


class PackerFinding(BaseModel):
    id: str
    name: str
    confidence: Confidence
    markers: list[str] = Field(default_factory=list)
    notes: str | None = None


class DexFile(BaseModel):
    name: str
    size_bytes: int


class NativeLibrary(BaseModel):
    abi: str
    name: str
    size_bytes: int


class SignatureInfo(BaseModel):
    v1_certificates: list[str] = Field(default_factory=list)
    apk_signing_block: bool = False
    status: Literal["signed_v1", "signed_v2_plus", "signed_v1_and_v2", "unsigned", "unknown"]
    notes: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    stages_completed: list[str] = Field(default_factory=list)
    stages_skipped: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EndpointDiscovery(BaseModel):
    urls: list[str] = Field(default_factory=list)
    schemes: list[str] = Field(default_factory=list)
    deep_links: list[str] = Field(default_factory=list)
    api_paths: list[str] = Field(default_factory=list)
    total_count: int = 0


class StorageDiscovery(BaseModel):
    sqlite_databases: list[str] = Field(default_factory=list)
    shared_preferences: list[str] = Field(default_factory=list)
    storage_technologies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str
    title: str
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    report_id: str
    project_id: str
    artifact_id: str
    artifact_type: str
    filename: str
    sha256: str
    size_bytes: int
    generated_at: datetime
    stages: list[str] = Field(default_factory=list)
    coverage: Coverage
    summary: dict[str, Any] = Field(default_factory=dict)
    dex_files: list[DexFile] = Field(default_factory=list)
    native_libraries: list[NativeLibrary] = Field(default_factory=list)
    signature: SignatureInfo
    frameworks: list[FrameworkFinding] = Field(default_factory=list)
    packers: list[PackerFinding] = Field(default_factory=list)
    manifest: ManifestInfo | None = None
    manifest_error: str | None = None
    resource_summary: ResourceSummary | None = None
    resource_error: str | None = None
    dex_summary: DexSummary | None = None
    dex_error: str | None = None
    endpoints: EndpointDiscovery | None = None
    storage: StorageDiscovery | None = None
    findings: list[Finding] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ExportResult(BaseModel):
    format: str
    path: str
    size_bytes: int
