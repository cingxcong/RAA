"""Built-in static inspection pipeline and job lifecycle.

Jobs run in a bounded local thread pool. This keeps ``analysis_start``
non-blocking for MCP/REST and lets one-shot CLI invocations finish even after
the caller's event loop closes. A durable queue replaces this executor in
server mode.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from raa.config import Settings
from raa.domain.dex import DexSummary
from raa.domain.manifest import ManifestInfo
from raa.domain.models import (
    AnalysisJob,
    AnalysisReport,
    Artifact,
    Authority,
    Confidence,
    Coverage,
    EndpointDiscovery,
    Finding,
    JobStatus,
    Representation,
    StorageDiscovery,
)
from raa.domain.resources import ResourceSummary
from raa.errors import InvalidArgumentsError, RAAError, StateError
from raa.services.android.arsc import decode_resource_table
from raa.services.android.crosscheck import cross_check_inventory
from raa.services.android.dex import decode_dex_index
from raa.services.android.discovery import discover_endpoints, discover_storage
from raa.services.android.manifest import decode_manifest, manifest_findings
from raa.services.artifacts import ArtifactService
from raa.services.evidence import EvidenceService
from raa.services.frameworks import detect_frameworks
from raa.services.inspection import InspectionResult, inspect_archive
from raa.services.projects import ProjectService
from raa.services.workspace import Workspace
from raa.storage.repositories import JobRepository
from raa.utils.ids import new_id
from raa.utils.time import utc_now

logger = logging.getLogger(__name__)

ALLOWED_STAGES: tuple[str, ...] = (
    "container",
    "inventory",
    "manifest",
    "resources",
    "code",
    "frameworks",
    "signatures",
)


class AnalysisService:
    def __init__(
        self,
        *,
        settings: Settings,
        workspace: Workspace,
        projects: ProjectService,
        artifacts: ArtifactService,
        evidence: EvidenceService,
        jobs: JobRepository,
    ) -> None:
        self.settings = settings
        self.workspace = workspace
        self.projects = projects
        self.artifacts = artifacts
        self.evidence = evidence
        self.jobs = jobs
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="raa-analysis")

    def start(
        self,
        project_id: str,
        artifact_id: str,
        stages: list[str] | None = None,
    ) -> AnalysisJob:
        self.projects.get_or_raise(project_id)
        self.artifacts.get_or_raise(project_id, artifact_id)
        normalized = _normalize_stages(stages)
        now = utc_now()
        job = AnalysisJob(
            id=new_id("job"),
            project_id=project_id,
            artifact_id=artifact_id,
            tool="analysis",
            status=JobStatus.QUEUED,
            progress=0.0,
            stages=normalized,
            created_at=now,
            updated_at=now,
        )
        self.jobs.create(job)
        self._executor.submit(self._run_job, job.id, normalized)
        return job

    def _run_job(self, job_id: str, stages: list[str]) -> None:
        job = self.jobs.get(job_id)
        if job is None or job.status == JobStatus.CANCELLED:
            return
        try:
            job.status = JobStatus.RUNNING
            job.progress = 0.1
            job.updated_at = utc_now()
            self.jobs.update(job)

            project = self.projects.get_or_raise(job.project_id)
            artifact = self.artifacts.get_or_raise(project.id, job.artifact_id)
            path = self.artifacts.path_for(artifact)

            inspection = inspect_archive(
                path,
                artifact.artifact_type,
                max_entries=self.settings.max_archive_entries,
                max_uncompressed_bytes=self.settings.max_uncompressed_bytes,
            )

            manifest: ManifestInfo | None = None
            manifest_error: str | None = None
            if "manifest" in stages:
                try:
                    manifest = decode_manifest(
                        path,
                        artifact.artifact_type,
                        max_bytes=self.settings.max_manifest_bytes,
                    )
                except RAAError as exc:
                    manifest_error = f"{exc.code}: {exc.message}"
            else:
                manifest_error = "Manifest stage was not selected."

            resource_summary = None
            resource_error: str | None = None
            if "resources" in stages:
                try:
                    table = decode_resource_table(
                        path,
                        artifact.artifact_type,
                        max_bytes=self.settings.max_resource_bytes,
                    )
                    resource_summary = table.summary()
                except RAAError as exc:
                    resource_error = f"{exc.code}: {exc.message}"
            else:
                resource_error = "Resources stage was not selected."

            dex_index = None
            dex_summary = None
            dex_error: str | None = None
            if "code" in stages:
                try:
                    dex_index = decode_dex_index(
                        path,
                        artifact.artifact_type,
                        max_bytes=self.settings.max_dex_bytes,
                    )
                    dex_summary = dex_index.summary()
                except RAAError as exc:
                    dex_error = f"{exc.code}: {exc.message}"
            else:
                dex_error = "Code stage was not selected."

            endpoints = discover_endpoints(manifest, dex_index)
            storage = discover_storage(manifest, dex_index)
            crosscheck_findings, crosscheck_limits = cross_check_inventory(manifest, dex_index)
            inspection.frameworks = detect_frameworks(
                inspection.names, manifest=manifest, dex_index=dex_index
            )

            current = self.jobs.get(job_id)
            if current is None or current.status == JobStatus.CANCELLED:
                return

            report = self._build_report(
                project.id,
                artifact,
                inspection,
                stages,
                manifest=manifest,
                manifest_error=manifest_error,
                resource_summary=resource_summary,
                resource_error=resource_error,
                dex_summary=dex_summary,
                dex_error=dex_error,
                endpoints=endpoints,
                storage=storage,
                crosscheck_findings=crosscheck_findings,
                crosscheck_limits=crosscheck_limits,
            )
            current.status = JobStatus.COMPLETED
            current.progress = 1.0
            current.error = None
            current.updated_at = utc_now()
            self.jobs.update(current, result=report.model_dump(mode="json"))
        except Exception as exc:
            logger.exception("Analysis job failed", extra={"project_id": job.project_id})
            failed = self.jobs.get(job_id)
            if failed is None:
                return
            failed.status = JobStatus.FAILED
            failed.progress = 0.0
            failed.error = f"{type(exc).__name__}: {exc}"
            failed.updated_at = utc_now()
            self.jobs.update(failed)

    def _build_report(
        self,
        project_id: str,
        artifact: Artifact,
        inspection: InspectionResult,
        stages: list[str],
        *,
        manifest: ManifestInfo | None,
        manifest_error: str | None,
        resource_summary: ResourceSummary | None,
        resource_error: str | None,
        dex_summary: DexSummary | None,
        dex_error: str | None,
        endpoints: EndpointDiscovery | None = None,
        storage: StorageDiscovery | None = None,
        crosscheck_findings: list[Finding] | None = None,
        crosscheck_limits: list[str] | None = None,
    ) -> AnalysisReport:
        if inspection.signature is None:
            raise ValueError("Inspection signature is required to compile analysis report.")

        evidence_by_key = {
            "container": self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="artifact.inventory",
                summary="Archive inventory and container metadata",
                payload={
                    "artifact_type": artifact.artifact_type,
                    "entry_count": inspection.total_entries,
                    "uncompressed_bytes": inspection.total_uncompressed_bytes,
                    "asset_count": inspection.asset_count,
                    "encrypted_entries": inspection.encrypted_entries,
                    "sample_entries": inspection.names[:50],
                },
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.OBSERVED,
            ),
            "dex": self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="code.dex_inventory",
                summary="DEX files detected in the container",
                payload={
                    "dex_files": [dex.model_dump(mode="json") for dex in inspection.dex_files]
                },
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.OBSERVED,
            ),
            "native": self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="native.library_inventory",
                summary="Native libraries detected in the container",
                payload={
                    "abis": inspection.abis,
                    "libraries": [
                        library.model_dump(mode="json") for library in inspection.native_libraries
                    ],
                },
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.OBSERVED,
            ),
            "signature": self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="signature.inventory",
                summary="Signing artifacts detected in the container",
                payload=inspection.signature.model_dump(mode="json"),
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.DERIVED,
            ),
            "frameworks": self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="framework.detection",
                summary="Framework detection from container markers",
                payload={
                    "frameworks": [
                        framework.model_dump(mode="json") for framework in inspection.frameworks
                    ]
                },
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.INFERRED,
                confidence=Confidence.DERIVED,
            ),
        }
        if manifest is not None:
            evidence_by_key["manifest"] = self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="manifest.parsed",
                summary="Decoded binary AndroidManifest.xml",
                payload=manifest.model_dump(mode="json"),
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.DERIVED,
            )
        if resource_summary is not None:
            evidence_by_key["resources"] = self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="resources.inventory",
                summary="Decoded resources.arsc inventory",
                payload=resource_summary.model_dump(mode="json"),
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.DERIVED,
            )
        if dex_summary is not None:
            evidence_by_key["code_index"] = self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="code.index",
                summary="Bounded DEX class and member index",
                payload=dex_summary.model_dump(mode="json"),
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.ORIGINAL,
                confidence=Confidence.DERIVED,
            )
        if inspection.packers:
            evidence_by_key["packers"] = self.evidence.add(
                project_id=project_id,
                artifact_id=artifact.id,
                kind="packer.heuristic",
                summary="Packer markers detected from container filenames",
                payload={
                    "packers": [packer.model_dump(mode="json") for packer in inspection.packers]
                },
                source_tool="analysis_start",
                authority=Authority.SHIPPED_ARTIFACT,
                representation=Representation.INFERRED,
                confidence=Confidence.INFERRED,
            )

        findings = [
            Finding(
                id=finding.id,
                severity=finding.severity,
                category=finding.category,
                title=finding.title,
                detail=finding.detail,
                evidence_ids=(
                    [evidence_by_key[finding.evidence_key].id]
                    if finding.evidence_key in evidence_by_key
                    else []
                ),
            )
            for finding in inspection.findings
        ]
        manifest_evidence = evidence_by_key.get("manifest")
        if manifest is not None:
            for finding in manifest_findings(manifest):
                if manifest_evidence is not None:
                    finding.evidence_ids = [manifest_evidence.id]
                findings.append(finding)
        elif manifest_error and "manifest" in stages:
            findings.append(
                Finding(
                    id="finding_manifest_unavailable",
                    severity="info",
                    category="manifest",
                    title="Manifest could not be decoded",
                    detail=manifest_error,
                )
            )

        if resource_error and "resources" in stages:
            findings.append(
                Finding(
                    id="finding_resources_unavailable",
                    severity="info",
                    category="resources",
                    title="Resource table could not be decoded",
                    detail=resource_error,
                )
            )

        dex_evidence = evidence_by_key.get("code_index")
        if dex_error and "code" in stages:
            findings.append(
                Finding(
                    id="finding_dex_index_unavailable",
                    severity="info",
                    category="code",
                    title="DEX index could not be built",
                    detail=dex_error,
                )
            )
        elif dex_summary is not None:
            failed = [item for item in dex_summary.files if item.error]
            if failed:
                findings.append(
                    Finding(
                        id="finding_dex_file_errors",
                        severity="info",
                        category="code",
                        title="Some DEX files could not be indexed",
                        detail="; ".join(f"{item.name}: {item.error}" for item in failed),
                        evidence_ids=[dex_evidence.id] if dex_evidence is not None else [],
                    )
                )

        if crosscheck_findings:
            findings.extend(crosscheck_findings)

        limitations = list(inspection.limitations)
        if crosscheck_limits:
            limitations.extend(crosscheck_limits)
        if manifest is not None:
            limitations.extend(manifest.limitations)
        elif manifest_error:
            limitations.append(manifest_error)
        if resource_summary is not None:
            limitations.extend(resource_summary.limitations)
        elif resource_error:
            limitations.append(resource_error)
        if dex_summary is not None:
            limitations.extend(dex_summary.limitations)
        elif dex_error:
            limitations.append(dex_error)

        # Transparency banner for engine availability
        if not self.settings.engine_execution_enabled:
            limitations.append(
                "Engine execution is currently disabled (engine_execution_enabled=false). "
                "Analysis is metadata/DEX-index only; external engines (JADX, Ghidra, Apktool) "
                "are not invoked."
            )

        summary: dict[str, object] = {
            "dex_count": len(inspection.dex_files),
            "native_library_count": len(inspection.native_libraries),
            "abi_count": len(inspection.abis),
            "abis": inspection.abis,
            "asset_count": inspection.asset_count,
            "entry_count": inspection.total_entries,
            "archive_names": inspection.names,
            "uncompressed_bytes": inspection.total_uncompressed_bytes,
            "framework_ids": [framework.id for framework in inspection.frameworks],
            "packer_ids": [packer.id for packer in inspection.packers],
        }
        if manifest is not None:
            summary.update(
                {
                    "package": manifest.package,
                    "min_sdk": manifest.min_sdk,
                    "target_sdk": manifest.target_sdk,
                    "requested_permission_count": len(manifest.requested_permissions),
                    "component_count": len(manifest.components),
                    "exported_component_count": len(manifest.exported_components),
                    "deep_link_count": len(manifest.deep_links),
                    "debuggable": manifest.application.debuggable,
                }
            )
        if resource_summary is not None:
            summary.update(
                {
                    "resource_entry_count": resource_summary.entry_count,
                    "resource_value_count": resource_summary.value_count,
                    "resource_config_count": resource_summary.config_count,
                    "resource_type_count": len(resource_summary.types),
                }
            )
        if dex_summary is not None:
            summary.update(
                {
                    "dex_indexed_file_count": dex_summary.file_count,
                    "dex_class_count": dex_summary.class_count,
                    "dex_method_count": dex_summary.method_count,
                    "dex_field_count": dex_summary.field_count,
                    "dex_string_count": dex_summary.string_count,
                    "multi_dex": dex_summary.multi_dex,
                }
            )
        if endpoints is not None:
            summary.update(
                {
                    "endpoint_count": endpoints.total_count,
                    "url_count": len(endpoints.urls),
                }
            )
        if storage is not None:
            summary.update(
                {
                    "sqlite_database_count": len(storage.sqlite_databases),
                    "shared_preference_count": len(storage.shared_preferences),
                    "storage_technologies": storage.storage_technologies,
                }
            )

        return AnalysisReport(
            report_id=new_id("rep"),
            project_id=project_id,
            artifact_id=artifact.id,
            artifact_type=artifact.artifact_type,
            filename=artifact.filename,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            generated_at=datetime.now(UTC),
            stages=stages,
            coverage=Coverage(
                stages_completed=stages,
                stages_skipped=[stage for stage in ALLOWED_STAGES if stage not in stages],
                limitations=limitations,
            ),
            summary=summary,
            dex_files=inspection.dex_files,
            native_libraries=inspection.native_libraries,
            signature=inspection.signature,
            frameworks=inspection.frameworks,
            packers=inspection.packers,
            manifest=manifest,
            manifest_error=manifest_error,
            resource_summary=resource_summary,
            resource_error=resource_error,
            dex_summary=dex_summary,
            dex_error=dex_error,
            endpoints=endpoints,
            storage=storage,
            findings=findings,
            evidence_ids=[record.id for record in evidence_by_key.values()],
        )

    def get_job(self, project_id: str, job_id: str) -> AnalysisJob:
        self.projects.get_or_raise(project_id)
        job = self.jobs.get(job_id)
        if job is None or job.project_id != project_id:
            raise InvalidArgumentsError(
                f"Job not found in project {project_id}: {job_id}",
                hint="Call analysis_get_status with a job_id returned by analysis_start.",
            )
        return job

    def cancel(self, project_id: str, job_id: str) -> AnalysisJob:
        job = self.get_job(project_id, job_id)
        if job.status.terminal:
            raise StateError(
                f"Job is already {job.status.value}.",
                hint="Only queued or running jobs can be cancelled.",
            )
        job.status = JobStatus.CANCELLED
        job.updated_at = utc_now()
        return self.jobs.update(job)

    def get_report(self, project_id: str, job_id: str) -> AnalysisReport:
        job = self.get_job(project_id, job_id)
        if job.status != JobStatus.COMPLETED:
            raise StateError(
                f"Job is {job.status.value}; no report is available.",
                hint="Poll analysis_get_status until the job is completed.",
            )
        raw = self.jobs.get_result(job.id)
        if raw is None:
            raise StateError("Completed job has no stored report.")
        return AnalysisReport.model_validate(raw)

    async def wait(
        self,
        project_id: str,
        job_id: str,
        *,
        timeout_seconds: float | None = None,
        interval_seconds: float = 0.1,
    ) -> AnalysisJob:
        deadline = time.monotonic() + (timeout_seconds or self.settings.analysis_timeout_seconds)
        while time.monotonic() < deadline:
            job = self.get_job(project_id, job_id)
            if job.status.terminal:
                return job
            await asyncio.sleep(interval_seconds)
        raise StateError(
            "Timed out while waiting for the analysis job.",
            hint="Poll analysis_get_status or raise RAA_ANALYSIS_TIMEOUT_SECONDS.",
            details={"job_id": job_id},
        )

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def _normalize_stages(stages: list[str] | None) -> list[str]:
    if stages is None:
        return list(ALLOWED_STAGES)
    normalized: list[str] = []
    unknown: list[str] = []
    for stage in stages:
        value = stage.strip().lower()
        if value not in ALLOWED_STAGES:
            unknown.append(stage)
            continue
        if value not in normalized:
            normalized.append(value)
    if unknown:
        raise InvalidArgumentsError(
            "Unknown analysis stage(s): " + ", ".join(unknown),
            hint="Valid stages are: " + ", ".join(ALLOWED_STAGES),
            details={"allowed": list(ALLOWED_STAGES)},
        )
    if not normalized:
        raise InvalidArgumentsError("At least one analysis stage is required.")
    return normalized
