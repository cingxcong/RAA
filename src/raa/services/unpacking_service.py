"""Orchestrator service for unpacking, packer detection, deobfuscation, retrace, and native."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from raa.domain.models import Authority, Confidence
from raa.domain.unpacking import (
    DeobfuscationResult,
    NativeInventoryReport,
    PackerDetectionReport,
    RetraceReport,
    UnpackExtractionReport,
    UnpackVerificationReport,
)
from raa.errors import NotFoundError
from raa.services.android.deobfuscator import deobfuscate_source
from raa.services.android.dump_verifier import verify_dex_dump
from raa.services.android.native_adapters import (
    GhidraNativeAdapter,
    RizinNativeAdapter,
    inventory_native_libraries,
)
from raa.services.android.packer_detector import detect_packers_and_protectors
from raa.services.android.payload_extractor import extract_static_payloads
from raa.services.android.retracer import execute_retrace

if TYPE_CHECKING:
    from raa.services.artifacts import ArtifactService
    from raa.services.engine_runner import EngineRunner
    from raa.services.evidence import EvidenceService
    from raa.services.workspace import Workspace


class UnpackingService:
    """Coordinates packer detection, static payload carving,
    verification, deobfuscation, and retrace.
    """

    def __init__(
        self,
        workspace: Workspace,
        artifacts: ArtifactService,
        evidence: EvidenceService,
        engine_runner: EngineRunner | None = None,
    ) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.evidence = evidence
        self.engine_runner = engine_runner
        self.ghidra = GhidraNativeAdapter(runner=engine_runner)
        self.rizin = RizinNativeAdapter(runner=engine_runner)

    def get_unpack_dir(self, project_id: str) -> Path:
        """Get or create project unpacking directory."""
        p = self.workspace.root / "projects" / project_id / "unpacking"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _resolve_apk_path(
        self, project_id: str, artifact_id: str | None = None
    ) -> tuple[str, Path]:
        """Resolve artifact ID and actual local filesystem path."""
        if artifact_id:
            art = self.artifacts.get_or_raise(project_id, artifact_id)
            return art.id, self.workspace.root / art.stored_path

        # Find first APK in project
        proj_artifacts = self.artifacts.repository.list(project_id)
        for art in proj_artifacts:
            if art.artifact_type in ("apk", "aab", "aar"):
                return art.id, self.workspace.root / art.stored_path

        if proj_artifacts:
            art0 = proj_artifacts[0]
            return art0.id, self.workspace.root / art0.stored_path

        raise NotFoundError("No APK or Android container artifact found in project.")

    def detect_packers(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> PackerDetectionReport:
        """Detect packers, protectors, obfuscators, and anti-analysis mechanisms."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        report = detect_packers_and_protectors(apk_path, artifact_id=aid)

        # Record evidence
        total_findings = len(report.packers) + len(report.protectors) + len(report.anti_analysis)
        ev = self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="packer.detection",
            summary=(
                f"Packer detection: {'Packed' if report.is_packed else 'Clean'} "
                f"({total_findings} finding(s))"
            ),
            payload={
                "is_packed": report.is_packed,
                "packers": [p.name for p in report.packers],
                "protectors": [p.name for p in report.protectors],
                "anti_analysis": [a.name for a in report.anti_analysis],
                "entropy_score": report.entropy_score,
            },
            source_tool="packer_detect",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.DERIVED,
        )
        for p in report.packers:
            p.evidence_ids.append(ev.id)
        for a in report.anti_analysis:
            a.evidence_ids.append(ev.id)

        return report

    def extract_payloads(
        self,
        project_id: str,
        artifact_id: str | None = None,
        output_dir: Path | None = None,
    ) -> UnpackExtractionReport:
        """Statically carve and extract embedded DEX, ZIP, or encrypted payload containers."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        target_dir = output_dir or (self.get_unpack_dir(project_id) / "carved")
        report = extract_static_payloads(apk_path, target_dir, artifact_id=aid)
        report.project_id = project_id

        # Record evidence for each extracted payload
        for payload in report.payloads:
            ev = self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="unpack.payload",
                summary=f"Extracted payload ({payload.kind.value}) from {payload.source_path}",
                payload={
                    "payload_id": payload.payload_id,
                    "kind": payload.kind.value,
                    "size_bytes": payload.size_bytes,
                    "sha256": payload.sha256,
                    "output_path": payload.output_path,
                },
                source_tool="unpack_extract",
                authority=Authority.CONTROLLED_REPLAY,
                confidence=Confidence.OBSERVED,
            )
            payload.evidence_ids.append(ev.id)

        return report

    def verify_dump(
        self,
        project_id: str,
        file_path: Path,
        reanalyze: bool = False,
    ) -> UnpackVerificationReport:
        """Validate structural completeness, checksums, and real bytecode of a DEX dump."""
        report = verify_dex_dump(file_path)

        # If reanalyze requested and valid, ingest into project artifact repository
        if reanalyze and report.status.value in ("complete", "partial"):
            try:
                # Ingest into artifact repository so downstream analyzers can target it
                ingest_res = self.artifacts.ingest_path(project_id, str(file_path))
                report.reanalyzed = True
                report.reanalyzed_artifact_id = ingest_res.artifact.id
                self.evidence.add(
                    project_id=project_id,
                    artifact_id=ingest_res.artifact.id,
                    kind="unpack.reanalyzed",
                    summary=f"Ingested dumped DEX {file_path.name} as artifact for re-analysis",
                    payload={"artifact_id": ingest_res.artifact.id, "sha256": report.sha256},
                    source_tool="unpack_verify",
                    authority=Authority.CONTROLLED_REPLAY,
                    confidence=Confidence.OBSERVED,
                )
            except Exception as exc:
                report.issues.append(f"Re-analysis ingestion failed: {exc}")

        return report

    def deobfuscate(
        self,
        project_id: str,
        target: str,
        strategy: str = "simplify",
        source_text: str | None = None,
    ) -> DeobfuscationResult:
        """Deobfuscate target code/representation and record provenance warnings."""
        code_to_transform = source_text or f'// Target {target}\nClass.forName("{target}");'
        output_dir = self.get_unpack_dir(project_id) / "deobfuscated"
        result = deobfuscate_source(
            source_code=code_to_transform,
            target_name=target,
            strategy=strategy,
            output_dir=output_dir,
        )

        ev = self.evidence.add(
            project_id=project_id,
            kind="deobfuscation.result",
            summary=f"Deobfuscation applied to {target} (strategy: {strategy})",
            payload={
                "target": target,
                "strategy": strategy,
                "transformed": result.transformed,
                "constants_decrypted": result.constants_decrypted,
                "reflections_resolved": result.reflections_resolved,
            },
            source_tool="deobfuscate",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.DERIVED,
        )
        result.evidence_ids.append(ev.id)
        return result

    def retrace(
        self,
        project_id: str,
        mapping_path: Path,
        stack_trace: str | None = None,
    ) -> RetraceReport:
        """Parse ProGuard mapping file, retrace stack traces, and report coverage."""
        report = execute_retrace(mapping_path, stack_trace)

        self.evidence.add(
            project_id=project_id,
            kind="retrace.report",
            summary=(
                f"Retrace mapping: {report.total_classes_mapped} classes, "
                f"{report.retrace_coverage_percent}% coverage"
            ),
            payload={
                "mapping_file": str(mapping_path),
                "classes_mapped": report.total_classes_mapped,
                "methods_mapped": report.total_methods_mapped,
                "fields_mapped": report.total_fields_mapped,
                "coverage_percent": report.retrace_coverage_percent,
            },
            source_tool="retrace",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.DERIVED,
        )
        return report

    def inventory_native(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> NativeInventoryReport:
        """Inventory all native shared objects (.so) across all ABIs in an APK."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        report = inventory_native_libraries(apk_path, artifact_id=aid)

        self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="native.inventory",
            summary=(
                f"Native inventory: {report.total_libraries} library(ies) across "
                f"{len(report.abis_present)} ABI(s)"
            ),
            payload={
                "total_libraries": report.total_libraries,
                "abis": report.abis_present,
                "libraries": [lib.library_name for lib in report.libraries],
            },
            source_tool="native_list_libraries",
            authority=Authority.SHIPPED_ARTIFACT,
            confidence=Confidence.OBSERVED,
        )
        return report
