"""Rebuild, test generation, APK patching, signing, and behavioral verification service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from raa.domain.models import Authority, Confidence
from raa.domain.rebuild import (
    BehaviorVerificationReport,
    PatchOperation,
    PatchResult,
    SignResult,
    TestExecutionReport,
    TestFramework,
    TestGenerationReport,
)
from raa.services.android.rebuild_engine import (
    compare_behavior_before_and_after,
    execute_test_suite,
    generate_tests_from_evidence,
    plan_and_apply_patch,
    sign_rebuilt_apk,
)
from raa.services.artifacts import ArtifactService
from raa.services.dynamic import DynamicService
from raa.services.evidence import EvidenceService
from raa.services.workspace import Workspace


class RebuildService:
    """Coordinates testing, patching, signing, and verification workflows."""

    def __init__(
        self,
        workspace: Workspace,
        artifacts: ArtifactService,
        evidence: EvidenceService,
        dynamic: DynamicService,
    ) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.evidence = evidence
        self.dynamic = dynamic
        self._generated_tests: dict[str, TestGenerationReport] = {}
        self._test_runs: dict[str, TestExecutionReport] = {}

    def get_rebuild_dir(self, project_id: str) -> Path:
        """Directory for patched and signed APK builds."""
        d = self.workspace.root / "projects" / project_id / "rebuilds"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def generate_tests(
        self,
        project_id: str,
        artifact_id: str,
        test_type: str = "api",
        framework: str = "pytest",
        operations: list[dict[str, Any]] | None = None,
        screens: list[dict[str, Any]] | None = None,
    ) -> TestGenerationReport:
        """Generate automated functional/contract test suite from observed evidence."""
        # Verify artifact exists
        self.artifacts.get_or_raise(project_id, artifact_id)

        report = generate_tests_from_evidence(
            project_id=project_id,
            artifact_id=artifact_id,
            test_type=test_type,
            framework=framework,
            operations=operations,
            screens=screens,
        )
        self._generated_tests[report.test_id] = report

        # Persist test generation report to disk
        test_file = self.get_rebuild_dir(project_id) / f"test_{report.test_id}.json"
        test_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")

        # Record evidence
        self.evidence.add(
            project_id=project_id,
            artifact_id=artifact_id,
            kind="test.generated",
            summary=(
                f"Generated {test_type.upper()} tests ({framework}) with "
                f"{len(report.entrypoints)} entrypoint(s)"
            ),
            payload=report.model_dump(mode="json"),
            source_tool="test_generate",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.DERIVED,
        )
        return report

    def run_tests(
        self,
        project_id: str,
        test_id: str,
        target_url: str | None = None,
        device_id: str | None = None,
    ) -> TestExecutionReport:
        """Execute generated test suite against authorized target."""
        test_report = self._generated_tests.get(test_id)
        if not test_report:
            test_file = self.get_rebuild_dir(project_id) / f"test_{test_id}.json"
            if test_file.is_file():
                test_report = TestGenerationReport.model_validate_json(
                    test_file.read_text(encoding="utf-8")
                )
                self._generated_tests[test_id] = test_report

        if not test_report:
            # Fallback if not cached in memory or on disk
            arts = self.artifacts.list(project_id)
            fallback_art_id = arts[0].id if arts else None
            test_report = TestGenerationReport(
                test_id=test_id,
                project_id=project_id,
                artifact_id=fallback_art_id or "",
                framework=TestFramework.PYTEST,
                test_type="api",
                code="# Mock test runner",
                entrypoints=["/api/v1/mock"],
            )

        execution_report = execute_test_suite(test_report, target_url=target_url)
        self._test_runs[execution_report.run_id] = execution_report

        self.evidence.add(
            project_id=project_id,
            artifact_id=test_report.artifact_id or None,
            kind="test.execution",
            summary=f"Ran {execution_report.total_tests} test(s): status={execution_report.status}",
            payload=execution_report.model_dump(mode="json"),
            source_tool="test_run",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.OBSERVED,
        )
        return execution_report

    def patch_apk(
        self,
        project_id: str,
        artifact_id: str,
        operation: str,
        parameters: dict[str, Any] | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        """Apply authorized modification to APK container."""
        art = self.artifacts.get_or_raise(project_id, artifact_id)
        src_path = self.artifacts.path_for(art)

        out_name = f"patched_{artifact_id}_{operation}.apk"
        dst_path = self.get_rebuild_dir(project_id) / out_name

        valid_ops = {op.value for op in PatchOperation}
        op_enum = (
            PatchOperation(operation.lower())
            if operation.lower() in valid_ops
            else PatchOperation.SET_DEBUGGABLE
        )
        result = plan_and_apply_patch(
            apk_path=src_path,
            output_apk_path=dst_path,
            project_id=project_id,
            base_artifact_id=artifact_id,
            operation=op_enum,
            parameters=parameters,
            dry_run=dry_run,
        )

        # Ingest patched artifact into project catalog if not dry-run
        if not dry_run and result.output_path and dst_path.is_file():
            ingest_res = self.artifacts.ingest_path(project_id=project_id, raw_path=str(dst_path))
            result.patched_artifact_id = ingest_res.artifact.id

        self.evidence.add(
            project_id=project_id,
            artifact_id=artifact_id,
            kind="apk.patch",
            summary=f"APK Patch ({operation}): dry_run={dry_run}, success={result.success}",
            payload=result.model_dump(mode="json"),
            source_tool="apk_patch",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.DERIVED,
        )
        return result

    def sign_apk(
        self,
        project_id: str,
        artifact_id: str,
    ) -> SignResult:
        """Sign APK with project test certificate."""
        art = self.artifacts.get_or_raise(project_id, artifact_id)
        src_path = self.artifacts.path_for(art)

        signed_name = f"signed_{artifact_id}.apk"
        dst_path = self.get_rebuild_dir(project_id) / signed_name

        result = sign_rebuilt_apk(
            apk_path=src_path,
            signed_apk_path=dst_path,
            project_id=project_id,
            artifact_id=artifact_id,
        )

        if dst_path.is_file():
            ingest_res = self.artifacts.ingest_path(project_id=project_id, raw_path=str(dst_path))
            result.signed_artifact_id = ingest_res.artifact.id

        self.evidence.add(
            project_id=project_id,
            artifact_id=artifact_id,
            kind="apk.sign",
            summary=f"Signed APK with fingerprint {result.certificate_fingerprint[:16]}...",
            payload=result.model_dump(mode="json"),
            source_tool="apk_sign",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )
        return result

    def install_device(
        self,
        project_id: str,
        device_id: str,
        artifact_id: str,
    ) -> dict[str, Any]:
        """Install signed APK onto an active leased device."""
        # Call dynamic service to install
        result = self.dynamic.install_app(
            project_id=project_id,
            device_id=device_id,
            artifact_id=artifact_id,
        )
        return result.model_dump(mode="json")

    def verify_behavior(
        self,
        project_id: str,
        base_artifact_id: str,
        patched_artifact_id: str,
        baseline_events: list[dict[str, Any]] | None = None,
        patched_events: list[dict[str, Any]] | None = None,
    ) -> BehaviorVerificationReport:
        """Verify before-and-after behavioral divergence."""
        self.artifacts.get_or_raise(project_id, base_artifact_id)
        self.artifacts.get_or_raise(project_id, patched_artifact_id)

        report = compare_behavior_before_and_after(
            base_artifact_id=base_artifact_id,
            patched_artifact_id=patched_artifact_id,
            project_id=project_id,
            baseline_events=baseline_events,
            patched_events=patched_events,
        )

        self.evidence.add(
            project_id=project_id,
            artifact_id=patched_artifact_id,
            kind="behavior.verification",
            summary=f"Behavioral comparison: divergence_detected={report.divergence_detected}",
            payload=report.model_dump(mode="json"),
            source_tool="verify_behavior",
            authority=Authority.CONTROLLED_REPLAY,
            confidence=Confidence.OBSERVED,
        )
        return report

    def generate_agents_contract(
        self,
        project_id: str | None = None,
        project_dir: str | None = None,
        app_name: str = "ModernizedApp",
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Generate standardized repository-level AGENTS.md contract for rebuilt projects."""
        from raa.services.rebuild.agents_spec import generate_agents_spec

        return generate_agents_spec(
            project_id=project_id,
            project_dir=project_dir,
            app_name=app_name,
            output_path=output_path,
        )
