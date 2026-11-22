"""Diff service managing artifact comparisons, changes query, and diff reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from raa.domain.diff import DiffChangeItem, DiffReport
from raa.domain.models import Authority, Confidence
from raa.errors import NotFoundError
from raa.services.android.diff_engine import compare_apks, export_diff_report
from raa.services.artifacts import ArtifactService
from raa.services.evidence import EvidenceService
from raa.services.workspace import Workspace


class DiffService:
    """Coordinates version diffs, noise filtering, and change exports."""

    def __init__(
        self,
        workspace: Workspace,
        artifacts: ArtifactService,
        evidence: EvidenceService,
    ) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.evidence = evidence
        self._diff_reports: dict[str, DiffReport] = {}

    def get_diff_dir(self, project_id: str) -> Path:
        """Directory for diff outputs and reports."""
        d = self.workspace.root / "projects" / project_id / "diffs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def compare(
        self,
        project_id: str,
        base_artifact_id: str,
        target_artifact_id: str,
        categories: list[str] | None = None,
    ) -> DiffReport:
        """Run semantic diff between base and target APK containers."""
        base_art = self.artifacts.get_or_raise(project_id, base_artifact_id)
        target_art = self.artifacts.get_or_raise(project_id, target_artifact_id)

        base_path = self.artifacts.path_for(base_art)
        target_path = self.artifacts.path_for(target_art)

        report = compare_apks(
            base_path,
            target_path,
            base_artifact_id=base_artifact_id,
            target_artifact_id=target_artifact_id,
            project_id=project_id,
            categories=categories,
        )
        self._diff_reports[report.diff_id] = report

        # Persist report to workspace
        diff_file = self.get_diff_dir(project_id) / f"{report.diff_id}.json"
        diff_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")

        # Record evidence
        self.evidence.add(
            project_id=project_id,
            artifact_id=target_artifact_id,
            kind="diff.report",
            summary=(
                f"Diff between {base_artifact_id} and {target_artifact_id}: "
                f"{report.total_changes} change(s) "
                f"({report.semantic_changes_count} semantic, {report.noise_changes_count} noise)"
            ),
            payload={
                "diff_id": report.diff_id,
                "base_artifact_id": base_artifact_id,
                "target_artifact_id": target_artifact_id,
                "total_changes": report.total_changes,
                "semantic_changes": report.semantic_changes_count,
                "noise_changes": report.noise_changes_count,
            },
            source_tool="artifact_compare",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )

        return report

    def _get_report(self, project_id: str, diff_id: str) -> DiffReport:
        if diff_id in self._diff_reports:
            return self._diff_reports[diff_id]
        diff_file = self.get_diff_dir(project_id) / f"{diff_id}.json"
        if diff_file.is_file():
            report = DiffReport.model_validate_json(diff_file.read_text(encoding="utf-8"))
            self._diff_reports[diff_id] = report
            return report
        raise NotFoundError(
            f"Diff report '{diff_id}' not found.",
            hint="Run artifact_compare first to produce a diff report.",
            details={"diff_id": diff_id},
        )

    def list_changes(
        self,
        project_id: str,
        diff_id: str,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List paginated changes for a diff comparison."""
        report = self._get_report(project_id, diff_id)

        changes = report.changes
        if category:
            changes = [c for c in changes if c.category.value == category.lower()]

        total = len(changes)
        paged = changes[offset : offset + limit]

        return {
            "diff_id": diff_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "changes": [c.model_dump(mode="json") for c in paged],
        }

    def get_change(self, project_id: str, diff_id: str, change_id: str) -> DiffChangeItem:
        """Retrieve full details of one specific change entry."""
        report = self._get_report(project_id, diff_id)

        for ch in report.changes:
            if ch.change_id == change_id:
                return ch

        raise NotFoundError(
            f"Change '{change_id}' not found in diff report '{diff_id}'.",
            details={"change_id": change_id, "diff_id": diff_id},
        )

    def export(self, project_id: str, diff_id: str, format_type: str = "json") -> str:
        """Export diff report in JSON, Markdown, or unified diff format."""
        report = self._get_report(project_id, diff_id)

        return export_diff_report(report, format_type=format_type)
