"""Agent coverage tracking service.

Measures reverse engineering and reconstruction coverage across activities,
API endpoints, native libraries, and UI screens for a given project.
"""

from __future__ import annotations

from typing import Any

from raa.domain.models import Authority, Confidence
from raa.services.artifacts import ArtifactService
from raa.services.evidence import EvidenceService
from raa.services.projects import ProjectService
from raa.services.workspace import Workspace


class CoverageTracker:
    """Calculates multidimensional reversing and reconstruction coverage."""

    def __init__(
        self,
        workspace: Workspace,
        evidence: EvidenceService,
        artifacts: ArtifactService,
        projects: ProjectService,
    ) -> None:
        self.workspace = workspace
        self.evidence = evidence
        self.artifacts = artifacts
        self.projects = projects

    def get_coverage(self, project_id: str) -> dict[str, Any]:
        """Compute coverage metrics across all analysis dimensions for a project."""
        self.projects.get_or_raise(project_id)
        evidence_records = self.evidence.list(project_id, limit=500)

        kinds = {ev.kind for ev in evidence_records}

        # 1. Activities Coverage
        total_activities = 1
        analyzed_activities = 0
        for ev in evidence_records:
            if ev.kind in ("android_manifest", "manifest"):
                components = ev.payload.get("components", {})
                acts = components.get("activities", [])
                if acts:
                    total_activities = max(len(acts), 1)
            if ev.kind in ("ui_runtime_capture", "screen_model", "source_class"):
                analyzed_activities += 1
        analyzed_activities = min(analyzed_activities, total_activities)
        activity_pct = round((analyzed_activities / total_activities) * 100.0, 1)

        # 2. Endpoints Coverage
        total_endpoints = 0
        synthesized_spec = False
        for ev in evidence_records:
            if ev.kind in ("api_endpoints", "api_endpoint_list"):
                endpoints = ev.payload.get("endpoints", [])
                total_endpoints = max(total_endpoints, len(endpoints))
            if ev.kind == "api_synthesized_spec":
                synthesized_spec = True
        if synthesized_spec and total_endpoints > 0:
            endpoints_pct = 100.0
        elif total_endpoints > 0:
            endpoints_pct = 50.0
        else:
            endpoints_pct = 0.0

        # 3. Native Libraries Coverage
        has_native_symbols = (
            "native_symbols" in kinds
            or "native_decompile" in kinds
            or "unity_il2cpp_metadata" in kinds
        )
        has_flutter_analysis = "flutter_strings" in kinds or "flutter_patched_apk" in kinds
        if has_native_symbols and has_flutter_analysis:
            native_pct = 100.0
        elif has_native_symbols or has_flutter_analysis:
            native_pct = 50.0
        else:
            native_pct = 0.0

        # 4. UI Reconstruction Coverage
        has_capture = "ui_runtime_capture" in kinds
        has_redesign = "screen_redesign" in kinds
        has_diff = "visual_comparison" in kinds
        ui_score = 0.0
        if has_capture:
            ui_score += 35.0
        if has_redesign:
            ui_score += 45.0
        if has_diff:
            ui_score += 20.0
        ui_pct = round(ui_score, 1)

        # Overall weighted score
        overall = round(
            (activity_pct * 0.25) + (endpoints_pct * 0.25) + (native_pct * 0.25) + (ui_pct * 0.25),
            1,
        )

        gaps = []
        if activity_pct < 100.0:
            diff_acts = total_activities - analyzed_activities
            gaps.append(f"{diff_acts} activities lack source or UI inspection.")
        if not synthesized_spec:
            gaps.append("API specification has not been synthesized into OpenAPI 3.1.")
        if not has_redesign:
            gaps.append("Modern UI redesign has not been generated.")
        if not has_flutter_analysis and not has_native_symbols:
            gaps.append("Native binaries or framework runtimes have not been disassembled/dumped.")

        report = {
            "project_id": project_id,
            "overall_coverage_pct": overall,
            "dimensions": {
                "activities": {
                    "total": total_activities,
                    "analyzed": analyzed_activities,
                    "percentage": activity_pct,
                },
                "api_endpoints": {
                    "total_discovered": total_endpoints,
                    "spec_synthesized": synthesized_spec,
                    "percentage": endpoints_pct,
                },
                "native_binaries": {
                    "analyzed": has_native_symbols or has_flutter_analysis,
                    "percentage": native_pct,
                },
                "ui_reconstruction": {
                    "runtime_captured": has_capture,
                    "redesign_generated": has_redesign,
                    "visually_verified": has_diff,
                    "percentage": ui_pct,
                },
            },
            "evidence_count": len(evidence_records),
            "unresolved_gaps": gaps,
        }

        self.evidence.add(
            project_id=project_id,
            kind="agent_coverage_report",
            summary=f"Project reversing coverage: {overall}% ({len(gaps)} open gaps)",
            payload=report,
            source_tool="agent_coverage_get",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )

        return report
