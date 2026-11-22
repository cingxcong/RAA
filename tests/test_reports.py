"""Report rendering and export tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from raa.domain.models import (
    AnalysisReport,
    Confidence,
    Coverage,
    Finding,
    FrameworkFinding,
    SignatureInfo,
)
from raa.services.reports import render_markdown, write_report
from raa.services.workspace import Workspace


def _report() -> AnalysisReport:
    return AnalysisReport(
        report_id="rep_test",
        project_id="prj_test",
        artifact_id="art_test",
        artifact_type="apk",
        filename="sample.apk",
        sha256="a" * 64,
        size_bytes=1024,
        generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        stages=["container", "inventory"],
        coverage=Coverage(
            stages_completed=["container", "inventory"],
            stages_skipped=["signatures"],
            limitations=["No code analysis was performed."],
        ),
        summary={"dex_count": 2, "framework_ids": ["flutter"]},
        signature=SignatureInfo(
            v1_certificates=["META-INF/CERT.RSA"],
            apk_signing_block=False,
            status="signed_v1",
        ),
        frameworks=[
            FrameworkFinding(
                id="flutter",
                name="Flutter",
                category="cross_platform",
                confidence=Confidence.OBSERVED,
                markers=["lib/arm64-v8a/libflutter.so"],
            )
        ],
        findings=[
            Finding(
                id="finding_signature_v1_only",
                severity="low",
                category="signature",
                title="Only legacy v1 signing was detected",
                detail="No APK Signing Block.",
                evidence_ids=["ev_signature"],
            )
        ],
        evidence_ids=["ev_signature"],
    )


def test_markdown_contains_claims_and_evidence() -> None:
    markdown = render_markdown(_report())
    assert "# RAA analysis report" in markdown
    assert "rep_test" in markdown
    assert "a" * 64 in markdown
    assert "Flutter" in markdown
    assert "Only legacy v1 signing was detected" in markdown
    assert "ev_signature" in markdown
    assert "No code analysis was performed." in markdown
    assert "signed_v1" in markdown


def test_write_markdown_export(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    workspace.ensure()
    result = write_report(
        _report(),
        format="markdown",
        workspace=workspace,
        filename="report.md",
    )
    path = Path(result.path)
    assert path.is_file()
    assert path.parent == workspace.exports_dir / "prj_test"
    assert result.format == "markdown"
    assert result.size_bytes == path.stat().st_size


def test_write_json_export(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    workspace.ensure()
    result = write_report(
        _report(),
        format="json",
        workspace=workspace,
        filename="report.json",
    )
    path = Path(result.path)
    assert path.is_file()
    assert result.format == "json"
    assert '"report_id": "rep_test"' in path.read_text(encoding="utf-8")


def test_export_filename_is_sanitized(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspace")
    workspace.ensure()
    result = write_report(
        _report(),
        format="json",
        workspace=workspace,
        filename="../../escape.json",
    )
    path = Path(result.path)
    assert path.parent == workspace.exports_dir / "prj_test"
    assert path.name == "escape.json"
