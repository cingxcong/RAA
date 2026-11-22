"""Report rendering and workspace exports."""

from __future__ import annotations

from raa.domain.models import AnalysisReport, ExportResult
from raa.errors import InvalidArgumentsError
from raa.services.workspace import Workspace, sanitize_filename


def write_report(
    report: AnalysisReport,
    *,
    format: str,
    workspace: Workspace,
    filename: str | None = None,
) -> ExportResult:
    normalized = format.lower()
    if normalized in {"md", "markdown"}:
        extension = "md"
        content = render_markdown(report)
    elif normalized == "json":
        extension = "json"
        content = report.model_dump_json(indent=2)
    else:
        raise InvalidArgumentsError(
            f"Unsupported report format: {format}",
            hint="Use 'json' or 'markdown'.",
            details={"supported": ["json", "markdown"]},
        )

    default_name = f"report_{report.report_id}.{extension}"
    path = workspace.export_path(
        report.project_id,
        sanitize_filename(filename or default_name),
    )
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return ExportResult(
        format="markdown" if extension == "md" else "json",
        path=str(path),
        size_bytes=len(content.encode("utf-8")),
    )


def render_markdown(report: AnalysisReport) -> str:
    lines: list[str] = [
        "# RAA analysis report",
        "",
        f"- Report: `{report.report_id}`",
        f"- Artifact: `{report.filename}`",
        f"- Artifact ID: `{report.artifact_id}`",
        f"- Type: `{report.artifact_type}`",
        f"- SHA-256: `{report.sha256}`",
        f"- Size: {report.size_bytes} bytes",
        f"- Generated: {report.generated_at.isoformat()}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in report.summary.items():
        if isinstance(value, list):
            rendered = ", ".join(str(item) for item in value) or "-"
        else:
            rendered = str(value)
        lines.append(f"| {key} | {rendered} |")

    lines.extend(["", "## Manifest", ""])
    manifest = report.manifest
    if manifest is None:
        lines.append(f"Manifest unavailable: {report.manifest_error or 'manifest stage not run'}.")
    else:
        lines.extend(
            [
                "| Field | Value |",
                "|---|---|",
                f"| Package | `{manifest.package or '-'}` |",
                f"| Version | `{manifest.version_name or '-'}` ({manifest.version_code or '-'}) |",
                f"| Min SDK | {manifest.min_sdk if manifest.min_sdk is not None else '-'} |",
                "| Target SDK | "
                f"{manifest.target_sdk if manifest.target_sdk is not None else '-'} |",
                f"| Debuggable | {manifest.application.debuggable} |",
                f"| Cleartext traffic | {manifest.application.effective_cleartext_traffic} |",
                f"| Allow backup | {manifest.application.allow_backup} |",
                "",
            ]
        )
        if manifest.requested_permissions:
            permissions = ", ".join(
                f"`{permission.name}`" for permission in manifest.requested_permissions
            )
            lines.extend(["### Requested permissions", "", permissions, ""])
        if manifest.components:
            lines.extend(
                [
                    "### Components",
                    "",
                    "| Kind | Name | Exported | Permission |",
                    "|---|---|---|---|",
                ]
            )
            for component in manifest.components:
                lines.append(
                    f"| {component.kind} | `{component.name}` | "
                    f"{component.effective_exported} | {component.permission or '-'} |"
                )
            lines.append("")
        if manifest.deep_links:
            lines.extend(
                ["### Deep links", "", "| Component | Scheme | Host | Path |", "|---|---|---|---|"]
            )
            for link in manifest.deep_links:
                path = link.path_prefix or link.path or link.path_pattern or "-"
                lines.append(
                    f"| `{link.component}` | {link.scheme} | {link.host or '-'} | {path} |"
                )
            lines.append("")

    lines.extend(["", "## Resources", ""])
    resources = report.resource_summary
    if resources is None:
        lines.append(
            f"Resource table unavailable: {report.resource_error or 'resources stage not run'}."
        )
    else:
        lines.extend(
            [
                f"- Packages: {', '.join(f'`{item}`' for item in resources.packages) or '-'}",
                f"- Resource IDs: {resources.entry_count}",
                f"- Configuration variants: {resources.value_count}",
                f"- Configurations: {resources.config_count}",
                f"- Skipped compact entries: {resources.skipped_compact_entries}",
                "",
                "| Type | Resource IDs | Variants | Default values |",
                "|---|---:|---:|---:|",
            ]
        )
        for resource_type in resources.types:
            lines.append(
                f"| {resource_type.type} | {resource_type.entry_count} "
                f"| {resource_type.value_count} | {resource_type.default_count} |"
            )
        lines.append("")

    lines.extend(["", "## Code", ""])
    dex = report.dex_summary
    if dex is None:
        lines.append(f"DEX index unavailable: {report.dex_error or 'code stage not run'}.")
    else:
        lines.extend(
            [
                f"- Indexed DEX files: {dex.file_count}",
                f"- Classes: {dex.class_count}",
                f"- Declared methods: {dex.method_count}",
                f"- Declared fields: {dex.field_count}",
                f"- Strings: {dex.string_count}",
                f"- Multi-DEX: {dex.multi_dex}",
                "",
                "| DEX file | Version | Classes | Methods | Fields | Strings | Error |",
                "|---|---|---:|---:|---:|---:|---|",
            ]
        )
        for dex_file in dex.files:
            lines.append(
                f"| `{dex_file.name}` | {dex_file.version or '-'} | {dex_file.class_count} "
                f"| {dex_file.method_count} | {dex_file.field_count} | {dex_file.string_count} "
                f"| {dex_file.error or '-'} |"
            )
        lines.append("")

    lines.extend(["", "## Frameworks", ""])
    if report.frameworks:
        lines.extend(
            [
                "| ID | Name | Category | Confidence | Markers |",
                "|---|---|---|---|---|",
            ]
        )
        for framework in report.frameworks:
            markers = ", ".join(framework.markers[:5]) or "-"
            lines.append(
                f"| {framework.id} | {framework.name} | {framework.category} "
                f"| {framework.confidence.value} | {markers} |"
            )
    else:
        lines.append("No framework markers were detected.")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        lines.extend(["| Severity | Category | Finding | Evidence |", "|---|---|---|---|"])
        for finding in report.findings:
            evidence = ", ".join(f"`{item}`" for item in finding.evidence_ids) or "-"
            lines.append(
                f"| {finding.severity} | {finding.category} | {finding.title} | {evidence} |"
            )
    else:
        lines.append("No findings.")

    lines.extend(
        [
            "",
            "## Signature",
            "",
            f"- Status: `{report.signature.status}`",
            f"- v1 certificate files: {len(report.signature.v1_certificates)}",
            f"- APK Signing Block: {report.signature.apk_signing_block}",
            "",
            "## Coverage and limitations",
            "",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in report.coverage.limitations)
    lines.extend(
        [
            "",
            "## Evidence",
            "",
            *(f"- `{evidence_id}`" for evidence_id in report.evidence_ids),
            "",
        ]
    )
    return "\n".join(lines)
