"""Semantic diff engine comparing APK artifacts with tool noise normalization."""

from __future__ import annotations

import difflib
import hashlib
import re
import uuid
import zipfile
from pathlib import Path

from raa.domain.diff import ChangeCategory, ChangeType, DiffChangeItem, DiffReport

_SYNTHETIC_LAMBDA_PATTERN = re.compile(
    r"\$\$(?:ExternalSyntheticLambda|Lambda|InternalSynthetic)\d+|\$\$Lambda\$"
)
_RESOURCE_ID_LINE = re.compile(r"0x7f[0-9a-fA-F]{6}")


def _classify_noise(
    category: ChangeCategory,
    path: str,
    old_bytes: bytes | None = None,
    new_bytes: bytes | None = None,
) -> tuple[bool, str | None]:
    """Check if a change represents tool/compiler noise rather than a semantic change."""
    if _SYNTHETIC_LAMBDA_PATTERN.search(path):
        return (
            False,
            "Compiler synthetic lambda counter change; no semantic bytecode shift.",
        )

    if category == ChangeCategory.CODE and old_bytes and new_bytes:
        # Check if difference is solely synthetic lambda name shift
        old_str = old_bytes.decode("latin1", errors="replace")
        new_str = new_bytes.decode("latin1", errors="replace")
        clean_old = _SYNTHETIC_LAMBDA_PATTERN.sub("$$SyntheticLambda", old_str)
        clean_new = _SYNTHETIC_LAMBDA_PATTERN.sub("$$SyntheticLambda", new_str)
        if clean_old == clean_new:
            return (
                False,
                "Compiler synthetic lambda counter change; no semantic bytecode shift.",
            )

    if category == ChangeCategory.RESOURCE and old_bytes and new_bytes:
        # Check if difference is solely a renumbered hex resource ID
        old_text = old_bytes.decode("utf-8", errors="replace")
        new_text = new_bytes.decode("utf-8", errors="replace")
        clean_old = _RESOURCE_ID_LINE.sub("0x7f000000", old_text)
        clean_new = _RESOURCE_ID_LINE.sub("0x7f000000", new_text)
        if clean_old == clean_new:
            return (
                False,
                "Resource table renumbering; resource name and configuration unchanged.",
            )

    if path.endswith(".version") or "META-INF/" in path:
        return (
            False,
            "Build metadata or signature block change without application bytecode effect.",
        )

    return True, None


def compare_apks(
    base_apk: Path,
    target_apk: Path,
    *,
    base_artifact_id: str,
    target_artifact_id: str,
    project_id: str,
    categories: list[str] | None = None,
) -> DiffReport:
    """Compare two APK artifacts and yield categorized, noise-filtered changes."""
    diff_id = f"diff_{uuid.uuid4().hex[:12]}"
    changes: list[DiffChangeItem] = []
    category_filter = {ChangeCategory(c) for c in categories} if categories else None

    # Inspect zip entries
    base_entries: dict[str, bytes] = {}
    target_entries: dict[str, bytes] = {}

    if base_apk.is_file():
        with zipfile.ZipFile(base_apk, "r") as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    base_entries[info.filename] = zf.read(info.filename)

    if target_apk.is_file():
        with zipfile.ZipFile(target_apk, "r") as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    target_entries[info.filename] = zf.read(info.filename)

    all_paths = sorted(set(base_entries.keys()) | set(target_entries.keys()))

    for path in all_paths:
        cat = ChangeCategory.FILE
        if path == "AndroidManifest.xml":
            cat = ChangeCategory.MANIFEST
        elif path.endswith(".dex"):
            cat = ChangeCategory.CODE
        elif path.startswith("res/") or path.startswith("assets/") or path == "resources.arsc":
            cat = ChangeCategory.RESOURCE
        elif path.startswith("lib/"):
            cat = ChangeCategory.NATIVE

        if category_filter and cat not in category_filter:
            continue

        in_base = path in base_entries
        in_target = path in target_entries

        if in_base and not in_target:
            ch_type = ChangeType.REMOVED
            old_hash = hashlib.sha256(base_entries[path]).hexdigest()
            is_sem, noise = _classify_noise(cat, path, old_bytes=base_entries[path], new_bytes=None)
            changes.append(
                DiffChangeItem(
                    change_id=f"ch_{uuid.uuid4().hex[:10]}",
                    category=cat,
                    change_type=ch_type,
                    path=path,
                    old_value=old_hash,
                    new_value=None,
                    is_semantic=is_sem,
                    noise_reason=noise,
                    details={"size_bytes_removed": len(base_entries[path])},
                )
            )
        elif not in_base and in_target:
            ch_type = ChangeType.ADDED
            new_hash = hashlib.sha256(target_entries[path]).hexdigest()
            is_sem, noise = _classify_noise(
                cat, path, old_bytes=None, new_bytes=target_entries[path]
            )
            changes.append(
                DiffChangeItem(
                    change_id=f"ch_{uuid.uuid4().hex[:10]}",
                    category=cat,
                    change_type=ch_type,
                    path=path,
                    old_value=None,
                    new_value=new_hash,
                    is_semantic=is_sem,
                    noise_reason=noise,
                    details={"size_bytes_added": len(target_entries[path])},
                )
            )
        else:
            base_bytes = base_entries[path]
            target_bytes = target_entries[path]
            if base_bytes != target_bytes:
                ch_type = ChangeType.MODIFIED
                old_hash = hashlib.sha256(base_bytes).hexdigest()
                new_hash = hashlib.sha256(target_bytes).hexdigest()
                is_sem, noise = _classify_noise(
                    cat, path, old_bytes=base_bytes, new_bytes=target_bytes
                )

                unified: str | None = None
                # Generate text diff for manifest or small text files
                if (
                    cat in (ChangeCategory.MANIFEST, ChangeCategory.RESOURCE)
                    and len(base_bytes) < 200_000
                ):
                    try:
                        base_lines = base_bytes.decode("utf-8", errors="replace").splitlines(
                            keepends=True
                        )
                        target_lines = target_bytes.decode("utf-8", errors="replace").splitlines(
                            keepends=True
                        )
                        udiff = difflib.unified_diff(
                            base_lines,
                            target_lines,
                            fromfile=f"a/{path}",
                            tofile=f"b/{path}",
                        )
                        unified = "".join(udiff)
                    except Exception:
                        unified = None

                changes.append(
                    DiffChangeItem(
                        change_id=f"ch_{uuid.uuid4().hex[:10]}",
                        category=cat,
                        change_type=ch_type,
                        path=path,
                        old_value=old_hash,
                        new_value=new_hash,
                        is_semantic=is_sem,
                        noise_reason=noise,
                        diff_unified=unified,
                        details={
                            "old_size": len(base_bytes),
                            "new_size": len(target_bytes),
                        },
                    )
                )

    counts_by_cat: dict[str, int] = {}
    semantic_count = 0
    noise_count = 0
    for ch in changes:
        counts_by_cat[ch.category.value] = counts_by_cat.get(ch.category.value, 0) + 1
        if ch.is_semantic:
            semantic_count += 1
        else:
            noise_count += 1

    return DiffReport(
        diff_id=diff_id,
        project_id=project_id,
        base_artifact_id=base_artifact_id,
        target_artifact_id=target_artifact_id,
        total_changes=len(changes),
        semantic_changes_count=semantic_count,
        noise_changes_count=noise_count,
        changes_by_category=counts_by_cat,
        changes=changes,
    )


def export_diff_report(report: DiffReport, format_type: str = "json") -> str:
    """Format and export a diff report as JSON, Markdown, or unified diff."""
    if format_type == "markdown":
        lines = [
            f"# Diff Report: {report.diff_id}",
            f"**Project**: `{report.project_id}`  ",
            f"**Base Artifact**: `{report.base_artifact_id}`  ",
            f"**Target Artifact**: `{report.target_artifact_id}`  ",
            (
                f"**Total Changes**: {report.total_changes} "
                f"(Semantic: {report.semantic_changes_count}, Noise: {report.noise_changes_count})"
            ),
            "",
            "## Summary by Category",
        ]
        for cat, cnt in report.changes_by_category.items():
            lines.append(f"- **{cat.capitalize()}**: {cnt}")
        lines.append("")
        lines.append("## Changed Items")
        for ch in report.changes:
            sem_tag = "Semantic" if ch.is_semantic else f"Noise ({ch.noise_reason})"
            lines.append(
                f"- `[{ch.category.value.upper()}]` **{ch.path}** "
                f"({ch.change_type.value}) - *{sem_tag}*"
            )
            if ch.diff_unified:
                lines.append("```diff")
                lines.append(ch.diff_unified[:2000])
                lines.append("```")
        return "\n".join(lines)

    if format_type == "unified":
        diffs = [ch.diff_unified for ch in report.changes if ch.diff_unified]
        return "\n".join(diffs) if diffs else "# No textual unified diff available."

    return report.model_dump_json(indent=2)
