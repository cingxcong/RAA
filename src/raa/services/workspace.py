"""Workspace layout and safe path handling."""

from __future__ import annotations

import re
from pathlib import Path

from raa.errors import InvalidArgumentsError, NotFoundError, PolicyDeniedError

_UNSAFE_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class Workspace:
    """Owns every path RAA writes to."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    @property
    def tmp_dir(self) -> Path:
        return self.root / "tmp"

    @property
    def audit_dir(self) -> Path:
        return self.root / "audit"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    def ensure(self) -> None:
        for directory in (
            self.root,
            self.artifacts_dir,
            self.exports_dir,
            self.tmp_dir,
            self.audit_dir,
            self.logs_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def artifact_dir(self, project_id: str, artifact_id: str) -> Path:
        directory = self.artifacts_dir / project_id / artifact_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def export_path(self, project_id: str, filename: str) -> Path:
        directory = self.exports_dir / project_id
        directory.mkdir(parents=True, exist_ok=True)
        candidate = (directory / sanitize_filename(filename)).resolve()
        self.ensure_within(candidate, self.exports_dir)
        return candidate

    def stored_path(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        self.ensure_within(candidate, self.root)
        if not candidate.is_file():
            raise NotFoundError(
                "Artifact data is missing from the workspace.",
                hint="Re-ingest the artifact or restore the workspace.",
                details={"path": relative},
            )
        return candidate

    def relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def ensure_within(self, path: Path, root: Path) -> None:
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError as exc:
            raise PolicyDeniedError(
                "Path escapes the allowed workspace root.",
                details={"path": str(path), "root": str(root)},
            ) from exc

    def is_within(self, path: Path, root: Path | None = None) -> bool:
        base = (root or self.root).resolve()
        try:
            path.resolve().relative_to(base)
            return True
        except ValueError:
            return False

    def check_input_path(self, raw_path: str, roots: list[Path]) -> Path:
        candidate = Path(raw_path).expanduser()
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise InvalidArgumentsError(
                f"Input file does not exist: {raw_path}",
                hint="Pass an absolute or workspace-relative path to an APK/AAB/APKS/XAPK file.",
            ) from exc
        if not resolved.is_file():
            raise InvalidArgumentsError(
                f"Input path is not a file: {raw_path}",
                hint="Directories are not accepted by artifact_ingest.",
            )
        for root in roots:
            try:
                resolved.relative_to(root.expanduser().resolve())
                return resolved
            except ValueError:
                continue
        raise PolicyDeniedError(
            "Input path is outside the allowed input roots.",
            hint=(
                "Add the directory to RAA_ALLOWED_INPUT_ROOTS or copy the file into the workspace."
            ),
            details={"path": str(resolved), "roots": [str(root) for root in roots]},
        )


def sanitize_filename(name: str) -> str:
    """Return a single safe path component."""

    clean_name = name.replace("\\", "/")
    candidate = Path(clean_name).name.strip()
    candidate = _UNSAFE_FILENAME.sub("_", candidate)
    candidate = candidate.strip(" .")
    if not candidate:
        candidate = "artifact.bin"
    stem = candidate.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        candidate = f"_{candidate}"
    return candidate[:180]
