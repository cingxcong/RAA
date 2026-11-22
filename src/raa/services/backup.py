"""Enterprise backup, restore, and data retention service."""

from __future__ import annotations

import hashlib
import json
import tarfile
import time
from pathlib import Path
from typing import Any

from raa.errors import NotFoundError, RAAError
from raa.services.artifacts import ArtifactService
from raa.services.projects import ProjectService
from raa.services.workspace import Workspace
from raa.storage.database import Database
from raa.utils.time import utc_now


class BackupService:
    """Handles project backup archive creation, restoration, and retention policy enforcement."""

    def __init__(
        self,
        workspace: Workspace,
        database: Database,
        projects: ProjectService,
        artifacts: ArtifactService,
    ) -> None:
        self.workspace = workspace
        self.database = database
        self.projects = projects
        self.artifacts = artifacts
        self.backup_dir = workspace.root / "backups"

    def create_backup(
        self,
        project_id: str,
        output_path: Path | None = None,
    ) -> dict[str, Any]:
        """Create a compressed .tar.gz backup bundle containing project records and artifacts."""
        project = self.projects.get_or_raise(project_id)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        target_file = (
            output_path
            or self.backup_dir / f"backup_{project.id}_{int(time.time())}.raa.bundle.tar.gz"
        )
        target_file.parent.mkdir(parents=True, exist_ok=True)

        project_artifacts = self.artifacts.list(project_id=project.id, limit=500)

        # Build bundle metadata
        manifest: dict[str, Any] = {
            "version": "1.0",
            "format": "raa.bundle.v1",
            "created_at": utc_now().isoformat(),
            "project": {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "scopes": sorted(project.scopes),
                "created_at": project.created_at.isoformat(),
                "updated_at": project.updated_at.isoformat(),
            },
            "artifact_count": len(project_artifacts),
            "files": {},
        }

        # Create tar archive
        with tarfile.open(target_file, "w:gz") as tar:
            for art in project_artifacts:
                art_path = self.workspace.root / art.stored_path
                if art_path.is_file():
                    tar.add(art_path, arcname=f"artifacts/{art.id}_{art.filename}")
                    manifest["files"][art.id] = {
                        "filename": art.filename,
                        "sha256": art.sha256,
                        "size_bytes": art.size_bytes,
                        "artifact_type": art.artifact_type,
                        "arcname": f"artifacts/{art.id}_{art.filename}",
                    }

            # Write manifest into archive
            manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
            tarinfo = tarfile.TarInfo(name="manifest.json")
            tarinfo.size = len(manifest_bytes)
            tarinfo.mtime = int(time.time())
            from io import BytesIO

            tar.addfile(tarinfo, BytesIO(manifest_bytes))

        bundle_bytes = target_file.read_bytes()
        bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()

        return {
            "project_id": project.id,
            "backup_file": str(target_file),
            "size_bytes": len(bundle_bytes),
            "sha256": bundle_hash,
            "artifact_count": len(project_artifacts),
            "created_at": manifest["created_at"],
        }

    def restore_backup(
        self,
        bundle_path: Path,
        new_name: str | None = None,
    ) -> dict[str, Any]:
        """Validate and restore a project from a backup bundle."""
        if not bundle_path.is_file():
            raise NotFoundError(
                f"Backup bundle not found: {bundle_path}",
                hint="Provide a valid path to an existing .raa.bundle.tar.gz file.",
            )

        with tarfile.open(bundle_path, "r:gz") as tar:
            try:
                manifest_member = tar.getmember("manifest.json")
                f = tar.extractfile(manifest_member)
                if not f:
                    raise ValueError("Empty manifest.json")
                manifest = json.loads(f.read().decode("utf-8"))
            except Exception as exc:
                raise RAAError(
                    "Invalid or corrupt backup bundle: manifest.json is missing or unreadable.",
                    code="corrupt_backup",
                ) from exc

            # Verify bundle format
            if manifest.get("format") != "raa.bundle.v1":
                raise RAAError(
                    f"Unsupported backup format: {manifest.get('format')}",
                    code="unsupported_backup_format",
                )

            # Create restored project
            project_data = manifest["project"]
            target_name = new_name or f"{project_data['name']} (Restored)"

            new_project = self.projects.create(
                name=target_name,
                description=project_data.get("description", ""),
                scopes=project_data.get("scopes", []),
            )

            restored_artifacts = 0
            for art_id, file_meta in manifest.get("files", {}).items():
                arcname = file_meta.get("arcname", f"artifacts/{art_id}_{file_meta['filename']}")
                try:
                    member = tar.getmember(arcname)
                    extracted = tar.extractfile(member)
                    if not extracted:
                        continue
                    content = extracted.read()

                    # Ingest artifact into restored project
                    temp_art = self.workspace.tmp_dir / f"restore_{art_id}_{file_meta['filename']}"
                    temp_art.parent.mkdir(parents=True, exist_ok=True)
                    temp_art.write_bytes(content)
                    self.artifacts.ingest_path(
                        project_id=new_project.id,
                        raw_path=str(temp_art),
                    )
                    restored_artifacts += 1
                except KeyError:
                    continue

        return {
            "restored_project_id": new_project.id,
            "name": new_project.name,
            "original_project_id": project_data["id"],
            "artifacts_restored": restored_artifacts,
            "status": "restored",
        }

    def purge_retention(self, retention_days: int = 30) -> dict[str, Any]:
        """Prune expired backup files and temporary caches older than retention threshold."""
        cutoff_seconds = time.time() - (retention_days * 86400)
        purged_files = 0
        reclaimed_bytes = 0

        # Prune backup files older than cutoff
        if self.backup_dir.is_dir():
            for item in self.backup_dir.glob("*.raa.bundle.tar.gz"):
                try:
                    stats = item.stat()
                    if stats.st_mtime < cutoff_seconds:
                        size = stats.st_size
                        item.unlink()
                        purged_files += 1
                        reclaimed_bytes += size
                except OSError:
                    continue

        return {
            "retention_days": retention_days,
            "purged_files": purged_files,
            "reclaimed_bytes": reclaimed_bytes,
            "reclaimed_mb": round(reclaimed_bytes / (1024 * 1024), 2),
            "status": "retention_policy_enforced",
        }
