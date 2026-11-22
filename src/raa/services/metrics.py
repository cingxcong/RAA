"""Enterprise system metrics, worker observability, and telemetry service."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any

from raa.services.audit import AuditService
from raa.services.engines import EngineService
from raa.services.workspace import Workspace
from raa.storage.database import Database
from raa.utils.time import utc_now
from raa.version import PROTOCOL_VERSION, __version__


class MetricsService:
    """Collects observability telemetry, storage statistics, and worker health metrics."""

    def __init__(
        self,
        workspace: Workspace,
        database: Database,
        engines: EngineService,
        audit: AuditService,
    ) -> None:
        self.workspace = workspace
        self.database = database
        self.engines = engines
        self.audit = audit

    def get_system_metrics(self) -> dict[str, Any]:
        """Collect current system metrics, database storage, and worker observability data."""
        # Database file sizes
        db_path = self.database.path
        db_size = db_path.stat().st_size if db_path.is_file() else 0
        wal_path = Path(str(db_path) + "-wal")
        wal_size = wal_path.stat().st_size if wal_path.is_file() else 0
        shm_path = Path(str(db_path) + "-shm")
        shm_size = shm_path.stat().st_size if shm_path.is_file() else 0

        # Workspace storage
        workspace_bytes = 0
        file_count = 0
        try:
            for root, _, files in os.walk(self.workspace.root):
                for f in files:
                    p = Path(root) / f
                    try:
                        workspace_bytes += p.stat().st_size
                        file_count += 1
                    except OSError:
                        pass
        except OSError:
            pass

        # Audit stats
        audit_integrity = self.audit.verify_integrity()

        # Engine summary
        engines_summary = self.engines.summary()

        return {
            "timestamp": utc_now().isoformat(),
            "raa": {
                "version": __version__,
                "protocol": PROTOCOL_VERSION,
                "platform": sys.platform,
                "python_version": sys.version.split()[0],
            },
            "runtime_health": {
                "database_ok": self.database.ping(),
                "active_threads": threading.active_count(),
            },
            "storage": {
                "workspace_root": str(self.workspace.root),
                "workspace_size_bytes": workspace_bytes,
                "workspace_size_mb": round(workspace_bytes / (1024 * 1024), 2),
                "total_files": file_count,
                "database_size_bytes": db_size,
                "database_wal_bytes": wal_size,
                "database_shm_bytes": shm_size,
            },
            "audit": {
                "records_checked": audit_integrity.get("records_checked", 0),
                "tamper_free": not audit_integrity.get("tampered", False),
                "latest_hash": audit_integrity.get("latest_hash"),
            },
            "engines": engines_summary,
        }
