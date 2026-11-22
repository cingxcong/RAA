"""Domain models for artifact diffing, noise filtering, and semantic change analysis."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from raa.utils.time import utc_now


class ChangeCategory(StrEnum):
    """Category of artifact change."""

    MANIFEST = "manifest"
    CODE = "code"
    RESOURCE = "resource"
    NATIVE = "native"
    API = "api"
    UI = "ui"
    FILE = "file"


class ChangeType(StrEnum):
    """Kind of structural change."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"


class DiffChangeItem(BaseModel):
    """A granular change entry between two artifact versions."""

    change_id: str
    category: ChangeCategory
    change_type: ChangeType
    path: str
    old_value: str | None = None
    new_value: str | None = None
    is_semantic: bool = True
    noise_reason: str | None = None
    diff_unified: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


class DiffReport(BaseModel):
    """Overall comparison report between base and target artifacts."""

    diff_id: str
    project_id: str
    base_artifact_id: str
    target_artifact_id: str
    total_changes: int = 0
    semantic_changes_count: int = 0
    noise_changes_count: int = 0
    changes_by_category: dict[str, int] = Field(default_factory=dict)
    changes: list[DiffChangeItem] = Field(default_factory=list)
    compared_at: datetime = Field(default_factory=utc_now)
