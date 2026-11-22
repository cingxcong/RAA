"""Typed Android resource-table results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ResourceValueInfo(BaseModel):
    """Decoded ``Res_value``."""

    type: str
    data: int
    value: str | int | float | bool | None = None


class ResourceMapInfo(BaseModel):
    """One entry in a complex resource such as a style or array."""

    name: str
    value: ResourceValueInfo


class ResourceVariantInfo(BaseModel):
    """One configuration-specific value of a resource."""

    resource_id: str
    package: str
    type: str
    name: str
    entry_index: int
    config: str
    is_default: bool
    complex: bool
    value: ResourceValueInfo | None = None
    parent: str | None = None
    map_count: int = 0
    maps: list[ResourceMapInfo] = Field(default_factory=list)
    maps_truncated: bool = False
    file_reference: str | None = None


class ResourceTypeSummary(BaseModel):
    type: str
    entry_count: int
    value_count: int
    default_count: int
    config_count: int


class ResourceSummary(BaseModel):
    packages: list[str] = Field(default_factory=list)
    entry_count: int = 0
    value_count: int = 0
    config_count: int = 0
    types: list[ResourceTypeSummary] = Field(default_factory=list)
    skipped_compact_entries: int = 0
    skipped_unsupported_chunks: int = 0
    limitations: list[str] = Field(default_factory=list)
