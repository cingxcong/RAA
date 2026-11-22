"""Typed DEX index models.

The index is intentionally metadata-only: it describes classes, fields and
methods declared by shipped DEX files without disassembling method bodies.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ReferenceKind = Literal[
    "method_call",
    "field_access",
    "type_reference",
    "string_reference",
]


class DexMemberInfo(BaseModel):
    """One field or method declared by a class."""

    name: str
    descriptor: str
    access_flags: int
    access: list[str] = Field(default_factory=list)
    static: bool = False
    has_code: bool = False


class DexClassInfo(BaseModel):
    """Class metadata without member lists."""

    name: str
    descriptor: str
    access_flags: int
    access: list[str] = Field(default_factory=list)
    superclass: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    source_file: str | None = None
    dex_file: str
    field_count: int = 0
    method_count: int = 0


class DexClassDetail(DexClassInfo):
    """Class metadata with bounded member lists."""

    fields: list[DexMemberInfo] = Field(default_factory=list)
    methods: list[DexMemberInfo] = Field(default_factory=list)
    field_total: int = 0
    method_total: int = 0
    truncated: bool = False


class DexReferenceInfo(BaseModel):
    """One bytecode reference from a declared method."""

    kind: ReferenceKind
    from_class: str
    from_method: str
    from_descriptor: str
    target: str
    target_class: str | None = None
    target_name: str | None = None
    target_descriptor: str | None = None
    value: str | None = None
    opcode: int
    offset: int
    dex_file: str


class DexFileSummary(BaseModel):
    """Per-file DEX metadata and index counts."""

    name: str
    size_bytes: int
    version: str | None = None
    checksum: str | None = None
    checksum_valid: bool | None = None
    signature_valid: bool | None = None
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    string_count: int = 0
    error: str | None = None


class DexSummary(BaseModel):
    """Aggregate DEX index information stored on an analysis report."""

    file_count: int = 0
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    string_count: int = 0
    multi_dex: bool = False
    files: list[DexFileSummary] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
