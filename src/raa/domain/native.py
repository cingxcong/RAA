"""Domain models for native ELF binaries and JNI method mapping."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ElfHeaderInfo(BaseModel):
    """ELF header metadata for native shared libraries."""

    path: str
    abi: str
    bitness: int
    endianness: str
    machine: str
    entry_point: int
    is_shared_library: bool
    sections: list[str] = Field(default_factory=list)


class NativeSymbol(BaseModel):
    """An individual symbol exported or imported by a native shared library."""

    name: str
    symbol_type: str
    binding: str
    is_exported: bool = False
    is_jni: bool = False
    demangled_jni: str | None = None
    address: int | None = None


class NativeSymbolsSummary(BaseModel):
    """Summary of dynamic symbols extracted from a native shared library."""

    library: str
    abi: str
    exported_symbols: list[NativeSymbol] = Field(default_factory=list)
    imported_symbols: list[NativeSymbol] = Field(default_factory=list)
    jni_symbols: list[NativeSymbol] = Field(default_factory=list)
    total_count: int = 0
    has_jni_on_load: bool = False


class JniBinding(BaseModel):
    """Correlation between a declared Java native method and a native symbol."""

    java_class: str
    java_method: str
    descriptor: str
    native_symbol: str | None = None
    library: str | None = None
    status: Literal["bound", "dynamic", "unresolved"]
    notes: str | None = None


class JniMappingReport(BaseModel):
    """Report mapping all DEX native method declarations to native libraries."""

    bindings: list[JniBinding] = Field(default_factory=list)
    total_native_methods: int = 0
    bound_count: int = 0
    dynamic_count: int = 0
    unresolved_count: int = 0
    libraries_searched: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
