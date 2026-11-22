"""Domain models for framework detection, capabilities, and framework-specific artifacts."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FrameworkCapability(BaseModel):
    """Capabilities, supported operations, and limits for a detected framework."""

    id: str
    name: str
    category: str
    supported_operations: list[str] = Field(default_factory=list)
    recovery_modes: list[str] = Field(default_factory=list)
    supported_engines: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    notes: str | None = None


class FlutterAssetInfo(BaseModel):
    """Metadata for an asset bundled inside assets/flutter_assets/."""

    path: str
    size_bytes: int
    asset_type: str
    is_manifest: bool = False


class FlutterAssetsSummary(BaseModel):
    """Summary of assets declared in a Flutter application."""

    assets: list[FlutterAssetInfo] = Field(default_factory=list)
    total_count: int = 0
    font_families: list[str] = Field(default_factory=list)
    has_asset_manifest: bool = False
    has_font_manifest: bool = False
    manifest_entries: list[str] = Field(default_factory=list)


class FlutterSymbolsSummary(BaseModel):
    """Dart and Flutter symbols recovered from native libraries."""

    engine_version: str | None = None
    snapshot_type: str | None = None
    build_id: str | None = None
    symbols: list[str] = Field(default_factory=list)
    total_count: int = 0
    recovery_mode: str = "headers_and_strings"
    limitations: list[str] = Field(default_factory=list)


class ReactNativeBundleInfo(BaseModel):
    """Inspection result for a React Native JavaScript or Hermes bundle."""

    bundle_path: str
    size_bytes: int
    is_hermes: bool
    hermes_version: int | None = None
    minified: bool = True
    has_source_map: bool = False
    sample_text: str | None = None
    notes: list[str] = Field(default_factory=list)


class ReactNativeModulesSummary(BaseModel):
    """Native modules, TurboModules, and bridge packages identified in React Native."""

    components: list[str] = Field(default_factory=list)
    turbo_modules: list[str] = Field(default_factory=list)
    react_packages: list[str] = Field(default_factory=list)
    bridge_modules: list[str] = Field(default_factory=list)
    total_count: int = 0


class UnityMetadataSummary(BaseModel):
    """Metadata recovered from Unity's global-metadata.dat and libil2cpp."""

    format_version: int | None = None
    is_valid: bool = False
    string_literal_count: int = 0
    type_definitions_count: int = 0
    method_definitions_count: int = 0
    definitions_count: int = 0
    notes: list[str] = Field(default_factory=list)


class UnityAssetsSummary(BaseModel):
    """Inventory of Unity engine assets and scene data."""

    data_files: list[str] = Field(default_factory=list)
    streaming_assets: list[str] = Field(default_factory=list)
    has_global_metadata: bool = False
    total_count: int = 0


class DotnetAssembly(BaseModel):
    """Information about a managed .NET assembly found in the package."""

    name: str
    size_bytes: int
    is_pe: bool = False
    is_cil: bool = False
    version: str | None = None


class DotnetAssembliesSummary(BaseModel):
    """Inventory of managed assemblies in Xamarin or .NET MAUI applications."""

    assemblies: list[DotnetAssembly] = Field(default_factory=list)
    total_count: int = 0
    runtime: str = "xamarin"
    notes: list[str] = Field(default_factory=list)


class DotnetTypeDetail(BaseModel):
    """Type detail extracted from managed assemblies."""

    type_name: str
    assembly_name: str
    methods: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    source: str = "metadata"
    decompiled_csharp: str | None = None
