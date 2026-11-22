"""Typed results from the Android manifest decoder."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ComponentKind = Literal["activity", "activity_alias", "service", "receiver", "provider"]
ExportedSource = Literal["explicit", "intent_filter_legacy", "default_false"]


class IntentDataInfo(BaseModel):
    scheme: str | None = None
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
    mime_type: str | None = None


class IntentFilterInfo(BaseModel):
    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    data: list[IntentDataInfo] = Field(default_factory=list)
    priority: int | None = None
    auto_verify: bool = False


class ComponentInfo(BaseModel):
    kind: ComponentKind
    name: str
    target_activity: str | None = None
    exported: bool | None = None
    effective_exported: bool = False
    exported_source: ExportedSource = "default_false"
    enabled: bool = True
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    permission_protected: bool = False
    authorities: str | None = None
    grant_uri_permissions: bool = False
    launcher: bool = False
    intent_filters: list[IntentFilterInfo] = Field(default_factory=list)


class RequestedPermission(BaseModel):
    name: str
    max_sdk_version: int | None = None
    flags: str | None = None


class DeclaredPermission(BaseModel):
    name: str
    protection_level: str | int | None = None
    label: str | None = None
    description: str | None = None


class UsesFeature(BaseModel):
    name: str
    required: bool = True


class ApplicationInfo(BaseModel):
    name: str | None = None
    label: str | None = None
    icon: str | None = None
    theme: str | None = None
    debuggable: bool = False
    allow_backup: bool = True
    test_only: bool = False
    uses_cleartext_traffic: bool | None = None
    effective_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    extract_native_libs: bool | None = None
    request_legacy_external_storage: bool | None = None
    backup_agent: str | None = None
    full_backup_content: str | None = None
    data_extraction_rules: str | None = None


class DeepLinkInfo(BaseModel):
    component: str
    component_kind: ComponentKind
    scheme: str
    host: str | None = None
    port: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
    auto_verify: bool = False


class ManifestInfo(BaseModel):
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    compile_sdk: int | None = None
    compile_sdk_codename: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    max_sdk: int | None = None
    requested_permissions: list[RequestedPermission] = Field(default_factory=list)
    declared_permissions: list[DeclaredPermission] = Field(default_factory=list)
    features: list[UsesFeature] = Field(default_factory=list)
    application: ApplicationInfo = Field(default_factory=ApplicationInfo)
    components: list[ComponentInfo] = Field(default_factory=list)
    deep_links: list[DeepLinkInfo] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def exported_components(self) -> list[ComponentInfo]:
        """Enabled components that the platform treats as exported."""

        return [
            component
            for component in self.components
            if component.effective_exported and component.enabled
        ]
