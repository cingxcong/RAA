"""Decode and interpret AndroidManifest.xml."""

from __future__ import annotations

from pathlib import Path

from raa.domain.manifest import (
    ApplicationInfo,
    ComponentInfo,
    ComponentKind,
    DeclaredPermission,
    DeepLinkInfo,
    ExportedSource,
    IntentDataInfo,
    IntentFilterInfo,
    ManifestInfo,
    RequestedPermission,
    UsesFeature,
)
from raa.domain.models import Finding
from raa.errors import InvalidArtifactError, UnsupportedError
from raa.services.android.axml import XmlElement, parse_binary_xml
from raa.services.inspection import read_archive_member

MANIFEST_MEMBER = "AndroidManifest.xml"
_VIEW_ACTION = "android.intent.action.VIEW"
_BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"
_MAIN_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
_COMPONENT_KINDS: dict[str, ComponentKind] = {
    "activity": "activity",
    "activity-alias": "activity_alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def read_manifest(path: Path, artifact_type: str, *, max_bytes: int) -> bytes:
    """Read the binary manifest from an APK-family artifact."""

    if artifact_type == "apk":
        return read_archive_member(path, MANIFEST_MEMBER, max_bytes=max_bytes)
    if artifact_type == "aab":
        raise UnsupportedError(
            "AAB manifests use protobuf encoding, not Android binary XML.",
            hint="Analyze a derived base APK, or wait for the AAB protobuf decoder.",
        )
    if artifact_type in {"apks", "xapk"}:
        raise UnsupportedError(
            "Split packages keep manifests inside nested APKs.",
            hint="Ingest the base APK, or wait for nested split manifest merging.",
        )
    raise UnsupportedError(f"Manifest decoding is not implemented for {artifact_type} containers.")


def decode_manifest(path: Path, artifact_type: str, *, max_bytes: int) -> ManifestInfo:
    return parse_manifest(read_manifest(path, artifact_type, max_bytes=max_bytes))


def parse_manifest(data: bytes) -> ManifestInfo:
    """Parse an AndroidManifest.xml binary document into typed metadata."""

    document = parse_binary_xml(data)
    root = document.root
    if root.name != "manifest":
        raise InvalidArtifactError(
            "AndroidManifest.xml does not start with a manifest element.",
            details={"root": root.name},
        )

    uses_sdk = root.find("uses-sdk")
    application = root.find("application")
    target_sdk = _int(uses_sdk, "targetSdkVersion")
    min_sdk = _int(uses_sdk, "minSdkVersion")
    max_sdk = _int(uses_sdk, "maxSdkVersion")

    manifest = ManifestInfo(
        package=_string(root, "package"),
        version_code=_int(root, "versionCode"),
        version_name=_string(root, "versionName"),
        compile_sdk=_int(root, "compileSdkVersion"),
        compile_sdk_codename=_string(root, "compileSdkVersionCodename"),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        max_sdk=max_sdk,
        requested_permissions=_requested_permissions(root),
        declared_permissions=_declared_permissions(root),
        features=_features(root),
        application=_application_info(application, target_sdk),
        components=_components(application, target_sdk),
    )
    manifest.deep_links = _deep_links(manifest.components)
    manifest.limitations = _limitations(manifest)
    return manifest


def manifest_findings(manifest: ManifestInfo) -> list[Finding]:
    """Derive findings from decoded manifest facts without overstating impact."""

    findings: list[Finding] = []
    application = manifest.application
    if application.debuggable:
        findings.append(
            Finding(
                id="finding_manifest_debuggable",
                severity="high",
                category="manifest",
                title="Application is debuggable",
                detail=(
                    "android:debuggable is true. Debug builds may expose data and "
                    "additional runtime surfaces."
                ),
            )
        )
    if application.uses_cleartext_traffic is True:
        findings.append(
            Finding(
                id="finding_manifest_cleartext_traffic",
                severity="medium",
                category="network",
                title="Cleartext traffic is explicitly enabled",
                detail=(
                    "android:usesCleartextTraffic is true. Confirm whether HTTP is "
                    "intended and whether a network security config restricts it."
                ),
            )
        )
    if application.allow_backup:
        findings.append(
            Finding(
                id="finding_manifest_allow_backup",
                severity="low",
                category="data_protection",
                title="Application backup is allowed",
                detail=(
                    "android:allowBackup is true or unset. Verify whether sensitive "
                    "application data may be included in platform backups."
                ),
            )
        )

    unprotected = [
        component
        for component in manifest.exported_components
        if not component.launcher and not component.permission_protected
    ]
    if unprotected:
        names = ", ".join(f"{component.kind}:{component.name}" for component in unprotected[:12])
        suffix = "" if len(unprotected) <= 12 else f" (+{len(unprotected) - 12} more)"
        findings.append(
            Finding(
                id="finding_exported_without_permission",
                severity="high",
                category="exported_surface",
                title="Exported components have no permission guard",
                detail=(
                    f"{len(unprotected)} non-launcher exported component(s) declare no "
                    f"permission: {names}{suffix}. Confirm which are intentionally public."
                ),
            )
        )

    if manifest.target_sdk is not None and manifest.target_sdk >= 31:
        missing_exported = [
            component
            for component in manifest.components
            if component.exported is None and component.intent_filters
        ]
        if missing_exported:
            names = ", ".join(component.name for component in missing_exported[:12])
            findings.append(
                Finding(
                    id="finding_manifest_missing_exported",
                    severity="info",
                    category="manifest",
                    title="Components with intent filters omit android:exported",
                    detail=(
                        "Target SDK 31+ requires an explicit android:exported value when "
                        f"a component has intent filters: {names}."
                    ),
                )
            )
    return findings


def _requested_permissions(root: XmlElement) -> list[RequestedPermission]:
    permissions: list[RequestedPermission] = []
    seen: set[tuple[str, int | None]] = set()
    for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
        for element in root.findall(tag):
            name = _string(element, "name")
            if not name:
                continue
            max_sdk = _int(element, "maxSdkVersion")
            key = (name, max_sdk)
            if key in seen:
                continue
            seen.add(key)
            permissions.append(
                RequestedPermission(
                    name=name,
                    max_sdk_version=max_sdk,
                    flags=_string(element, "usesPermissionFlags"),
                )
            )
    return permissions


def _declared_permissions(root: XmlElement) -> list[DeclaredPermission]:
    permissions: list[DeclaredPermission] = []
    seen: set[str] = set()
    for element in root.findall("permission"):
        name = _string(element, "name")
        if not name or name in seen:
            continue
        seen.add(name)
        permissions.append(
            DeclaredPermission(
                name=name,
                protection_level=_protection_level(element),
                label=_string(element, "label"),
                description=_string(element, "description"),
            )
        )
    return permissions


def _features(root: XmlElement) -> list[UsesFeature]:
    features: list[UsesFeature] = []
    seen: set[str] = set()
    for element in root.findall("uses-feature"):
        name = _string(element, "name")
        if not name or name in seen:
            continue
        seen.add(name)
        required = _bool(element, "required")
        features.append(UsesFeature(name=name, required=True if required is None else required))
    return features


def _application_info(application: XmlElement | None, target_sdk: int | None) -> ApplicationInfo:
    if application is None:
        return ApplicationInfo(
            effective_cleartext_traffic=None if target_sdk is None else target_sdk < 28,
        )
    cleartext = _bool(application, "usesCleartextTraffic")
    effective_cleartext = cleartext
    if effective_cleartext is None and target_sdk is not None:
        effective_cleartext = target_sdk < 28
    allow_backup = _bool(application, "allowBackup")
    return ApplicationInfo(
        name=_string(application, "name"),
        label=_string(application, "label"),
        icon=_string(application, "icon"),
        theme=_string(application, "theme"),
        debuggable=_bool(application, "debuggable") or False,
        allow_backup=True if allow_backup is None else allow_backup,
        test_only=_bool(application, "testOnly") or False,
        uses_cleartext_traffic=cleartext,
        effective_cleartext_traffic=effective_cleartext,
        network_security_config=_string(application, "networkSecurityConfig"),
        extract_native_libs=_bool(application, "extractNativeLibs"),
        request_legacy_external_storage=_bool(application, "requestLegacyExternalStorage"),
        backup_agent=_string(application, "backupAgent"),
        full_backup_content=_string(application, "fullBackupContent"),
        data_extraction_rules=_string(application, "dataExtractionRules"),
    )


def _components(application: XmlElement | None, target_sdk: int | None) -> list[ComponentInfo]:
    if application is None:
        return []
    components: list[ComponentInfo] = []
    for element in application.children:
        kind = _COMPONENT_KINDS.get(element.name)
        if kind is None:
            continue
        name = _string(element, "name")
        if not name:
            continue
        filters = [_intent_filter(child) for child in element.findall("intent-filter")]
        exported = _bool(element, "exported")
        if exported is not None:
            effective_exported = exported
            exported_source: ExportedSource = "explicit"
        elif filters and (target_sdk is None or target_sdk < 31):
            effective_exported = True
            exported_source = "intent_filter_legacy"
        else:
            effective_exported = False
            exported_source = "default_false"
        enabled = _bool(element, "enabled")
        permission = _string(element, "permission")
        read_permission = _string(element, "readPermission")
        write_permission = _string(element, "writePermission")
        components.append(
            ComponentInfo(
                kind=kind,
                name=name,
                target_activity=_string(element, "targetActivity"),
                exported=exported,
                effective_exported=effective_exported,
                exported_source=exported_source,
                enabled=True if enabled is None else enabled,
                permission=permission,
                read_permission=read_permission,
                write_permission=write_permission,
                permission_protected=bool(permission)
                or (kind == "provider" and bool(read_permission or write_permission)),
                authorities=_string(element, "authorities"),
                grant_uri_permissions=_bool(element, "grantUriPermissions") or False,
                launcher=any(_is_launcher(intent_filter) for intent_filter in filters),
                intent_filters=filters,
            )
        )
    return components


def _intent_filter(element: XmlElement) -> IntentFilterInfo:
    actions = [
        name
        for action in element.findall("action")
        if (name := _string(action, "name")) is not None
    ]
    categories = [
        name
        for category in element.findall("category")
        if (name := _string(category, "name")) is not None
    ]
    data = [_intent_data(item) for item in element.findall("data")]
    return IntentFilterInfo(
        actions=actions,
        categories=categories,
        data=data,
        priority=_int(element, "priority"),
        auto_verify=_bool(element, "autoVerify") or False,
    )


def _intent_data(element: XmlElement) -> IntentDataInfo:
    return IntentDataInfo(
        scheme=_string(element, "scheme"),
        host=_string(element, "host"),
        port=_string(element, "port"),
        path=_string(element, "path"),
        path_prefix=_string(element, "pathPrefix"),
        path_pattern=_string(element, "pathPattern"),
        mime_type=_string(element, "mimeType"),
    )


def _is_launcher(intent_filter: IntentFilterInfo) -> bool:
    return _MAIN_ACTION in intent_filter.actions and _LAUNCHER_CATEGORY in intent_filter.categories


def _deep_links(components: list[ComponentInfo]) -> list[DeepLinkInfo]:
    links: list[DeepLinkInfo] = []
    for component in components:
        for intent_filter in component.intent_filters:
            if _VIEW_ACTION not in intent_filter.actions:
                continue
            if _BROWSABLE_CATEGORY not in intent_filter.categories:
                continue
            for data in intent_filter.data:
                if not data.scheme:
                    continue
                links.append(
                    DeepLinkInfo(
                        component=component.name,
                        component_kind=component.kind,
                        scheme=data.scheme,
                        host=data.host,
                        port=data.port,
                        path=data.path,
                        path_prefix=data.path_prefix,
                        path_pattern=data.path_pattern,
                        auto_verify=intent_filter.auto_verify,
                    )
                )
    return links


def _limitations(manifest: ManifestInfo) -> list[str]:
    limitations = [
        (
            "Manifest values are decoded from the shipped binary XML; resource "
            "references are not resolved in this build."
        ),
        (
            "Exported flags and intent filters describe declarations, not runtime "
            "reachability or actual access control."
        ),
        'Exported counts exclude components declared with android:enabled="false".',
        "Only the outer APK manifest is decoded; split manifests are not merged.",
    ]
    if manifest.target_sdk is None:
        limitations.append(
            "targetSdkVersion is missing; legacy exported defaults may be inaccurate."
        )
    if manifest.application.network_security_config:
        limitations.append(
            "Network security config XML is not decoded; trust anchors and certificate "
            "pinning are unknown."
        )
    if manifest.min_sdk is not None and manifest.min_sdk < 17:
        limitations.append(
            "minSdkVersion is below 17; legacy content-provider export defaults are not modelled."
        )
    return limitations


def _protection_level(element: XmlElement) -> str | int | None:
    attribute = element.attribute("protectionLevel")
    if attribute is None:
        return None
    value = attribute.value
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return value
    return None


def _string(element: XmlElement | None, name: str) -> str | None:
    if element is None:
        return None
    attribute = element.attribute(name)
    if attribute is None or attribute.value is None:
        return None
    value = attribute.value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _int(element: XmlElement | None, name: str) -> int | None:
    if element is None:
        return None
    attribute = element.attribute(name)
    if attribute is None or attribute.value is None:
        return None
    value = attribute.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _bool(element: XmlElement | None, name: str) -> bool | None:
    if element is None:
        return None
    attribute = element.attribute(name)
    if attribute is None or attribute.value is None:
        return None
    value = attribute.value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1"}:
            return True
        if lowered in {"false", "0"}:
            return False
    return None
