"""Basic endpoint and storage discovery from manifest and DEX metadata."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from raa.domain.models import EndpointDiscovery, StorageDiscovery

if TYPE_CHECKING:
    from raa.domain.manifest import ManifestInfo
    from raa.services.android.dex import DexIndex

_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:/[-a-zA-Z0-9()@:%_+.~#?&/=]*)?",
    re.IGNORECASE,
)
_API_PATH_PATTERN = re.compile(r"^/(?:api|v[0-9]+)/[-a-zA-Z0-9_./]*", re.IGNORECASE)
_DB_PATTERN = re.compile(r"^[\w.-]+\.(?:db|sqlite|sqlite3)$", re.IGNORECASE)
_PREFS_PATTERN = re.compile(r"^[\w.-]+_(?:preferences?|prefs?)(?:\.xml)?$", re.IGNORECASE)

_IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://schemas.xmlsoap.org/",
    "https://schemas.xmlsoap.org/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://xmlpull.org/",
    "http://www.apache.org/",
    "https://www.apache.org/",
)


def discover_endpoints(
    manifest: ManifestInfo | None,
    dex_index: DexIndex | None,
) -> EndpointDiscovery:
    urls: set[str] = set()
    schemes: set[str] = set()
    deep_links: set[str] = set()
    api_paths: set[str] = set()

    if manifest is not None:
        for deep_link in manifest.deep_links:
            if deep_link.scheme:
                schemes.add(deep_link.scheme)
                full = f"{deep_link.scheme}://"
                if deep_link.host:
                    full += deep_link.host
                if deep_link.port:
                    full += f":{deep_link.port}"
                path_part = deep_link.path or deep_link.path_prefix or deep_link.path_pattern or ""
                if path_part:
                    full += path_part if path_part.startswith("/") else f"/{path_part}"
                deep_links.add(full)

    if dex_index is not None:
        all_strings: set[str] = set()
        for dex_file in dex_index.files:
            all_strings.update(dex_file.strings)

        for string_value in all_strings:
            stripped = string_value.strip()
            if not stripped:
                continue

            if _URL_PATTERN.match(stripped):
                if not any(stripped.startswith(prefix) for prefix in _IGNORED_URL_PREFIXES):
                    urls.add(stripped)
            elif _API_PATH_PATTERN.match(stripped):
                api_paths.add(stripped)

    sorted_urls = sorted(urls)
    sorted_schemes = sorted(schemes)
    sorted_deep_links = sorted(deep_links)
    sorted_api_paths = sorted(api_paths)
    total = len(sorted_urls) + len(sorted_deep_links) + len(sorted_api_paths)

    return EndpointDiscovery(
        urls=sorted_urls,
        schemes=sorted_schemes,
        deep_links=sorted_deep_links,
        api_paths=sorted_api_paths,
        total_count=total,
    )


def discover_storage(
    manifest: ManifestInfo | None,
    dex_index: DexIndex | None,
) -> StorageDiscovery:
    databases: set[str] = set()
    preferences: set[str] = set()
    technologies: set[str] = set()
    notes: list[str] = []

    if dex_index is not None:
        all_strings: set[str] = set()
        for dex_file in dex_index.files:
            all_strings.update(dex_file.strings)

        for string_value in all_strings:
            stripped = string_value.strip()
            if not stripped:
                continue

            if _DB_PATTERN.match(stripped):
                databases.add(stripped)
            elif _PREFS_PATTERN.match(stripped):
                preferences.add(stripped)

            if "RoomDatabase" in stripped or "androidx.room" in stripped:
                technologies.add("Android Room")
            if "SQLiteOpenHelper" in stripped or "android.database.sqlite" in stripped:
                technologies.add("SQLite")
            if "EncryptedSharedPreferences" in stripped:
                technologies.add("EncryptedSharedPreferences")
            elif "SharedPreferences" in stripped:
                technologies.add("SharedPreferences")
            if "SQLCipher" in stripped or "net.sqlcipher" in stripped:
                technologies.add("SQLCipher")
            if "AndroidKeyStore" in stripped or "java.security.KeyStore" in stripped:
                technologies.add("Android KeyStore")

        for klass in dex_index.classes:
            if klass.superclass in {"android.database.sqlite.SQLiteOpenHelper", "SQLiteOpenHelper"}:
                technologies.add("SQLite")
                notes.append(f"Class '{klass.name}' extends SQLiteOpenHelper.")
            elif klass.superclass in {"androidx.room.RoomDatabase", "RoomDatabase"}:
                technologies.add("Android Room")
                notes.append(f"Class '{klass.name}' extends RoomDatabase.")

    if manifest is not None and manifest.application.request_legacy_external_storage:
        technologies.add("External Storage (Legacy)")
        notes.append("requestLegacyExternalStorage is enabled in AndroidManifest.xml.")

    return StorageDiscovery(
        sqlite_databases=sorted(databases),
        shared_preferences=sorted(preferences),
        storage_technologies=sorted(technologies),
        notes=notes,
    )
