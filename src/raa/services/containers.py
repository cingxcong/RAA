"""Container type detection for APK-family artifacts."""

from __future__ import annotations

import zipfile
from pathlib import Path

from raa.errors import InvalidArtifactError

MEDIA_TYPES: dict[str, str] = {
    "apk": "application/vnd.android.package-archive",
    "aab": "application/octet-stream",
    "apks": "application/zip",
    "xapk": "application/zip",
    "zip": "application/zip",
    "unknown": "application/octet-stream",
}


def detect_artifact_type(path: Path, max_entries: int = 50_000) -> str:
    """Classify an artifact without extracting it.

    Extensions are hints, never trusted. A malformed ZIP raises
    ``InvalidArtifactError`` so callers fail closed.
    """

    if not zipfile.is_zipfile(path):
        return "unknown"

    try:
        with zipfile.ZipFile(path) as archive:
            names: set[str] = set()
            for index, info in enumerate(archive.infolist()):
                if index >= max_entries:
                    break
                names.add(info.filename.replace("\\", "/"))
    except (OSError, zipfile.BadZipFile) as exc:
        raise InvalidArtifactError(
            "The artifact is not a readable ZIP container.",
            hint="Re-download the APK/AAB/APKS/XAPK and verify its hash.",
        ) from exc

    has_apk_member = any(name.lower().endswith(".apk") for name in names)

    if "BundleConfig.pb" in names or any(name.startswith("base/manifest/") for name in names):
        return "aab"
    if "toc.pb" in names or (has_apk_member and any(name.startswith("splits/") for name in names)):
        return "apks"
    if "manifest.json" in names and has_apk_member:
        return "xapk"
    if has_apk_member:
        return "apks"
    if "AndroidManifest.xml" in names:
        return "apk"
    return "zip"


def media_type_for(artifact_type: str) -> str:
    return MEDIA_TYPES.get(artifact_type, MEDIA_TYPES["unknown"])
