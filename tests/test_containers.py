"""Container classification tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

from raa.services.containers import detect_artifact_type, media_type_for


def _zip(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def test_detects_apk(apk_path: Path) -> None:
    assert detect_artifact_type(apk_path) == "apk"
    assert media_type_for("apk") == "application/vnd.android.package-archive"


def test_detects_aab(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "bundle.aab",
        {"BundleConfig.pb": b"", "base/manifest/AndroidManifest.xml": b""},
    )
    assert detect_artifact_type(path) == "aab"


def test_detects_apks(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "splits.apks",
        {"toc.pb": b"", "splits/base-master.apk": b"PK", "splits/config.en.apk": b"PK"},
    )
    assert detect_artifact_type(path) == "apks"


def test_detects_xapk(tmp_path: Path) -> None:
    path = _zip(
        tmp_path / "package.xapk",
        {"manifest.json": b"{}", "com.example.app.apk": b"PK"},
    )
    assert detect_artifact_type(path) == "xapk"


def test_detects_nested_apk_as_apks(tmp_path: Path) -> None:
    path = _zip(tmp_path / "unknown.zip", {"base.apk": b"PK"})
    assert detect_artifact_type(path) == "apks"


def test_detects_plain_zip(tmp_path: Path) -> None:
    path = _zip(tmp_path / "files.zip", {"readme.txt": b"hello"})
    assert detect_artifact_type(path) == "zip"


def test_detects_unknown_for_non_zip(tmp_path: Path) -> None:
    path = tmp_path / "sample.apk"
    path.write_bytes(b"not a zip")
    assert detect_artifact_type(path) == "unknown"
    assert media_type_for("unknown") == "application/octet-stream"


def test_extension_is_not_trusted(tmp_path: Path) -> None:
    path = _zip(tmp_path / "really-a-bundle.aab", {"manifest.json": b"{}", "x.apk": b"PK"})
    assert detect_artifact_type(path) == "xapk"


def test_truncated_zip_is_unknown(tmp_path: Path) -> None:
    path = tmp_path / "broken.apk"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    assert detect_artifact_type(path) == "unknown"
