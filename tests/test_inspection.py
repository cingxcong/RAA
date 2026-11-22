"""Extract-free archive inspection tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from raa.errors import InvalidArtifactError, LimitExceededError
from raa.services.inspection import inspect_archive, list_archive_members


def _inspect(path: Path, artifact_type: str = "apk"):
    return inspect_archive(
        path,
        artifact_type,
        max_entries=10_000,
        max_uncompressed_bytes=10_000_000,
    )


def test_inventory_of_synthetic_apk(apk_path: Path) -> None:
    result = _inspect(apk_path)

    assert result.total_entries >= 8
    assert [dex.name for dex in result.dex_files] == ["classes.dex", "classes2.dex"]
    assert result.abis == ["arm64-v8a"]
    assert {library.name for library in result.native_libraries} == {
        "libapp.so",
        "libflutter.so",
    }
    assert result.asset_count == 2
    assert result.total_uncompressed_bytes > 0
    assert "flutter" in {framework.id for framework in result.frameworks}
    assert result.signature is not None
    assert result.signature.status == "signed_v1"
    assert result.signature.v1_certificates == ["META-INF/CERT.RSA"]
    assert result.limitations


def test_v1_only_finding(apk_path: Path) -> None:
    result = _inspect(apk_path)
    assert "finding_signature_v1_only" in {finding.id for finding in result.findings}


def test_unsigned_apk_finding(unsigned_apk_path: Path) -> None:
    result = _inspect(unsigned_apk_path)
    assert result.signature is not None
    assert result.signature.status == "unsigned"
    assert "finding_signature_absent" in {finding.id for finding in result.findings}


def test_no_dex_finding(tmp_path: Path) -> None:
    path = tmp_path / "empty.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    result = _inspect(path)
    assert "finding_no_dex" in {finding.id for finding in result.findings}


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "traversal.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape.txt", b"escape")
    with pytest.raises(InvalidArtifactError):
        _inspect(path)


def test_absolute_path_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "absolute.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("C:/Windows/evil.txt", b"escape")
    with pytest.raises(InvalidArtifactError):
        _inspect(path)


def test_entry_limit_is_enforced(tmp_path: Path) -> None:
    path = tmp_path / "many.apk"
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(5):
            archive.writestr(f"file-{index}.txt", b"x")
    with pytest.raises(LimitExceededError):
        inspect_archive(path, "apk", max_entries=2, max_uncompressed_bytes=1_000)


def test_uncompressed_limit_is_enforced(tmp_path: Path) -> None:
    path = tmp_path / "large.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"x")
        archive.writestr("big.bin", b"\x00" * 10_000)
    with pytest.raises(LimitExceededError):
        inspect_archive(path, "apk", max_entries=100, max_uncompressed_bytes=1_000)


def test_list_members_pattern_and_paging(apk_path: Path) -> None:
    items, total = list_archive_members(
        apk_path,
        pattern="lib/*/*.so",
        limit=1,
        offset=0,
        max_entries=10_000,
    )
    assert total == 2
    assert len(items) == 1
    assert items[0]["name"].endswith(".so")

    second, _ = list_archive_members(
        apk_path,
        pattern="lib/*/*.so",
        limit=1,
        offset=1,
        max_entries=10_000,
    )
    assert second[0]["name"] != items[0]["name"]


def test_non_zip_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.apk"
    path.write_bytes(b"not a zip")
    with pytest.raises(InvalidArtifactError):
        _inspect(path)
