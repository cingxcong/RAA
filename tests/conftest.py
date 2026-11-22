"""Shared fixtures and synthetic Android containers.

The fixtures build deliberately tiny ZIP-based packages with a valid binary
manifest and resource table. They test container, manifest and resource handling
without shipping a real APK or executing any code.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from raa.config import Settings
from raa.runtime import Runtime
from tests.arsc_builder import build_sample_resource_table
from tests.axml_builder import build_sample_manifest
from tests.dex_builder import build_sample_dex, build_sample_dex2


def make_apk(
    path: Path,
    *,
    entries: dict[str, bytes] | None = None,
    signed: bool = True,
    include_manifest: bool = True,
    include_resources: bool = True,
    include_dex: bool = True,
) -> Path:
    payload: dict[str, bytes] = {
        "lib/arm64-v8a/libflutter.so": b"\x7fELF" + b"\x00" * 64,
        "lib/arm64-v8a/libapp.so": b"\x7fELF" + b"\x00" * 64,
        "assets/flutter_assets/AssetManifest.json": b"{}",
        "assets/flutter_assets/fonts/Roboto.ttf": b"\x00" * 32,
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n\n",
    }
    if include_manifest:
        payload["AndroidManifest.xml"] = build_sample_manifest()
    if include_resources:
        payload["resources.arsc"] = build_sample_resource_table()
    if include_dex:
        payload["classes.dex"] = build_sample_dex()
        payload["classes2.dex"] = build_sample_dex2()
    if signed:
        payload["META-INF/CERT.RSA"] = b"\x30\x82" + b"\x00" * 32
    payload.update(entries or {})

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in payload.items():
            archive.writestr(name, data)
    return path


@pytest.fixture
def apk_path(tmp_path: Path) -> Path:
    return make_apk(tmp_path / "sample.apk")


@pytest.fixture
def unsigned_apk_path(tmp_path: Path) -> Path:
    return make_apk(tmp_path / "unsigned.apk", signed=False)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        workspace=tmp_path / "workspace",
        profile="core",
        allowed_input_roots=[tmp_path],
        analysis_timeout_seconds=15,
    )


@pytest.fixture
def runtime(settings: Settings) -> Iterator[Runtime]:
    instance = Runtime(settings)
    try:
        yield instance
    finally:
        instance.analysis.shutdown()
