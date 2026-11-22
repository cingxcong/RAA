"""Framework and packer marker detection tests."""

from __future__ import annotations

from raa.domain.models import Confidence
from raa.services.frameworks import detect_frameworks, detect_packers


def _ids(names: list[str]) -> set[str]:
    return {finding.id for finding in detect_frameworks(names)}


def test_detects_flutter() -> None:
    findings = detect_frameworks(
        ["lib/arm64-v8a/libflutter.so", "assets/flutter_assets/AssetManifest.json"]
    )
    flutter = next(item for item in findings if item.id == "flutter")
    assert flutter.confidence is Confidence.OBSERVED
    assert flutter.markers


def test_detects_multiple_frameworks() -> None:
    names = [
        "lib/arm64-v8a/libflutter.so",
        "lib/arm64-v8a/libunity.so",
        "lib/arm64-v8a/libmonodroid.so",
        "assets/www/cordova.js",
    ]
    assert {"flutter", "unity", "xamarin", "cordova"} <= _ids(names)


def test_react_native_hermes_marker() -> None:
    assert "react_native" in _ids(["lib/x86_64/libhermes.so"])


def test_native_android_requires_manifest_and_dex() -> None:
    assert "native_android" not in _ids(["AndroidManifest.xml"])
    assert "native_android" in _ids(["AndroidManifest.xml", "classes.dex"])


def test_unknown_package_has_no_framework() -> None:
    assert detect_frameworks(["assets/readme.txt", "res/raw/data.bin"]) == []


def test_packer_markers_are_inferred() -> None:
    findings = detect_packers(["lib/armeabi-v7a/libjiagu.so"])
    assert findings
    assert findings[0].id == "jiagu"
    assert findings[0].confidence is Confidence.INFERRED


def test_packer_no_false_positive() -> None:
    assert detect_packers(["lib/arm64-v8a/libflutter.so"]) == []
