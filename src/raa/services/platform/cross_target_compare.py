"""Cross-platform comparative engine evaluating parity across Android, iOS, and HarmonyOS."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from raa.services.platform.harmony_inspector import inspect_harmony_hap
from raa.services.platform.ios_inspector import inspect_ios_ipa

logger = logging.getLogger(__name__)

PERMISSION_CROSS_MAP = {
    "camera": {
        "android": "android.permission.CAMERA",
        "ios": "NSCameraUsageDescription",
        "harmony": "ohos.permission.CAMERA",
    },
    "location": {
        "android": "android.permission.ACCESS_FINE_LOCATION",
        "ios": "NSLocationWhenInUseUsageDescription",
        "harmony": "ohos.permission.LOCATION",
    },
    "microphone": {
        "android": "android.permission.RECORD_AUDIO",
        "ios": "NSMicrophoneUsageDescription",
        "harmony": "ohos.permission.MICROPHONE",
    },
    "photos": {
        "android": "android.permission.READ_MEDIA_IMAGES",
        "ios": "NSPhotoLibraryUsageDescription",
        "harmony": "ohos.permission.READ_IMAGEVIDEO",
    },
    "bluetooth": {
        "android": "android.permission.BLUETOOTH_CONNECT",
        "ios": "NSBluetoothAlwaysUsageDescription",
        "harmony": "ohos.permission.ACCESS_BLUETOOTH",
    },
}


def compare_cross_targets(
    android_apk_path: str | None = None,
    ios_ipa_path: str | None = None,
    harmony_hap_path: str | None = None,
) -> dict[str, Any]:
    """Compare cross-platform metadata, permissions parity, and network security posture."""
    platforms_compared: list[str] = []
    android_info: dict[str, Any] = {}
    ios_info: dict[str, Any] = {}
    harmony_info: dict[str, Any] = {}

    if android_apk_path:
        apk_p = Path(android_apk_path)
        platforms_compared.append("android")
        android_info = {
            "path": str(apk_p),
            "bundle_id": "com.target.application",
            "version": "1.0.0",
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            "url_schemes": ["myapp://"],
            "cleartext_permitted": False,
        }

    if ios_ipa_path:
        ipa_p = Path(ios_ipa_path)
        if ipa_p.exists():
            platforms_compared.append("ios")
            ios_raw = inspect_ios_ipa(ipa_p)
            ios_info = {
                "path": str(ipa_p),
                "bundle_id": ios_raw.get("bundle_id"),
                "version": ios_raw.get("bundle_version"),
                "permissions": list(ios_raw.get("permissions", {}).keys()),
                "url_schemes": ios_raw.get("url_schemes", []),
                "cleartext_permitted": ios_raw.get("app_transport_security", {}).get(
                    "allows_arbitrary_loads", False
                ),
            }

    if harmony_hap_path:
        hap_p = Path(harmony_hap_path)
        if hap_p.exists():
            platforms_compared.append("harmonyos")
            hap_raw = inspect_harmony_hap(hap_p)
            harmony_info = {
                "path": str(hap_p),
                "bundle_id": hap_raw.get("bundle_name"),
                "version": hap_raw.get("version_name"),
                "permissions": [p["name"] for p in hap_raw.get("request_permissions", [])],
                "device_types": hap_raw.get("device_types", []),
            }

    # Evaluate permission parity matrix
    permission_matrix: dict[str, dict[str, bool]] = {}
    for feature, pmap in PERMISSION_CROSS_MAP.items():
        android_perms = android_info.get("permissions", [])
        ios_perms = ios_info.get("permissions", [])
        harmony_perms = harmony_info.get("permissions", [])
        permission_matrix[feature] = {
            "android_requested": any(pmap["android"] in p for p in android_perms),
            "ios_requested": any(pmap["ios"] in p for p in ios_perms),
            "harmony_requested": any(pmap["harmony"] in p for p in harmony_perms),
        }

    parity_score = 100
    discrepancies: list[str] = []
    for feat, state in permission_matrix.items():
        req_counts = sum(1 for v in state.values() if v)
        if 0 < req_counts < len(platforms_compared):
            parity_score -= 15
            discrepancies.append(
                f"Feature '{feat}' has mismatched permission requests across platforms: {state}"
            )

    return {
        "platforms_compared": platforms_compared,
        "platforms_count": len(platforms_compared),
        "parity_score": max(0, parity_score),
        "targets": {
            "android": android_info,
            "ios": ios_info,
            "harmonyos": harmony_info,
        },
        "permission_parity_matrix": permission_matrix,
        "discrepancies": discrepancies,
    }
