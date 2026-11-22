"""Privacy PII data flows analysis and third-party SDK/tracker inventory."""

from __future__ import annotations

import uuid
import zipfile
from pathlib import Path

from raa.domain.security import PrivacyDataFlow, SdkFinding

# PII source API signatures
_PII_SOURCES: list[tuple[str, str, str]] = [
    (
        "location",
        "LocationManager.getLastKnownLocation",
        "android/location/LocationManager;->getLastKnownLocation",
    ),
    (
        "location",
        "FusedLocationProviderClient.getLastLocation",
        "FusedLocationProviderClient;->getLastLocation",
    ),
    (
        "imei_android_id",
        "TelephonyManager.getDeviceId",
        "android/telephony/TelephonyManager;->getDeviceId",
    ),
    ("imei_android_id", "Settings.Secure.ANDROID_ID", "android_id"),
    ("contacts", "ContactsContract.Contacts", "content://com.android.contacts"),
    ("camera", "CameraManager.openCamera", "android/hardware/camera2/CameraManager;->openCamera"),
    ("microphone", "MediaRecorder.setAudioSource", "android/media/MediaRecorder;->setAudioSource"),
    ("sms", "SmsManager.sendTextMessage", "android/telephony/SmsManager;->sendTextMessage"),
]

# Destination sink API signatures
_DATA_SINKS: list[tuple[str, str]] = [
    ("network_transmit", "HttpURLConnection;->getOutputStream"),
    ("network_transmit", "okhttp3/OkHttpClient;->newCall"),
    ("network_transmit", "retrofit2/Retrofit;->create"),
    ("network_transmit", "java/net/URL;->openConnection"),
    ("logging", "android/util/Log;->d"),
    ("shared_prefs", "android/content/SharedPreferences$Editor;->putString"),
]

# Third-party SDK signature catalog
_KNOWN_SDKS: list[tuple[str, str, str, bool, str | None]] = [
    (
        "Firebase Analytics",
        "analytics",
        "com/google/firebase/analytics",
        True,
        "https://firebase.google.com/support/privacy",
    ),
    (
        "Google AdMob",
        "advertising",
        "com/google/android/gms/ads",
        True,
        "https://policies.google.com/privacy",
    ),
    ("Facebook SDK", "social", "com/facebook", True, "https://www.facebook.com/privacy/policy"),
    ("AppsFlyer", "analytics", "com/appsflyer", True, "https://www.appsflyer.com/privacy-policy/"),
    (
        "Branch Metrics",
        "analytics",
        "io/branch",
        True,
        "https://branch.io/policies/privacy-policy/",
    ),
    ("Mixpanel", "analytics", "com/mixpanel", True, "https://mixpanel.com/legal/privacy-policy/"),
    (
        "Adjust SDK",
        "advertising",
        "com/adjust/sdk",
        True,
        "https://www.adjust.com/terms/privacy-policy/",
    ),
    ("Unity Ads", "advertising", "com/unity3d/ads", True, "https://unity.com/legal/privacy-policy"),
    ("Sentry", "crash_reporting", "io/sentry", False, "https://sentry.io/privacy/"),
    ("OkHttp", "networking", "okhttp3", False, None),
    ("Retrofit", "networking", "retrofit2", False, None),
    ("Gson", "utility", "com/google/gson", False, None),
]


def analyze_privacy_data_flows(
    apk_path: Path, artifact_id: str, pii_type: str | None = None
) -> list[PrivacyDataFlow]:
    """Detect sensitive data flows connecting PII sources to network or disk sinks."""
    flows: list[PrivacyDataFlow] = []
    if not apk_path.is_file():
        return flows

    dex_texts: list[tuple[str, str]] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                content = zf.read(name).decode("latin1", errors="replace")
                dex_texts.append((name, content))

    for dex_name, text in dex_texts:
        found_sources = [
            (ptype, name, sig)
            for ptype, name, sig in _PII_SOURCES
            if (pii_type is None or pii_type == ptype) and (sig in text or name in text)
        ]
        found_sinks = [
            (sname, sig)
            for sname, sig in _DATA_SINKS
            if sig in text or (";->" in sig and sig.split(";->")[1] in text)
        ]

        for ptype, src_name, _ in found_sources:
            for sink_name, _ in found_sinks:
                flows.append(
                    PrivacyDataFlow(
                        flow_id=f"flow_{uuid.uuid4().hex[:10]}",
                        artifact_id=artifact_id,
                        pii_type=ptype,
                        source_api=src_name,
                        sink_api=sink_name,
                        source_location=f"{dex_name}::{src_name}",
                        sink_location=f"{dex_name}::{sink_name}",
                    )
                )

    return flows


def inventory_sdks(
    apk_path: Path, artifact_id: str, category: str | None = None
) -> list[SdkFinding]:
    """Scan container classes for presence of known third-party SDKs and trackers."""
    findings: list[SdkFinding] = []
    if not apk_path.is_file():
        return findings

    all_dex_content = ""
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                all_dex_content += zf.read(name).decode("latin1", errors="replace")

    for name, cat, prefix, is_tracker, privacy_url in _KNOWN_SDKS:
        if category and category != cat:
            continue
        if prefix in all_dex_content:
            findings.append(
                SdkFinding(
                    sdk_id=f"sdk_{uuid.uuid4().hex[:10]}",
                    name=name,
                    category=cat,
                    package_prefix=prefix.replace("/", "."),
                    is_tracker=is_tracker,
                    privacy_policy_url=privacy_url,
                )
            )

    return findings
