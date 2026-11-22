"""Phase 9 Diff, Security, Privacy, SBOM, and Malware Intelligence tests.

Verifies:
1. Multi-category APK diff engine with noise normalization (synthetic lambda counters,
   resource table renumbering, metadata changes).
2. Diff report exports in JSON, Markdown, and unified diff formats.
3. Static MASVS/MASTG security checks (debuggable, allowBackup, usesCleartextTraffic,
   exported components, ECB ciphers, weak hashes, empty TrustManagers, DexClassLoader).
4. Secret scanning with Shannon entropy calculation and mandatory redaction masking.
5. Privacy PII source-to-sink data flow analysis (location, IMEI, contacts, camera).
6. Third-party SDK and advertising/analytics tracker inventory.
7. Software Bill of Materials (SBOM) generation conforming to CycloneDX 1.5 and SPDX 2.3.
8. Component vulnerability correlation against CVE/OSV advisories.
9. YARA rule scanning, Capa capability detection, and Quark behavioral risk scoring.
10. Indicators of Compromise (IOC) harvesting and multi-format export (JSON, CSV, STIX 2.1).
11. Threat intelligence enrichment with mandatory consent gating (PolicyDeniedError).
12. Full end-to-end Runtime dispatch across all 17 Phase 9 tools.
13. Typer CLI subcommands under `raa diff` and `raa security`.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.domain.diff import ChangeCategory, ChangeType
from raa.domain.security import MasvsCategory
from raa.errors import PolicyDeniedError
from raa.runtime import Runtime
from raa.services.android.diff_engine import compare_apks, export_diff_report
from raa.services.android.malware_scanner import (
    compute_quark_score,
    enrich_sample,
    export_iocs,
    extract_iocs,
    run_capa_scan,
    run_yara_scan,
)
from raa.services.android.privacy_engine import analyze_privacy_data_flows, inventory_sdks
from raa.services.android.sbom_engine import (
    export_sbom_document,
    generate_sbom,
    scan_vulnerabilities,
)
from raa.services.android.secret_scanner import scan_secrets
from raa.services.android.security_scanner import scan_static_security

runner = CliRunner()


def _make_custom_apk(path: Path, entries: dict[str, bytes]) -> Path:
    """Helper to build an APK zip with precise entries."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_diff_engine_semantic_and_noise(tmp_path: Path) -> None:
    """Verify that semantic changes are flagged True while compiler noise is filtered."""
    base_apk = _make_custom_apk(
        tmp_path / "base.apk",
        {
            "AndroidManifest.xml": (
                b"<manifest><application><activity android:name='.MainActivity'/>"
                b"</application></manifest>"
            ),
            "classes.dex": b"DEX\n035\x00BASE_CODE",
            "res/values/strings.xml": (
                b"<resources><string name='app_name' id='0x7f010001'>TestApp</string></resources>"
            ),
            "classes2.dex": b"DEX\n035\x00com/example/Helper$$ExternalSyntheticLambda0",
            "sample.version": b"version=1.0.0",
        },
    )

    target_apk = _make_custom_apk(
        tmp_path / "target.apk",
        {
            # Semantic: added SecretActivity
            "AndroidManifest.xml": (
                b"<manifest><application><activity android:name='.MainActivity'/>"
                b"<activity android:name='.SecretActivity'/></application></manifest>"
            ),
            # Semantic: changed bytecode
            "classes.dex": b"DEX\n035\x00TARGET_CODE_MODIFIED",
            # Noise: solely renumbered resource ID from 0x7f010001 to 0x7f020002
            "res/values/strings.xml": (
                b"<resources><string name='app_name' id='0x7f020002'>TestApp</string></resources>"
            ),
            # Noise: lambda counter shifted from Lambda0 to Lambda1
            "classes2.dex": b"DEX\n035\x00com/example/Helper$$ExternalSyntheticLambda1",
            # Noise: build metadata version change
            "sample.version": b"version=1.0.1",
            # Semantic: added native library
            "lib/arm64-v8a/libpayload.so": b"\x7fELF\x02\x01\x01\x00",
        },
    )

    report = compare_apks(
        base_apk,
        target_apk,
        base_artifact_id="art_base",
        target_artifact_id="art_target",
        project_id="prj_test",
    )

    assert report.total_changes >= 5
    assert report.semantic_changes_count >= 3
    assert report.noise_changes_count >= 2

    # Manifest change must be semantic
    manifest_change = next(c for c in report.changes if c.path == "AndroidManifest.xml")
    assert manifest_change.is_semantic is True
    assert manifest_change.category == ChangeCategory.MANIFEST
    assert manifest_change.diff_unified is not None
    assert "SecretActivity" in manifest_change.diff_unified

    # Native lib addition must be semantic
    native_change = next(c for c in report.changes if c.path.startswith("lib/"))
    assert native_change.is_semantic is True
    assert native_change.change_type == ChangeType.ADDED

    # Resource renumbering must be flagged noise
    res_change = next(c for c in report.changes if c.path == "res/values/strings.xml")
    assert res_change.is_semantic is False
    assert res_change.noise_reason is not None
    assert "Resource table renumbering" in res_change.noise_reason

    # Build metadata must be flagged noise
    ver_change = next(c for c in report.changes if c.path == "sample.version")
    assert ver_change.is_semantic is False
    assert ver_change.noise_reason is not None

    # Test report export formats
    json_out = export_diff_report(report, "json")
    parsed = json.loads(json_out)
    assert parsed["diff_id"] == report.diff_id

    md_out = export_diff_report(report, "markdown")
    assert f"# Diff Report: {report.diff_id}" in md_out
    assert "## Summary by Category" in md_out

    unified_out = export_diff_report(report, "unified")
    assert "--- a/AndroidManifest.xml" in unified_out


def test_security_scanner_masvs_rules(tmp_path: Path) -> None:
    """Verify static security checks against vulnerable manifest flags and insecure code."""
    vulnerable_manifest = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        b'  <application android:debuggable="true" android:allowBackup="true" '
        b'android:usesCleartextTraffic="true">\n'
        b'    <activity android:name=".ExportedVulnerableActivity" android:exported="true" />\n'
        b"  </application>\n"
        b"</manifest>\n"
    )
    insecure_code = (
        b"// Insecure crypto and network code\n"
        b'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        b'MessageDigest md = MessageDigest.getInstance("MD5");\n'
        b"public void checkServerTrusted(X509Certificate[] chain, String authType) {}\n"
        b"DexClassLoader loader = new DexClassLoader(dexPath, null, null, getClassLoader());\n"
    )

    apk_path = _make_custom_apk(
        tmp_path / "vulnerable.apk",
        {
            "AndroidManifest.xml": vulnerable_manifest,
            "classes.dex": insecure_code,
        },
    )

    findings = scan_static_security(apk_path, "art_vuln")
    rule_ids = {f.rule_id for f in findings}

    assert "RULE-PLATFORM-DEBUGGABLE" in rule_ids
    assert "RULE-STORAGE-BACKUP" in rule_ids
    assert "RULE-NETWORK-CLEARTEXT" in rule_ids
    assert "RULE-PLATFORM-EXPORTED" in rule_ids
    assert "RULE-CRYPTO-ECB" in rule_ids
    assert "RULE-CRYPTO-WEAK-HASH" in rule_ids
    assert "RULE-NETWORK-TRUST-ALL" in rule_ids
    assert "RULE-CODE-DCL" in rule_ids

    # Validate MASVS mapping and CWE presence
    ecb_finding = next(f for f in findings if f.rule_id == "RULE-CRYPTO-ECB")
    assert ecb_finding.masvs_id == MasvsCategory.CRYPTO.value
    assert ecb_finding.severity == "high"
    assert ecb_finding.cwe_id == "CWE-327"
    assert "ECB" in ecb_finding.title


def test_secret_scanner_redaction(tmp_path: Path) -> None:
    """Verify credential scanning, Shannon entropy, and mandatory value redaction."""
    embedded_secrets = (
        b'val awsKey = "' + b"AKIA" + b'IOSFODNN7EXAMPLE"\n'
        b'val googleKey = "' + b"AIza" + b'SyD-XYZ1234567890abcdefghij1234567"\n'
        b'val ghToken = "' + b"ghp_" + b'1234567890abcdefghijklmnopqrstuvwxyz"\n'
        b'val cert = "-----' + b"BEGIN RSA PRIVATE KEY" + b"-----\n"
        b"MIIEowIBAAKCAQEA0M123456789\n-----" + b"END RSA PRIVATE KEY" + b'-----"\n'
    )

    apk_path = _make_custom_apk(
        tmp_path / "secrets.apk",
        {
            "classes.dex": embedded_secrets,
            "assets/config.json": b'{"api_token": "' + b"AKIA" + b'I44QH8DHBEXAMPLE"}',
        },
    )

    findings = scan_secrets(apk_path, "art_secrets")
    assert len(findings) >= 3

    # Ensure raw secret is NEVER exposed and redaction format matches prefix...****
    for f in findings:
        assert f.redacted_value.endswith("...****")
        assert f.entropy > 2.5
        assert f.location is not None
        # Must not contain full unmasked token
        assert ("AKIA" + "IOSFODNN7EXAMPLE") not in f.redacted_value
        assert ("AIza" + "SyD-XYZ1234567890abcdefghij1234567") not in f.redacted_value


def test_privacy_data_flows_and_sdks(tmp_path: Path) -> None:
    """Verify PII source-to-sink transmission flows and third-party tracker detection."""
    source_sink_code = (
        b"android/location/LocationManager;->getLastKnownLocation\n"
        b"android/telephony/TelephonyManager;->getDeviceId\n"
        b"HttpURLConnection;->getOutputStream\n"
        b"// Third-party SDK signatures\n"
        b"com/google/firebase/analytics\n"
        b"com/google/android/gms/ads\n"
        b"okhttp3\n"
    )

    apk_path = _make_custom_apk(
        tmp_path / "privacy.apk",
        {
            "classes.dex": source_sink_code,
        },
    )

    # 1. PII Flows
    flows = analyze_privacy_data_flows(apk_path, "art_privacy")
    assert len(flows) >= 2
    types = {flow.pii_type for flow in flows}
    assert "location" in types
    assert "imei_android_id" in types

    location_flow = next(flow for flow in flows if flow.pii_type == "location")
    assert "LocationManager" in location_flow.source_api
    assert "network_transmit" in location_flow.sink_api

    # 2. SDK Inventory
    sdks = inventory_sdks(apk_path, "art_privacy")
    sdk_names = {s.name for s in sdks}
    assert "Firebase Analytics" in sdk_names
    assert "Google AdMob" in sdk_names
    assert "OkHttp" in sdk_names

    firebase = next(s for s in sdks if s.name == "Firebase Analytics")
    assert firebase.is_tracker is True
    assert firebase.category == "analytics"
    assert firebase.privacy_policy_url is not None

    okhttp = next(s for s in sdks if s.name == "OkHttp")
    assert okhttp.is_tracker is False
    assert okhttp.category == "networking"


def test_sbom_and_vulnerabilities(tmp_path: Path) -> None:
    """Verify CycloneDX 1.5, SPDX 2.3 SBOM generation, and known CVE mapping."""
    apk_path = _make_custom_apk(
        tmp_path / "app_sbom.apk",
        {
            "classes.dex": b"okhttp3/OkHttpClient retrofit2/Retrofit com/google/gson/Gson",
        },
    )

    # CycloneDX 1.5
    cdx_doc = generate_sbom(apk_path, "art_sbom", format_type="cyclonedx")
    assert cdx_doc.format == "cyclonedx"
    assert cdx_doc.spec_version == "1.5"
    assert len(cdx_doc.components) >= 3

    cdx_json = export_sbom_document(cdx_doc)
    parsed_cdx = json.loads(cdx_json)
    assert parsed_cdx["bomFormat"] == "CycloneDX"
    assert parsed_cdx["specVersion"] == "1.5"

    # SPDX 2.3
    spdx_doc = generate_sbom(apk_path, "art_sbom", format_type="spdx")
    assert spdx_doc.format == "spdx"
    assert spdx_doc.spec_version == "2.3"

    spdx_json = export_sbom_document(spdx_doc)
    parsed_spdx = json.loads(spdx_json)
    assert parsed_spdx["spdxVersion"] == "SPDX-2.3"

    # Vulnerability Correlation
    vulns = scan_vulnerabilities(apk_path, "art_sbom")
    cve_ids = {v.vuln_id for v in vulns}
    assert "CVE-2021-0341" in cve_ids
    okhttp_vuln = next(v for v in vulns if v.vuln_id == "CVE-2021-0341")
    assert okhttp_vuln.package_name == "okhttp3"
    assert okhttp_vuln.cvss_score == 6.5
    assert okhttp_vuln.fixed_version == "4.9.2"


def test_malware_yara_capa_quark_and_iocs(tmp_path: Path) -> None:
    """Verify malware capability detection, behavioral scoring, and IOC export."""
    malicious_bytecode = (
        b"// Offensive capabilities\n"
        b"android.provider.Telephony.SMS_RECEIVED getDisplayMessageBody\n"
        b"DexClassLoader dalvik.system Runtime.getRuntime().exec\n"
        b"AccessibilityService android.accessibilityservice\n"
        b"// Hardcoded C2 indicators\n"
        b'String c2Ip = "198.51.100.77";\n'
        b'String c2Domain = "malicious-payload-drop.top";\n'
        b'String c2Url = "http://malicious-payload-drop.top/c2/gate.php";\n'
    )

    apk_path = _make_custom_apk(
        tmp_path / "malware.apk",
        {
            "classes.dex": malicious_bytecode,
        },
    )

    # 1. YARA scan
    yara_hits = run_yara_scan(apk_path, "art_malware")
    assert len(yara_hits) >= 1

    # 2. Capa offensive capabilities
    capa_hits = run_capa_scan(apk_path, "art_malware")
    capa_names = {c.name for c in capa_hits}
    assert "SMS Interception and Exfiltration" in capa_names

    # 3. Quark behavioral scoring
    quark = compute_quark_score(apk_path, "art_malware")
    assert quark.total_score > 5.0
    assert quark.risk_level in ("medium", "high", "critical")
    assert len(quark.triggered_rules) >= 2

    # 4. IOC harvesting
    iocs = extract_iocs(apk_path)
    ioc_values = {item.value for item in iocs}
    assert "198.51.100.77" in ioc_values
    assert "malicious-payload-drop.top" in ioc_values
    assert "http://malicious-payload-drop.top/c2/gate.php" in ioc_values

    # 5. IOC export: JSON
    json_iocs = export_iocs(iocs, "json")
    assert "198.51.100.77" in json_iocs

    # 6. IOC export: CSV
    csv_iocs = export_iocs(iocs, "csv")
    csv_reader = csv.reader(io.StringIO(csv_iocs))
    rows = list(csv_reader)
    assert len(rows) >= 4  # Header + 3 IOCs
    assert rows[0] == ["ioc_id", "type", "value", "context", "threat_source"]

    # 7. IOC export: STIX 2.1
    stix_iocs = export_iocs(iocs, "stix21")
    stix_bundle = json.loads(stix_iocs)
    assert stix_bundle["type"] == "bundle"
    assert len(stix_bundle["objects"]) >= 3
    pattern_types = {obj["pattern"] for obj in stix_bundle["objects"] if obj["type"] == "indicator"}
    assert any("ipv4-addr:value = '198.51.100.77'" in p for p in pattern_types)


def test_sample_enrich_consent_gate() -> None:
    """Verify strict consent gating for external threat intelligence enrichment."""
    # Calling without explicit consent MUST raise PolicyDeniedError
    with pytest.raises(PolicyDeniedError) as excinfo:
        enrich_sample(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", user_consent=False
        )
    assert "consent" in excinfo.value.message.lower()

    # Calling with consent succeeds
    report = enrich_sample(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        user_consent=True,
        provider="internal",
    )
    assert (
        report.sample_sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert report.provider == "internal"
    assert report.threat_verdict == "clean"


async def test_runtime_diff_and_security_tools(runtime: Runtime, tmp_path: Path) -> None:
    """Verify dispatching of all 17 Phase 9 tools via Runtime.invoke."""
    # Setup project and baseline artifacts
    created_proj = await runtime.invoke(
        "project_create",
        {
            "name": "Phase 9 Runtime Project",
            "scopes": [
                "project.read",
                "project.write",
                "static.read",
                "export.write",
                "export.raw",
                "llm.external",
            ],
        },
    )
    project_id = created_proj.data["id"]

    apk1 = _make_custom_apk(
        tmp_path / "app_v1.apk",
        {
            "AndroidManifest.xml": b"<manifest><application android:debuggable='true'/></manifest>",
            "classes.dex": (
                b"AKIA" + b"IOSFODNN7EXAMPLE\n"
                b"android/location/LocationManager;->getLastKnownLocation\n"
                b"HttpURLConnection;->getOutputStream\n"
                b"okhttp3/OkHttpClient\n"
                b"198.51.100.99\n"
            ),
        },
    )
    apk2 = _make_custom_apk(
        tmp_path / "app_v2.apk",
        {
            "AndroidManifest.xml": (
                b"<manifest><application android:debuggable='false'/></manifest>"
            ),
            "classes.dex": b"AKIA" + b"IOSFODNN7EXAMPLE okhttp3",
        },
    )

    ingest1 = await runtime.invoke("artifact_ingest", {"project_id": project_id, "path": str(apk1)})
    art1_id = ingest1.data["id"]

    ingest2 = await runtime.invoke("artifact_ingest", {"project_id": project_id, "path": str(apk2)})
    art2_id = ingest2.data["id"]

    # 1. artifact_compare
    diff_res = await runtime.invoke(
        "artifact_compare",
        {
            "project_id": project_id,
            "base_artifact_id": art1_id,
            "target_artifact_id": art2_id,
        },
    )
    diff_id = diff_res.data["diff_id"]
    assert diff_res.data["total_changes"] >= 1

    # 2. diff_list_changes
    list_changes = await runtime.invoke(
        "diff_list_changes",
        {"project_id": project_id, "diff_id": diff_id},
    )
    assert len(list_changes.data["changes"]) >= 1
    change_id = list_changes.data["changes"][0]["change_id"]

    # 3. diff_get
    change_detail = await runtime.invoke(
        "diff_get",
        {"project_id": project_id, "diff_id": diff_id, "change_id": change_id},
    )
    assert change_detail.data["change_id"] == change_id

    # 4. diff_export
    diff_exp = await runtime.invoke(
        "diff_export",
        {"project_id": project_id, "diff_id": diff_id, "format": "markdown"},
    )
    assert "Diff Report" in diff_exp.data["content"]

    # 5. security_scan_static
    sec_scan = await runtime.invoke(
        "security_scan_static",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert sec_scan.data["count"] >= 1

    # 6. security_get_findings
    sec_findings = await runtime.invoke(
        "security_get_findings",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert len(sec_findings.data["findings"]) >= 1

    # 7. security_find_secret_locations
    secrets_res = await runtime.invoke(
        "security_find_secret_locations",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert secrets_res.data["count"] >= 1
    assert secrets_res.data["secrets"][0]["redacted_value"].endswith("...****")

    # 8. privacy_data_flows
    privacy_res = await runtime.invoke(
        "privacy_data_flows",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert privacy_res.data["count"] >= 1

    # 9. sdk_inventory
    sdk_res = await runtime.invoke(
        "sdk_inventory",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert sdk_res.data["count"] >= 1

    # 10. sbom_generate
    sbom_res = await runtime.invoke(
        "sbom_generate",
        {"project_id": project_id, "artifact_id": art1_id, "format": "cyclonedx"},
    )
    assert sbom_res.data["format"] == "cyclonedx"
    assert "document" in sbom_res.data

    # 11. vulnerability_scan
    vuln_res = await runtime.invoke(
        "vulnerability_scan",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert vuln_res.data["count"] >= 1

    # 12. yara_scan
    yara_res = await runtime.invoke(
        "yara_scan",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert "matches" in yara_res.data

    # 13. capa_scan
    capa_res = await runtime.invoke(
        "capa_scan",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert "capabilities" in capa_res.data

    # 14. quark_score
    quark_res = await runtime.invoke(
        "quark_score",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert "total_score" in quark_res.data

    # 15. ioc_extract
    ioc_res = await runtime.invoke(
        "ioc_extract",
        {"project_id": project_id, "artifact_id": art1_id},
    )
    assert ioc_res.data["count"] >= 1

    # 16. ioc_export
    ioc_exp = await runtime.invoke(
        "ioc_export",
        {"project_id": project_id, "artifact_id": art1_id, "format": "stix21"},
    )
    assert ioc_exp.data["format"] == "stix21"

    # 17. sample_enrich: consent gating
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "sample_enrich",
            {"project_id": project_id, "artifact_id": art1_id, "user_consent": False},
        )

    enrich_res = await runtime.invoke(
        "sample_enrich",
        {"project_id": project_id, "artifact_id": art1_id, "user_consent": True},
    )
    assert enrich_res.data["threat_verdict"] in ("clean", "suspicious", "malicious")


def test_cli_diff_and_security_commands(tmp_path: Path) -> None:
    """Verify Typer CLI commands for raa diff and raa security subcommands."""
    ws = tmp_path / "workspace"
    apk1 = _make_custom_apk(
        tmp_path / "cli_v1.apk",
        {
            "AndroidManifest.xml": b"<manifest><application android:debuggable='true'/></manifest>",
            "classes.dex": (
                b"AKIA" + b"IOSFODNN7EXAMPLE\n"
                b"android/location/LocationManager;->getLastKnownLocation\n"
                b"HttpURLConnection;->getOutputStream\n"
                b"okhttp3/OkHttpClient\n"
                b"198.51.100.99\n"
            ),
        },
    )
    apk2 = _make_custom_apk(
        tmp_path / "cli_v2.apk",
        {
            "AndroidManifest.xml": (
                b"<manifest><application android:debuggable='false'/></manifest>"
            ),
            "classes.dex": b"AKIA" + b"IOSFODNN7EXAMPLE okhttp3",
        },
    )

    # Create project and ingest
    res = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "project",
            "create",
            "CLI Diff Project",
            "--scope",
            "project.read",
            "--scope",
            "project.write",
            "--scope",
            "static.read",
            "--scope",
            "export.write",
            "--scope",
            "export.raw",
            "--scope",
            "llm.external",
        ],
    )
    assert res.exit_code == 0
    proj_id = json.loads(res.stdout)["data"]["id"]

    res1 = runner.invoke(
        app, ["--workspace", str(ws), "--json", "artifact", "ingest", proj_id, str(apk1)]
    )
    art1_id = json.loads(res1.stdout)["data"]["id"]

    res2 = runner.invoke(
        app, ["--workspace", str(ws), "--json", "artifact", "ingest", proj_id, str(apk2)]
    )
    art2_id = json.loads(res2.stdout)["data"]["id"]

    # 1. raa diff compare
    res_diff = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "diff", "compare", proj_id, art1_id, art2_id],
    )
    assert res_diff.exit_code == 0
    diff_payload = json.loads(res_diff.stdout)
    diff_id = diff_payload["data"]["diff_id"]

    # 2. raa diff list
    res_list = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "diff", "list", proj_id, diff_id],
    )
    assert res_list.exit_code == 0

    # 3. raa diff export
    res_exp = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "diff", "export", proj_id, diff_id, "--format", "json"],
    )
    assert res_exp.exit_code == 0

    # 4. raa security scan
    res_scan = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "scan", proj_id, "-a", art1_id],
    )
    assert res_scan.exit_code == 0

    # 5. raa security findings
    res_find = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "findings", proj_id, "-a", art1_id],
    )
    assert res_find.exit_code == 0

    # 6. raa security secrets
    res_sec = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "secrets", proj_id, "-a", art1_id],
    )
    assert res_sec.exit_code == 0

    # 7. raa security privacy
    res_priv = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "privacy", proj_id, "-a", art1_id],
    )
    assert res_priv.exit_code == 0

    # 8. raa security sdks
    res_sdks = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "sdks", proj_id, "-a", art1_id],
    )
    assert res_sdks.exit_code == 0

    # 9. raa security sbom
    res_sbom = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "sbom", proj_id, "-a", art1_id],
    )
    assert res_sbom.exit_code == 0

    # 10. raa security vulns
    res_vulns = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "vulns", proj_id, "-a", art1_id],
    )
    assert res_vulns.exit_code == 0

    # 11. raa security ioc
    res_ioc = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "ioc", proj_id, "-a", art1_id],
    )
    assert res_ioc.exit_code == 0

    # 12. raa security enrich (consent required)
    res_enrich_noconsent = runner.invoke(
        app,
        ["--workspace", str(ws), "--json", "security", "enrich", proj_id, "-a", art1_id],
    )
    assert res_enrich_noconsent.exit_code == 1

    res_enrich_consent = runner.invoke(
        app,
        [
            "--workspace",
            str(ws),
            "--json",
            "security",
            "enrich",
            proj_id,
            "-a",
            art1_id,
            "--consent",
        ],
    )
    assert res_enrich_consent.exit_code == 0
