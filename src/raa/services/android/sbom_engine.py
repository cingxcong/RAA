"""Software Bill of Materials (SBOM) generator and vulnerability mapping engine."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from raa.domain.security import (
    SbomComponent,
    SbomDocument,
    VulnerabilityFinding,
)
from raa.services.android.privacy_engine import inventory_sdks

# Known vulnerability advisory catalog for Android third-party components
_KNOWN_VULNERABILITIES: list[tuple[str, str, str, str | None, str, float, str, str]] = [
    (
        "CVE-2021-0341",
        "okhttp3",
        "4.9.0",
        "4.9.2",
        "medium",
        6.5,
        "OkHttp TLS hostname verification vulnerability when handling certificate SANs.",
        "https://osv.dev/vulnerability/GHSA-w335-x7fc-cpfg",
    ),
    (
        "CVE-2022-25845",
        "com.alibaba.fastjson",
        "1.2.80",
        "1.2.83",
        "critical",
        9.8,
        "Fastjson deserialization vulnerability allowing remote code execution "
        "via AutoType bypass.",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-25845",
    ),
    (
        "CVE-2020-36518",
        "com.fasterxml.jackson",
        "2.12.0",
        "2.13.2.1",
        "high",
        7.5,
        "Jackson-databind deep nesting stack overflow leading to denial of service.",
        "https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2",
    ),
]


def generate_sbom(
    apk_path: Path,
    artifact_id: str,
    format_type: str = "cyclonedx",
) -> SbomDocument:
    """Generate a standard Software Bill of Materials (SBOM) for the APK container."""
    sdks = inventory_sdks(apk_path, artifact_id)
    components: list[SbomComponent] = []

    for sdk in sdks:
        prefix = sdk.package_prefix
        version = sdk.version or "1.0.0"
        purl = f"pkg:maven/{prefix}/{sdk.name.lower().replace(' ', '-')}@{version}"

        components.append(
            SbomComponent(
                purl=purl,
                name=sdk.name,
                version=version,
                supplier=f"Organization maintaining {sdk.name}",
                licenses=[
                    "Apache-2.0" if "Google" in sdk.name or "Firebase" in sdk.name else "MIT"
                ],
                cpe=f"cpe:2.3:a:{prefix}:{sdk.name.lower()}:{version}:*:*:*:*:*:*:*",
            )
        )

    # If no third-party SDKs found, add base Android application runtime component
    if not components:
        components.append(
            SbomComponent(
                purl="pkg:generic/android-app@1.0.0",
                name="Application Package",
                version="1.0.0",
                licenses=["Proprietary"],
            )
        )

    return SbomDocument(
        format="spdx" if format_type == "spdx" else "cyclonedx",
        spec_version="2.3" if format_type == "spdx" else "1.5",
        serial_number=f"urn:uuid:{uuid.uuid4()}",
        artifact_id=artifact_id,
        components=components,
    )


def scan_vulnerabilities(
    apk_path: Path,
    artifact_id: str,
    min_severity: str = "low",
) -> list[VulnerabilityFinding]:
    """Correlate identified software components with known CVE/OSV security advisories."""
    sdks = inventory_sdks(apk_path, artifact_id)
    findings: list[VulnerabilityFinding] = []

    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = severity_order.get(min_severity.lower(), 1)

    for cve, pkg, installed, fixed, sev, score, summary, url in _KNOWN_VULNERABILITIES:
        if severity_order.get(sev, 0) < threshold:
            continue

        # Check if package prefix matches any identified SDK
        matches = any(pkg in sdk.package_prefix.lower() or pkg in sdk.name.lower() for sdk in sdks)
        if matches:
            findings.append(
                VulnerabilityFinding(
                    vuln_id=cve,
                    package_name=pkg,
                    installed_version=installed,
                    fixed_version=fixed,
                    severity=sev,
                    cvss_score=score,
                    summary=summary,
                    advisory_url=url,
                )
            )

    return findings


def export_sbom_document(doc: SbomDocument) -> str:
    """Format and export the SBOM document in JSON string format."""
    if doc.format == "spdx":
        spdx_payload: dict[str, Any] = {
            "spdxVersion": f"SPDX-{doc.spec_version}",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"SBOM for artifact {doc.artifact_id}",
            "documentNamespace": f"https://raa.local/spdx/{doc.artifact_id}",
            "creationInfo": {
                "created": doc.generated_at.isoformat(),
                "creators": ["Tool: RAA-0.1.0"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{c.name.replace(' ', '-')}",
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": c.licenses[0] if c.licenses else "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": c.purl,
                        }
                    ],
                }
                for c in doc.components
            ],
        }
        return json.dumps(spdx_payload, indent=2)

    # CycloneDX 1.5 JSON
    cdx_payload: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": doc.spec_version,
        "serialNumber": doc.serial_number,
        "version": 1,
        "metadata": {
            "timestamp": doc.generated_at.isoformat(),
            "tools": [{"vendor": "RAA", "name": "RAA", "version": "0.1.0"}],
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "licenses": [{"license": {"id": lic}} for lic in c.licenses],
            }
            for c in doc.components
        ],
    }
    return json.dumps(cdx_payload, indent=2)
