"""Standardized Software Bill of Materials (SBOM) generation (CycloneDX v1.5 and SPDX 2.3)."""

from __future__ import annotations

import importlib.metadata
import sys
from typing import Any

from raa.services.engines import EngineService
from raa.utils.ids import new_request_id
from raa.utils.time import utc_now
from raa.version import PROTOCOL_VERSION, __version__


class SbomService:
    """Generates CycloneDX and SPDX Software Bill of Materials for RAA runtime and engines."""

    def __init__(self, engines: EngineService) -> None:
        self.engines = engines

    def generate_cyclonedx(self) -> dict[str, Any]:
        """Generate a CycloneDX v1.5 JSON SBOM."""
        components = self._gather_components()
        serial_number = f"urn:uuid:{new_request_id().replace('req_', '')}"

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": utc_now().isoformat(),
                "tools": [
                    {
                        "vendor": "RAA Project",
                        "name": "raa",
                        "version": __version__,
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "raa",
                    "version": __version__,
                    "description": (
                        "Evidence-first Android application intelligence "
                        "and reverse-engineering platform."
                    ),
                    "properties": [
                        {"name": "protocol_version", "value": PROTOCOL_VERSION},
                        {"name": "python_version", "value": sys.version.split()[0]},
                        {"name": "platform", "value": sys.platform},
                    ],
                },
            },
            "components": components,
        }

    def generate_spdx(self) -> dict[str, Any]:
        """Generate an SPDX 2.3 JSON document."""
        packages = self._gather_spdx_packages()
        doc_id = f"SPDXRef-DOCUMENT-{__version__}"

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": f"RAA-{__version__}",
            "documentNamespace": f"https://raa.local/spdxdocs/raa-{__version__}-{new_request_id()}",
            "creationInfo": {
                "created": utc_now().isoformat(),
                "creators": [
                    "Tool: RAA-SBOM-Generator-0.1.0",
                    "Organization: RAA Engineering Team",
                ],
            },
            "packages": packages,
        }

    def _gather_components(self) -> list[dict[str, Any]]:
        components: list[dict[str, Any]] = []

        # 1. Python runtime packages
        for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.name):
            meta: Any = dist.metadata
            name = meta.get("Name", "unknown")
            version = meta.get("Version", "unknown")
            license_val = meta.get("License", "Unknown")
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:pypi/{name}@{version}",
                    "licenses": [{"license": {"id": license_val}}],
                    "scope": "required",
                }
            )

        # 2. Reverse engineering engine catalogue
        for engine in self.engines.discover():
            desc = f"{engine.spec.name} (Tier {engine.spec.tier} reverse-engineering engine)"
            components.append(
                {
                    "type": "application",
                    "name": f"engine-{engine.spec.id}",
                    "version": "catalogued",
                    "description": desc,
                    "licenses": [{"license": {"id": engine.spec.license}}],
                    "properties": [
                        {"name": "tier", "value": str(engine.spec.tier)},
                        {"name": "integration", "value": engine.spec.integration},
                        {"name": "distribution", "value": engine.spec.distribution},
                        {"name": "installed", "value": str(engine.installed)},
                    ],
                }
            )

        return components

    def _gather_spdx_packages(self) -> list[dict[str, Any]]:
        packages: list[dict[str, Any]] = [
            {
                "SPDXID": "SPDXRef-Package-raa",
                "name": "raa",
                "versionInfo": __version__,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "Apache-2.0",
                "description": "Reverse Android Anything platform",
            }
        ]

        for engine in self.engines.discover():
            safe_id = engine.spec.id.replace("_", "-").replace(".", "-")
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-engine-{safe_id}",
                    "name": engine.spec.name,
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": engine.spec.license,
                    "comment": f"Tier {engine.spec.tier} engine. Available: {engine.installed}",
                }
            )

        return packages
