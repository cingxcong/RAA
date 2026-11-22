"""Domain models for security analysis, secret scanning, privacy flows, SBOM, and threat intel."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from raa.utils.time import utc_now

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]


class MasvsCategory(StrEnum):
    """OWASP Mobile Application Security Verification Standard (MASVS) categories."""

    STORAGE = "MASVS-STORAGE"
    CRYPTO = "MASVS-CRYPTO"
    AUTH = "MASVS-AUTH"
    NETWORK = "MASVS-NETWORK"
    PLATFORM = "MASVS-PLATFORM"
    CODE = "MASVS-CODE"
    RESILIENCE = "MASVS-RESILIENCE"


class SecurityFinding(BaseModel):
    """A verified security vulnerability, misconfiguration, or compliance finding."""

    finding_id: str
    artifact_id: str
    rule_id: str
    title: str
    severity: SeverityLevel
    masvs_id: str | None = None
    cwe_id: str | None = None
    description: str
    rationale: str
    remediation: str
    location: str
    line_number: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utc_now)


class SecretFinding(BaseModel):
    """Identified secret, credential, token, or private key with mandatory redaction."""

    secret_id: str
    artifact_id: str
    kind: str  # aws_key, google_api_key, private_key, jwt_token, generic_secret
    location: str
    line_number: int | None = None
    redacted_value: str
    entropy: float = 0.0
    evidence_id: str | None = None
    detected_at: datetime = Field(default_factory=utc_now)


class PrivacyDataFlow(BaseModel):
    """Taint path connecting a sensitive PII source API to an external sink API."""

    flow_id: str
    artifact_id: str
    pii_type: str  # location, imei_android_id, contacts, camera, microphone, sms
    source_api: str
    sink_api: str
    source_location: str
    sink_location: str
    evidence_id: str | None = None
    detected_at: datetime = Field(default_factory=utc_now)


class SdkFinding(BaseModel):
    """Identified third-party SDK, advertising network, or tracking library."""

    sdk_id: str
    name: str
    category: str  # analytics, advertising, crash_reporting, networking, social
    package_prefix: str
    version: str | None = None
    is_tracker: bool = False
    privacy_policy_url: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class SbomComponent(BaseModel):
    """Component entry in an SBOM document (CycloneDX / SPDX compatible)."""

    purl: str
    name: str
    version: str
    supplier: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)  # sha1, sha256
    licenses: list[str] = Field(default_factory=list)
    cpe: str | None = None


class SbomDocument(BaseModel):
    """Standard Software Bill of Materials."""

    format: Literal["cyclonedx", "spdx"] = "cyclonedx"
    spec_version: str = "1.5"
    serial_number: str
    artifact_id: str
    components: list[SbomComponent] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


class VulnerabilityFinding(BaseModel):
    """Mapped CVE/OSV advisory for an identified third-party component."""

    vuln_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: SeverityLevel
    cvss_score: float | None = None
    summary: str
    advisory_url: str | None = None


class MalwareCapability(BaseModel):
    """Observed behavioral or signature capability matching YARA, capa, or Quark rules."""

    rule_id: str
    name: str
    engine: Literal["yara", "capa", "quark"]
    description: str
    severity: SeverityLevel = "medium"
    matches: list[str] = Field(default_factory=list)
    score: float = 0.0


class QuarkScoreReport(BaseModel):
    """Android behavioral risk score calculated according to Quark rules."""

    artifact_id: str
    total_score: float
    risk_level: Literal["clean", "low", "moderate", "high", "critical"]
    triggered_rules: list[MalwareCapability] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=utc_now)


class IocItem(BaseModel):
    """Extracted Indicator of Compromise."""

    ioc_id: str
    type: Literal["ip", "domain", "url", "hash_sha256", "suspicious_file"]
    value: str
    context: str
    threat_source: str = "static_analysis"


class EnrichmentReport(BaseModel):
    """Threat intelligence enrichment record."""

    sample_sha256: str
    provider: str
    threat_verdict: Literal["clean", "suspicious", "malicious", "unknown"]
    reputation_score: int
    tags: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    consent_verified: bool = False
    enriched_at: datetime = Field(default_factory=utc_now)
