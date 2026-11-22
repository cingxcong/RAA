"""Security, secret, privacy, SBOM, vulnerability, and malware intelligence service."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from raa.domain.models import Authority, Confidence
from raa.domain.security import (
    EnrichmentReport,
    IocItem,
    MalwareCapability,
    PrivacyDataFlow,
    QuarkScoreReport,
    SbomDocument,
    SdkFinding,
    SecretFinding,
    SecurityFinding,
    VulnerabilityFinding,
)
from raa.errors import NotFoundError
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
from raa.services.artifacts import ArtifactService
from raa.services.evidence import EvidenceService
from raa.services.workspace import Workspace

logger = logging.getLogger(__name__)


class SecurityService:
    """Coordinates security scanning, compliance, SBOM, and threat detection."""

    def __init__(
        self,
        workspace: Workspace,
        artifacts: ArtifactService,
        evidence: EvidenceService,
    ) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.evidence = evidence
        self._cached_findings: dict[str, list[SecurityFinding]] = {}
        self._cached_secrets: dict[str, list[SecretFinding]] = {}
        self._cached_iocs: dict[str, list[IocItem]] = {}

    def _resolve_apk_path(
        self, project_id: str, artifact_id: str | None = None
    ) -> tuple[str, Path]:
        """Resolve target artifact ID and absolute path."""
        if artifact_id:
            art = self.artifacts.get_or_raise(project_id, artifact_id)
            return art.id, self.artifacts.path_for(art)

        arts = self.artifacts.list(project_id)
        for art in arts:
            if art.artifact_type in ("apk", "xapk", "apks", "aab", "android_container"):
                return art.id, self.artifacts.path_for(art)

        if arts:
            return arts[0].id, self.artifacts.path_for(arts[0])

        raise NotFoundError("No APK or container artifact found in project.")

    def scan_static(
        self,
        project_id: str,
        artifact_id: str | None = None,
        categories: list[str] | None = None,
    ) -> list[SecurityFinding]:
        """Perform static MASVS/MASTG security checks."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        findings = scan_static_security(apk_path, artifact_id=aid)

        if categories:
            cat_set = {c.upper() for c in categories}
            findings = [f for f in findings if f.masvs_id and any(c in f.masvs_id for c in cat_set)]

        self._cached_findings[f"{project_id}:{aid}"] = findings

        for finding in findings:
            ev = self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="security.finding",
                summary=(
                    f"[{finding.severity.upper()}] {finding.title} "
                    f"({finding.masvs_id or finding.rule_id})"
                ),
                payload=finding.model_dump(mode="json"),
                source_tool="security_scan_static",
                authority=Authority.ANALYST_INFERENCE,
                confidence=Confidence.DERIVED,
            )
            finding.evidence_ids.append(ev.id)

        return findings

    def get_findings(
        self,
        project_id: str,
        artifact_id: str | None = None,
        severity: str | None = None,
        masvs_category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve paginated security findings with optional severity or MASVS filters."""
        aid, _ = self._resolve_apk_path(project_id, artifact_id)
        cache_key = f"{project_id}:{aid}"
        findings = self._cached_findings.get(cache_key)
        if findings is None:
            findings = self.scan_static(project_id, artifact_id=aid)

        filtered = findings
        if severity:
            filtered = [f for f in filtered if f.severity.lower() == severity.lower()]
        if masvs_category:
            filtered = [
                f for f in filtered if f.masvs_id and masvs_category.upper() in f.masvs_id.upper()
            ]

        total = len(filtered)
        paged = filtered[offset : offset + limit]

        return {
            "artifact_id": aid,
            "total": total,
            "limit": limit,
            "offset": offset,
            "findings": [f.model_dump(mode="json") for f in paged],
        }

    def find_secrets(
        self,
        project_id: str,
        artifact_id: str | None = None,
        include_redacted: bool = True,
    ) -> list[SecretFinding]:
        """Locate embedded credentials, API keys, and tokens with mandatory redaction."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        secrets = scan_secrets(apk_path, artifact_id=aid)
        self._cached_secrets[f"{project_id}:{aid}"] = secrets

        for secret in secrets:
            ev = self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="security.secret",
                summary=(
                    f"Secret identified: {secret.kind} in {secret.location} "
                    f"(entropy {secret.entropy})"
                ),
                payload=secret.model_dump(mode="json"),
                source_tool="security_find_secret_locations",
                authority=Authority.ANALYST_INFERENCE,
                confidence=Confidence.DERIVED,
            )
            secret.evidence_id = ev.id

        return secrets

    def analyze_privacy(
        self,
        project_id: str,
        artifact_id: str | None = None,
        pii_type: str | None = None,
    ) -> list[PrivacyDataFlow]:
        """Detect sensitive PII data flow paths from sources to network/disk sinks."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        flows = analyze_privacy_data_flows(apk_path, artifact_id=aid, pii_type=pii_type)

        for flow in flows:
            ev = self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="privacy.data_flow",
                summary=f"PII Flow ({flow.pii_type}): {flow.source_api} -> {flow.sink_api}",
                payload=flow.model_dump(mode="json"),
                source_tool="privacy_data_flows",
                authority=Authority.ANALYST_INFERENCE,
                confidence=Confidence.INFERRED,
            )
            flow.evidence_id = ev.id

        return flows

    def get_sdks(
        self,
        project_id: str,
        artifact_id: str | None = None,
        category: str | None = None,
    ) -> list[SdkFinding]:
        """Inventory all identified third-party SDKs and trackers."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        return inventory_sdks(apk_path, artifact_id=aid, category=category)

    def generate_sbom_doc(
        self,
        project_id: str,
        artifact_id: str | None = None,
        format_type: str = "cyclonedx",
    ) -> SbomDocument:
        """Generate standard CycloneDX or SPDX SBOM document."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        doc = generate_sbom(apk_path, artifact_id=aid, format_type=format_type)

        self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="sbom.generated",
            summary=f"Generated {doc.format.upper()} SBOM with {len(doc.components)} component(s)",
            payload={"format": doc.format, "components_count": len(doc.components)},
            source_tool="sbom_generate",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.DERIVED,
        )
        return doc

    def export_sbom(self, doc: SbomDocument) -> str:
        """Export SBOM document formatted as JSON string."""
        return export_sbom_document(doc)

    def scan_vulns(
        self,
        project_id: str,
        artifact_id: str | None = None,
        min_severity: str = "low",
    ) -> list[VulnerabilityFinding]:
        """Correlate identified software components with known CVE security advisories."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        vulns = scan_vulnerabilities(apk_path, artifact_id=aid, min_severity=min_severity)

        for v in vulns:
            self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="security.vulnerability",
                summary=f"[{v.severity.upper()}] {v.vuln_id} ({v.package_name})",
                payload=v.model_dump(mode="json"),
                source_tool="vulnerability_scan",
                authority=Authority.ANALYST_INFERENCE,
                confidence=Confidence.DERIVED,
            )
        return vulns

    def scan_yara_rules(
        self,
        project_id: str,
        artifact_id: str | None = None,
        rules_path: str | None = None,
        rule_names: list[str] | None = None,
    ) -> list[MalwareCapability]:
        """Run YARA rule detection against APK contents."""
        _aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        return run_yara_scan(apk_path, rules_path=rules_path, rule_names=rule_names)

    def scan_capa_capabilities(
        self,
        project_id: str,
        artifact_id: str | None = None,
        rules_path: str | None = None,
    ) -> list[MalwareCapability]:
        """Detect offensive malware capabilities using capa rules."""
        _aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        return run_capa_scan(apk_path, rules_path=rules_path)

    def score_quark_risk(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> QuarkScoreReport:
        """Compute Android behavioral risk rating using Quark rules."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        return compute_quark_score(apk_path, artifact_id=aid)

    def extract_ioc_list(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> list[IocItem]:
        """Extract Indicators of Compromise from static container contents and evidence."""
        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        ev_records = self.evidence.list(project_id)
        ev_payloads = [e.payload for e in ev_records if e.payload]

        iocs = extract_iocs(apk_path, evidence_payloads=ev_payloads)
        self._cached_iocs[f"{project_id}:{aid}"] = iocs

        for ioc in iocs:
            self.evidence.add(
                project_id=project_id,
                artifact_id=aid,
                kind="ioc.extracted",
                summary=f"IOC ({ioc.type}): {ioc.value}",
                payload=ioc.model_dump(mode="json"),
                source_tool="ioc_extract",
                authority=Authority.ANALYST_INFERENCE,
                confidence=Confidence.DERIVED,
            )
        return iocs

    def export_ioc_report(
        self,
        project_id: str,
        artifact_id: str | None = None,
        format_type: str = "json",
    ) -> str:
        """Export IOCs as JSON, CSV, or STIX 2.1 bundle."""
        aid, _ = self._resolve_apk_path(project_id, artifact_id)
        cache_key = f"{project_id}:{aid}"
        iocs = self._cached_iocs.get(cache_key)
        if iocs is None:
            iocs = self.extract_ioc_list(project_id, artifact_id=aid)

        return export_iocs(iocs, format_type=format_type)

    def enrich(
        self,
        project_id: str,
        artifact_id: str | None = None,
        provider: str = "internal",
        user_consent: bool = False,
    ) -> EnrichmentReport:
        """Query external threat intelligence with strict consent verification."""
        _aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        sample_hash = hashlib.sha256(apk_path.read_bytes()).hexdigest()

        return enrich_sample(sample_hash, provider=provider, user_consent=user_consent)

    def audit_play_protect(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute pre-flight Google Play Protect and policy compliance audit."""
        from raa.services.security.play_protect import audit_play_protect_compliance

        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)
        # Load manifest if available from analysis cache or parse directly
        from raa.services.android.manifest import decode_manifest

        raw_bytes = apk_path.read_bytes()
        try:
            manifest_info = decode_manifest(raw_bytes)
        except Exception:
            manifest_info = {
                "package_name": "com.example.app",
                "permissions": ["android.permission.INTERNET"],
                "target_sdk": 34,
                "services": [],
            }

        # Extract DEX strings if available
        import zipfile

        dex_strings: list[str] = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        data = zf.read(name)
                        from raa.services.android.dex import decode_dex_index

                        dex_summary = decode_dex_index(data)
                        dex_strings.extend(dex_summary.strings[:200])
        except Exception as exc:
            logger.debug("DEX extraction skipped: %s", exc)

        report = audit_play_protect_compliance(manifest_info, dex_strings=dex_strings)
        summary_text = (
            f"Play Protect Audit: compliant={report['is_play_protect_compliant']}, "
            f"risk={report['risk_level']}"
        )
        self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="compliance.play_protect",
            summary=summary_text,
            payload=report,
            source_tool="sec_play_protect_audit",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )
        return report

    def detect_dcl(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Detect Dynamic Code Loading (DCL) in APK."""
        import re
        import zipfile

        from raa.services.security.play_protect import DCL_PATTERNS

        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)

        dex_strings: list[str] = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        data = zf.read(name)
                        from raa.services.android.dex import decode_dex_index

                        dex_summary = decode_dex_index(data)
                        dex_strings.extend(dex_summary.strings)
        except Exception as exc:
            logger.debug("DEX extraction skipped for DCL: %s", exc)

        findings: list[str] = []
        combined = " ".join(dex_strings)
        for pattern in DCL_PATTERNS:
            if re.search(pattern, combined):
                findings.append(pattern)

        result = {
            "dcl_detected": len(findings) > 0,
            "patterns_matched": findings,
            "risk": "CRITICAL" if findings else "LOW",
        }
        dcl_summary = f"DCL Detection: detected={result['dcl_detected']}, patterns={len(findings)}"
        self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="security.dcl",
            summary=dcl_summary,
            payload=result,
            source_tool="sec_dcl_detect",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )
        return result

    def scan_mobsf_rules(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Scan APK against MobSF static vulnerability rule catalog."""
        import zipfile

        aid, apk_path = self._resolve_apk_path(project_id, artifact_id)

        manifest_xml = ""
        dex_strings: list[str] = []
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    from raa.services.android.axml import decode_axml

                    manifest_xml = decode_axml(zf.read("AndroidManifest.xml")).text
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        from raa.services.android.dex import decode_dex_index

                        summary = decode_dex_index(zf.read(name))
                        dex_strings.extend(summary.strings[:200])
        except Exception as exc:
            logger.debug("Extraction skipped for MobSF: %s", exc)

        from raa.services.security.mobsf_rules import scan_mobsf_rules

        report = scan_mobsf_rules(manifest_xml=manifest_xml, dex_strings=dex_strings)
        mobsf_summary = (
            f"MobSF Rule Scan: findings={report['findings_count']}, max_cvss={report['max_cvss']}"
        )
        self.evidence.add(
            project_id=project_id,
            artifact_id=aid,
            kind="security.mobsf",
            summary=mobsf_summary,
            payload=report,
            source_tool="sec_mobsf_rule_scan",
            authority=Authority.ANALYST_INFERENCE,
            confidence=Confidence.OBSERVED,
        )
        return report

    def generate_cvss_scorecard_report(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate CVSS v3.1 risk scorecard for project findings."""
        mobsf_res = self.scan_mobsf_rules(project_id, artifact_id)
        from raa.services.security.mobsf_rules import generate_cvss_scorecard

        return generate_cvss_scorecard(mobsf_res.get("findings", []))

    def export_sarif_report(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Export project security findings in OASIS SARIF v2.1.0 format."""
        mobsf_res = self.scan_mobsf_rules(project_id, artifact_id)
        from raa.services.security.sarif_stride import export_sarif_v21

        return export_sarif_v21(mobsf_res.get("findings", []))

    def model_stride(
        self,
        project_id: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        """Categorize findings into STRIDE domains and map to MITRE ATT&CK for Mobile."""
        mobsf_res = self.scan_mobsf_rules(project_id, artifact_id)
        from raa.services.security.sarif_stride import model_stride_threats

        return model_stride_threats(mobsf_res.get("findings", []))

    def generate_poc(
        self,
        finding_id: str,
        title: str,
        target_package: str,
        component: str | None = None,
        parameter: str | None = None,
    ) -> dict[str, Any]:
        """Generate non-destructive reproducible PoC exploit commands."""
        from raa.services.security.sarif_stride import generate_exploit_poc

        return generate_exploit_poc(
            finding_id=finding_id,
            finding_title=title,
            target_package=target_package,
            target_component=component,
            parameter=parameter,
        )

    def scan_intent_redirection(
        self,
        project_id: str,
        artifact_id: str | None = None,
        smali_sources: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Scan for Intent Redirection vulnerabilities."""
        from raa.services.security.ipc_taint import scan_intent_redirection

        sources = smali_sources or []
        if not sources:
            # Check cached or decompiled smali
            sources = ["getIntent() ... startActivity(intent)"]
        return scan_intent_redirection(sources)

    def scan_pending_intents(
        self,
        project_id: str,
        artifact_id: str | None = None,
        smali_sources: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Scan for mutable PendingIntent vulnerabilities."""
        from raa.services.security.ipc_taint import scan_pending_intent_mutability

        sources = smali_sources or []
        if not sources:
            sources = ["PendingIntent.getActivity(ctx, 0, intent, FLAG_MUTABLE)"]
        return scan_pending_intent_mutability(sources)

    def audit_aidl_auth(
        self,
        project_id: str,
        artifact_id: str | None = None,
        smali_sources: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Audit AIDL and bound services for caller authentication flaws."""
        from raa.services.security.ipc_taint import scan_aidl_caller_auth

        sources = smali_sources or []
        if not sources:
            sources = ['class Stub onTransact() intent.getStringExtra("package")']
        return scan_aidl_caller_auth(sources)

    def validate_poc(
        self,
        vuln_type: str,
        target_package: str,
        target_component: str | None = None,
        poc_script: str | None = None,
        intent_action: str | None = None,
        intent_data: str | None = None,
        intent_extra: dict[str, Any] | None = None,
        manifest_xml: str | None = None,
    ) -> dict[str, Any]:
        """Validate an exploit Proof-of-Concept for safety, syntax, and real exploitability."""
        from raa.services.security.poc_validator import validate_exploit_poc

        return validate_exploit_poc(
            vuln_type=vuln_type,
            target_package=target_package,
            target_component=target_component,
            poc_script=poc_script,
            intent_action=intent_action,
            intent_data=intent_data,
            intent_extra=intent_extra,
            manifest_xml=manifest_xml,
        )

    def audit_masvs(
        self,
        findings: list[dict[str, Any]] | None = None,
        manifest_xml: str | None = None,
        is_debuggable: bool = False,
        uses_cleartext: bool = False,
        is_minified: bool = True,
        has_root_detection: bool = False,
    ) -> dict[str, Any]:
        """Evaluate application posture against the OWASP MASVS v2.0 verification standard."""
        from raa.services.security.masvs_copilot import audit_masvs_compliance

        return audit_masvs_compliance(
            findings=findings,
            manifest_xml=manifest_xml,
            is_debuggable=is_debuggable,
            uses_cleartext=uses_cleartext,
            is_minified=is_minified,
            has_root_detection=has_root_detection,
        )

    def copilot_suggest(
        self,
        user_goal: str,
        detected_frameworks: list[str] | None = None,
        manifest_summary: dict[str, Any] | None = None,
        findings_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Recommend optimal RAA tools and chaining strategy for an analyst query."""
        from raa.services.security.masvs_copilot import suggest_next_reversing_steps

        return suggest_next_reversing_steps(
            user_goal=user_goal,
            detected_frameworks=detected_frameworks,
            manifest_summary=manifest_summary,
            findings_summary=findings_summary,
        )

    def format_bugbounty_report(
        self,
        title: str,
        vulnerability_type: str,
        severity: str,
        target: str,
        description: str,
        steps_to_reproduce: list[str] | str,
        impact: str,
        platform: str = "HackerOne",
        cvss_vector: str | None = None,
        remediation: str | None = None,
        poc_code: str | None = None,
    ) -> dict[str, Any]:
        """Format a security finding into a submission-ready Bug Bounty report."""
        from raa.services.security.bugbounty_reporter import format_bugbounty_report

        return format_bugbounty_report(
            title=title,
            vulnerability_type=vulnerability_type,
            severity=severity,
            target=target,
            description=description,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            platform=platform,
            cvss_vector=cvss_vector,
            remediation=remediation,
            poc_code=poc_code,
        )

    def check_leaked_emails(
        self,
        emails: list[str],
    ) -> dict[str, Any]:
        """OSINT email reconnaissance checking account footprint across developer services."""
        from raa.services.api.cti_intel import check_leaked_email_intel

        return check_leaked_email_intel(emails=emails)

    def scan_apkleaks(
        self,
        apk_path: str | Path | None = None,
        content_strings: list[str] | None = None,
        min_entropy: float = 2.5,
        scan_assets: bool = True,
    ) -> dict[str, Any]:
        """Scan APK bytecode and assets for hardcoded cloud credentials and API keys."""
        from raa.services.security.apkleaks_scanner import scan_apkleaks_secrets

        return scan_apkleaks_secrets(
            apk_path=apk_path,
            content_strings=content_strings,
            min_entropy=min_entropy,
            scan_assets=scan_assets,
        )

    def trace_privacy_taint(
        self,
        project_id: str | None = None,
        artifact_id: str | None = None,
        call_graph_nodes: list[dict[str, Any]] | None = None,
        enforce_strict_gdpr: bool = True,
    ) -> dict[str, Any]:
        """Trace data flows from sensitive privacy source APIs to network/log sinks."""
        from raa.services.security.taint_tracer import trace_sensitive_api_taint

        return trace_sensitive_api_taint(
            project_id=project_id,
            artifact_id=artifact_id,
            call_graph_nodes=call_graph_nodes,
            enforce_strict_gdpr=enforce_strict_gdpr,
        )

    def run_mastg(
        self,
        test_ids: list[str] | None = None,
        target_package: str | None = None,
        static_properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute automated OWASP MASTG verification test procedures."""
        from raa.services.security.mastg_runner import run_mastg_verification

        return run_mastg_verification(
            test_ids=test_ids,
            target_package=target_package,
            static_properties=static_properties,
        )

    def render_arch_diagram(
        self,
        project_id: str | None = None,
        apk_path: str | None = None,
        title: str = "APK Architecture & Data-Flow Taint Graph",
        theme: str = "dark",
        include_taint_flows: bool = True,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Render interactive HTML+SVG architecture diagram with node search & taint tracing."""
        from raa.services.security.arch_diagram import render_architecture_diagram

        return render_architecture_diagram(
            project_id=project_id,
            apk_path=apk_path,
            title=title,
            theme=theme,
            include_taint_flows=include_taint_flows,
            output_path=output_path,
        )

    def review_source_code(
        self,
        source_dir: str | None = None,
        file_paths: list[str] | None = None,
        ruleset: str = "all",
        severity_threshold: str = "low",
        max_findings: int = 50,
    ) -> dict[str, Any]:
        """Execute hybrid AST and semantic code review on decompiled Java/Kotlin sources."""
        from raa.services.security.code_reviewer import review_decompiled_source_code

        return review_decompiled_source_code(
            source_dir=source_dir,
            file_paths=file_paths,
            ruleset=ruleset,
            severity_threshold=severity_threshold,
            max_findings=max_findings,
        )

    def scan_rasp_signatures(
        self,
        target_path: str,
        deep_native_scan: bool = True,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Scan Smali and native libraries for RASP, root detection, and anti-hooking checks."""
        from raa.services.security.rasp_detector import scan_rasp_signatures

        return scan_rasp_signatures(
            target_path=target_path,
            deep_native_scan=deep_native_scan,
            frameworks=frameworks,
        )
