"""Static MASVS/MASTG security checks scanner for Android applications."""

from __future__ import annotations

import re
import uuid
import zipfile
from pathlib import Path

from raa.domain.security import MasvsCategory, SecurityFinding

# Regex patterns for static code and manifest checks
_ECB_MODE_RE = re.compile(r'Cipher\.getInstance\(\s*"(?:AES|DES|DESede)/ECB/', re.IGNORECASE)
_WEAK_HASH_RE = re.compile(
    r'MessageDigest\.getInstance\(\s*"(?:MD5|SHA-1|MD4)"\s*\)', re.IGNORECASE
)
_TRUST_ALL_RE = re.compile(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}", re.DOTALL)
_CLEARTEXT_TRAFFIC_RE = re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']')
_DEBUGGABLE_RE = re.compile(r'android:debuggable\s*=\s*["\']true["\']')
_ALLOW_BACKUP_RE = re.compile(r'android:allowBackup\s*=\s*["\']true["\']')
_EXPORTED_COMPONENT_RE = re.compile(
    r'<(?:activity|service|receiver|provider)[^>]+android:exported\s*=\s*["\']true["\'][^>]*>',
    re.IGNORECASE,
)
_DEX_CLASS_LOADER_RE = re.compile(r"new\s+DexClassLoader\s*\(", re.IGNORECASE)


def scan_static_security(apk_path: Path, artifact_id: str) -> list[SecurityFinding]:
    """Run static security rules against APK manifest and code bytecode/strings."""
    findings: list[SecurityFinding] = []
    if not apk_path.is_file():
        return findings

    manifest_xml = ""
    dex_strings: list[str] = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if name == "AndroidManifest.xml":
                manifest_xml = zf.read(name).decode("latin1", errors="replace")
            elif name.endswith(".dex"):
                dex_data = zf.read(name)
                # Extract ASCII and UTF-8 strings
                dex_text = dex_data.decode("latin1", errors="replace")
                dex_strings.append(dex_text)

    # 1. Manifest: Debuggable
    if _DEBUGGABLE_RE.search(manifest_xml):
        findings.append(
            SecurityFinding(
                finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                artifact_id=artifact_id,
                rule_id="RULE-PLATFORM-DEBUGGABLE",
                title="Application is Marked as Debuggable",
                severity="high",
                masvs_id=MasvsCategory.PLATFORM.value,
                cwe_id="CWE-215",
                description=(
                    "The android:debuggable attribute is set to true in AndroidManifest.xml."
                ),
                rationale=(
                    "Debuggable applications allow arbitrary code execution, memory inspection, "
                    "and runtime manipulation via JDWP."
                ),
                remediation="Set android:debuggable='false' in release application variants.",
                location="AndroidManifest.xml",
            )
        )

    # 2. Manifest: Allow Backup
    if _ALLOW_BACKUP_RE.search(manifest_xml):
        findings.append(
            SecurityFinding(
                finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                artifact_id=artifact_id,
                rule_id="RULE-STORAGE-BACKUP",
                title="Application Data Backup Enabled",
                severity="medium",
                masvs_id=MasvsCategory.STORAGE.value,
                cwe_id="CWE-312",
                description=(
                    "The android:allowBackup attribute is set to true in AndroidManifest.xml."
                ),
                rationale=(
                    "Enabling application backup permits extracting sensitive app data via "
                    "adb backup."
                ),
                remediation=(
                    "Explicitly set android:allowBackup='false' unless backup is required "
                    "with custom rules."
                ),
                location="AndroidManifest.xml",
            )
        )

    # 3. Manifest: Uses Cleartext Traffic
    if _CLEARTEXT_TRAFFIC_RE.search(manifest_xml):
        findings.append(
            SecurityFinding(
                finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                artifact_id=artifact_id,
                rule_id="RULE-NETWORK-CLEARTEXT",
                title="Cleartext HTTP Traffic Permitted",
                severity="high",
                masvs_id=MasvsCategory.NETWORK.value,
                cwe_id="CWE-319",
                description="The android:usesCleartextTraffic attribute is set to true.",
                rationale=(
                    "Allowing unencrypted cleartext HTTP traffic permits network eavesdropping "
                    "and MitM attacks."
                ),
                remediation=(
                    "Enforce HTTPS across all application traffic via Network Security "
                    "Configuration."
                ),
                location="AndroidManifest.xml",
            )
        )

    # 4. Manifest: Exported Components
    for exp_match in _EXPORTED_COMPONENT_RE.finditer(manifest_xml):
        tag = exp_match.group(0)
        if 'android:permission="' not in tag:
            findings.append(
                SecurityFinding(
                    finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                    artifact_id=artifact_id,
                    rule_id="RULE-PLATFORM-EXPORTED",
                    title="Exported Component Without Permission Gate",
                    severity="medium",
                    masvs_id=MasvsCategory.PLATFORM.value,
                    cwe_id="CWE-276",
                    description=(
                        f"Exported component declared without permission guard: {tag[:80]}..."
                    ),
                    rationale=(
                        "Unprotected exported components can be triggered by any malicious "
                        "app on the device."
                    ),
                    remediation=(
                        "Set android:exported='false' or restrict access with a custom signature "
                        "permission."
                    ),
                    location="AndroidManifest.xml",
                )
            )
            break

    # 5. Bytecode / DEX Checks
    for idx, d_text in enumerate(dex_strings):
        loc = f"classes{'' if idx == 0 else str(idx + 1)}.dex"

        if _ECB_MODE_RE.search(d_text):
            findings.append(
                SecurityFinding(
                    finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                    artifact_id=artifact_id,
                    rule_id="RULE-CRYPTO-ECB",
                    title="Insecure Cipher Mode (ECB) Detected",
                    severity="high",
                    masvs_id=MasvsCategory.CRYPTO.value,
                    cwe_id="CWE-327",
                    description="Electronic Codebook (ECB) cipher mode observed in bytecode.",
                    rationale=(
                        "ECB mode produces identical ciphertext for identical plaintext blocks, "
                        "leaking structural data."
                    ),
                    remediation=(
                        "Use authenticated encryption modes such as AES-GCM with unique "
                        "initialization vectors."
                    ),
                    location=loc,
                )
            )

        if _WEAK_HASH_RE.search(d_text):
            findings.append(
                SecurityFinding(
                    finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                    artifact_id=artifact_id,
                    rule_id="RULE-CRYPTO-WEAK-HASH",
                    title="Broken Cryptographic Hash Algorithm in Use",
                    severity="medium",
                    masvs_id=MasvsCategory.CRYPTO.value,
                    cwe_id="CWE-328",
                    description="References to MD5 or SHA-1 MessageDigest instances found.",
                    rationale=(
                        "MD5 and SHA-1 suffer from collision attacks and must not be used for "
                        "cryptographic integrity or signatures."
                    ),
                    remediation="Migrate to SHA-256 or SHA-512 algorithms.",
                    location=loc,
                )
            )

        if _TRUST_ALL_RE.search(d_text):
            findings.append(
                SecurityFinding(
                    finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                    artifact_id=artifact_id,
                    rule_id="RULE-NETWORK-TRUST-ALL",
                    title="Insecure TrustManager (Accepts All Certificates)",
                    severity="critical",
                    masvs_id=MasvsCategory.NETWORK.value,
                    cwe_id="CWE-295",
                    description=(
                        "An empty checkServerTrusted method was identified in TrustManager "
                        "bytecode."
                    ),
                    rationale=(
                        "Disabling TLS certificate validation allows arbitrary attackers to "
                        "intercept and decrypt application traffic."
                    ),
                    remediation=(
                        "Remove custom TrustManagers and rely on standard Android CA trust "
                        "stores or cert pinning."
                    ),
                    location=loc,
                )
            )

        if _DEX_CLASS_LOADER_RE.search(d_text):
            findings.append(
                SecurityFinding(
                    finding_id=f"sec_{uuid.uuid4().hex[:10]}",
                    artifact_id=artifact_id,
                    rule_id="RULE-CODE-DCL",
                    title="Dynamic Code Loading (DexClassLoader)",
                    severity="medium",
                    masvs_id=MasvsCategory.CODE.value,
                    cwe_id="CWE-94",
                    description="Instantiation of DexClassLoader observed in bytecode.",
                    rationale=(
                        "Dynamic code loading from writable storage or network downloads "
                        "allows code injection and tampering."
                    ),
                    remediation=(
                        "Verify cryptographic signatures before executing dynamically loaded code, "
                        "or package code statically."
                    ),
                    location=loc,
                )
            )

    return findings
