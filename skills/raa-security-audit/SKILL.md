---
name: raa-security-audit
description: Comprehensive security and privacy vulnerability assessment against OWASP MASVS and Android best practices.
version: 1.0.0
tools: [security_scan_static, privacy_data_flows, quark_score]
---

# OWASP MASVS & Privacy Audit

Scan Android applications for security vulnerabilities, cryptographic flaws, privacy leaks, and malware scores.

## Workflow
1. Execute static security rules across manifest and bytecode using `security_scan_static`.
2. Trace sensitive PII, device identifiers, and location flows with `privacy_data_flows`.
3. Score Android malware behavior and security posture using `quark_score`.
