# Security Scanning & Vulnerability Management Policy

## Security Framework Overview
RAA incorporates continuous automated security scanning across the software development lifecycle to prevent vulnerabilities, insecure dependencies, hardcoded secrets, and supply chain attacks.

---

## 1. Static Application Security Testing (SAST)
- **Engine:** Semgrep & GitHub CodeQL
- **Coverage:**
  - Automated scanning for command injections (`S603`, `S607` subprocess isolation).
  - Unsafe deserialization and arbitrary file writes.
  - Path traversal and arbitrary extraction attacks (`zipfile` slip protection).
  - Weak cryptographic primitives.
- **Workflow:** `.github/workflows/security.yml` and `.github/workflows/codeql.yml`

---

## 2. Secret Detection
- **Engine:** Gitleaks
- **Scope:** Full Git commit history (`fetch-depth: 0`) on pull requests and pushes.
- **Detection Targets:**
  - API keys (OpenAI, Anthropic, Gemini, AWS, GCP).
  - Private keys (`.pem`, `.key`, `id_rsa`).
  - GitHub Personal Access Tokens and OAuth credentials.
  - Hardcoded tokens in configuration and test fixtures.
- **Remediation:** If Gitleaks flags a secret, the CI run immediately fails. Secrets must be revoked immediately; simply overwriting the file in a subsequent commit is disallowed.

---

## 3. Dependency Vulnerability Auditing
- **Engine:** `pip-audit`
- **Advisory Sources:** PyPA Advisory Database, OSV (Open Source Vulnerabilities).
- **Policy:**
  - PRs introducing dependencies with known HIGH or CRITICAL CVEs will be blocked.
  - Regular automated weekly scans flag newly disclosed advisories.

---

## 4. Software Bill of Materials (SBOM) & Supply Chain Security
- **Engine:** `raa admin sbom`
- **Output Standards:** CycloneDX v1.5 JSON & SPDX 2.3 JSON.
- **Artifact Signing & Digest:** All release packages are hashed with SHA256 (`SHA256SUMS`) and signed before distribution.
- **Workflow Action Pinning:** All third-party GitHub Actions must be pinned to immutable 40-character commit SHAs with semantic version comments.
