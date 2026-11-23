# GitHub Protected Branch & Ruleset Configuration Guide

## Purpose
The `main` branch of `uditrajput/RAA` contains production-ready code. To prevent unreviewed, untested, broken, or insecure code from being committed or merged, branch protection rules must be configured in GitHub repository settings.

> [!NOTE]
> GitHub branch protection rules and rulesets cannot be applied via workflow YAML files directly; they must be configured by an administrator in the GitHub Repository Settings.

---

## Recommended Ruleset Configuration

Navigate to: **Settings** -> **Rules** -> **Rulesets** -> **New ruleset** (or **Branches** -> **Branch protection rules**).

Target branch: `main` (Branch pattern: `main`)

### 1. Protect Branches & Merge Restrictions
- [x] **Restrict deletions:** Prevent accidental deletion of `main`.
- [x] **Block force pushes:** Prevent `git push --force` rewriting history.
- [x] **Require linear history:** Enforce rebase or squash merging to keep history clean.

### 2. Pull Request Protections
- [x] **Require a pull request before merging:**
  - **Required approvals:** Minimum `1` approval.
  - [x] **Dismiss stale pull request approvals when new commits are pushed.**
  - [x] **Require review from Code Owners** (via `.github/CODEOWNERS`).
  - [x] **Require approval of the most recent reviewable push.**
  - [x] **Require conversation resolution before merging.**

### 3. Required Status Checks
Enforce that branches must be up to date before merging and require all of the following stable status check jobs to pass:

| Check Name | Source Workflow | Mandatory Gate |
| :--- | :--- | :---: |
| `lint-and-format` | `.github/workflows/ci.yml` | Yes |
| `build` | `.github/workflows/ci.yml` | Yes |
| `unit-tests` | `.github/workflows/ci.yml` | Yes |
| `integration-tests` | `.github/workflows/ci.yml` | Yes |
| `mcp-tests` | `.github/workflows/mcp-tests.yml` | Yes |
| `android-engine-tests` | `.github/workflows/android-engines.yml` | Yes |
| `ui-tests` | `.github/workflows/ui-tests.yml` | Yes |
| `secret-detection` | `.github/workflows/security.yml` | Yes |
| `dependency-audit` | `.github/workflows/security.yml` | Yes |
| `security-tests` | `.github/workflows/security.yml` | Yes |
| `documentation-check` | `.github/workflows/documentation.yml` | Yes |
| `codeql-analysis` | `.github/workflows/codeql.yml` | Yes |

---

## Step-by-Step GitHub Setup Instructions

1. Go to repository: `https://github.com/uditrajput/RAA/settings/branches`.
2. Click **Add branch protection rule** (or use **Rulesets** -> **New branch ruleset**).
3. Set **Branch name pattern** to `main`.
4. Enable **Require a pull request before merging** with:
   - Required approvals: `1`
   - Dismiss stale approvals when new commits are pushed: Checked
   - Require review from Code Owners: Checked
   - Require conversation resolution: Checked
5. Enable **Require status checks to pass before merging**:
   - Check **Require branches to be up to date before merging**.
   - Search and select each check from the table above:
     - `lint-and-format`
     - `build`
     - `unit-tests`
     - `integration-tests`
     - `mcp-tests`
     - `android-engine-tests`
     - `ui-tests`
     - `secret-detection`
     - `dependency-audit`
     - `security-tests`
     - `documentation-check`
6. Check **Do not allow bypassing the above settings** for administrators to guarantee absolute policy enforcement.
7. Click **Create** / **Save changes**.
