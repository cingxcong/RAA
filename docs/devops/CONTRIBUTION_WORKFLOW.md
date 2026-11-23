# Developer & AI Agent Contribution Workflow

## Guidelines for Developers and Autonomous AI Agents

RAA welcomes contributions from human software engineers, security researchers, and autonomous AI coding agents (Claude Code, Antigravity, Cursor, Codex).

To maintain absolute stability and security, **all contributors must strictly abide by this workflow.** Direct pushes to `main` are strictly blocked.

---

## 1. Branch Naming Conventions

All work must be conducted on dedicated working branches branched from `main`:

| Branch Prefix | Purpose | Example |
| :--- | :--- | :--- |
| `feature/` | New tools, reverse engineering capabilities, or UI features | `feature/dex-constant-propagation` |
| `bugfix/` | Bug fixes, stability patches, or security mitigations | `bugfix/raa-stability-evolution` |
| `docs/` | Documentation additions or updates | `docs/devops-enhancements` |
| `chore/` | Dependency updates, tooling or CI adjustments | `chore/upgrade-ruff-rules` |

---

## 2. Local Verification Checklist

Before submitting a Pull Request, run the local check suite:

```powershell
# Run format, lint, mypy and test suite
.\scripts\check.ps1
```

Or execute individually:
```bash
ruff format --check src tests
ruff check src tests
pytest
```

---

## 3. Contribution Rules for New Components

### A. Adding a New MCP Tool
1. **Tool Registry:** Tool must be registered in the capability registry with explicit metadata, lowercase name, descriptive docstring, and valid Pydantic input model.
2. **Profile & Scopes:** Every tool must be categorized into appropriate profiles (`minimal`, `core`, `dynamic`, `ui`, `api`, `admin`, `full`) and require appropriate scopes (`project.read`, `project.write`, `android.patch`, etc.).
3. **Automated Tests:** You MUST include automated unit and integration tests in `tests/`. Verify using:
   ```bash
   pytest tests/test_production_e2e.py tests/test_mcp.py
   ```

### B. Adding a New Agent Skill
1. Place skill in `skills/<skill-name>/SKILL.md`.
2. Ensure valid YAML frontmatter containing `name`, `version`, and `description`.
3. Provide referenced markdown checklists or scripts.
4. Verify discovery passes:
   ```bash
   pytest tests/test_skills.py
   ```

### C. Adding an Android Reversing Engine Integration
1. Extend `EngineSpec` and add an adapter in `src/raa/services/engine_adapters.py`.
2. Do NOT bundle proprietary or untrusted binaries into Git.
3. Test using synthetic fixtures from `tests/conftest.py`.

---

## 4. Pull Request Submission & Merge Lifecycle

1. Push your branch to `origin`:
   ```bash
   git push origin feature/my-feature
   ```
2. Open a Pull Request targeting `main`.
3. CI/CD checks will trigger automatically:
   - `CI` (Build, Lint, Unit, Integration)
   - `MCP Validation`
   - `Android Engines`
   - `UI Reconstruction`
   - `Security` (Gitleaks, pip-audit, Semgrep)
   - `CodeQL`
   - `Documentation`
4. Request review from Code Owners.
5. Once all required checks are green and reviews approved, squash or rebase merge into `main`.
