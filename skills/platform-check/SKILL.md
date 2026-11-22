---
name: platform-check
description: Use before a session to verify RAA capabilities, profile, scopes, engine availability and workspace health.
version: 1.0.0
compatible_registry: "0.1.x"
tools: [capabilities_get, admin_doctor, admin_policy_get, admin_engine_list, admin_license_report]
---

# Platform check

Use this skill at the start of a new environment, after changing profiles or
scopes, and before promising an analysis that depends on an external engine.

## Workflow

1. Call `capabilities_get`. Record the server version, protocol baseline,
   implemented tool count, active profile, surfaces and planned extensions.
2. Call `admin_doctor`. Confirm the workspace is writable, the database responds
   and the MCP SDK version is available.
3. Call `admin_policy_get` with no project for the global scope catalogue, or
   with a project ID for that project's effective scopes.
4. For toolchain questions, switch to the `admin` or `full` profile and call
   `admin_engine_list`. Treat `installed: true` as "found on PATH or importable",
   not as a verified working analysis.
5. Call `admin_license_report` before proposing a bundled distribution. It is an
   inventory, not legal advice.

## Interpretation

- `minimal` exposes 12 tools: the short triage path.
- `core` exposes the static workflow, diagnostics and recipes.
- `full` exposes every implemented tool.
- `dynamic`, `api` and `ui` profiles track their workstreams as those tools are
  implemented; do not assume they contain every corresponding tool today.
- A profile never grants scopes. A project must still grant the scopes that a
  tool requires.

## Stop conditions

- Workspace is not writable.
- Database check fails.
- The requested tool is not in the active profile or is not implemented.
- The task depends on an engine that is not installed. Say so and offer a safe
  static fallback instead of pretending the engine ran.
