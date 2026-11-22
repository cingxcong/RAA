---
name: android-triage
description: Use when a new APK, AAB, APKS or XAPK needs a safe first-pass inventory, framework and packer check, and an evidence-backed report.
version: 1.5.0
compatible_registry: "0.1.x"
tools: [capabilities_get, project_create, artifact_ingest, analysis_start, analysis_get_status, analysis_get_report, android_get_manifest, android_get_exported_surface, android_get_network_config, android_list_resources, android_get_resource, source_search, source_get_class, source_get_method, source_find_references, source_get_callers, source_get_callees, source_get_smali, framework_list_detected, packer_detect, evidence_list, report_generate, recipe_run]
---

# Android triage

Use this skill for a first pass on an artifact whose provenance and content are
not yet known. The goal is a bounded, reproducible inventory, not a claim that
the app has been fully reverse engineered.

## Preconditions

- Confirm you are authorized to analyze the artifact.
- Keep the artifact inside an allowed input root. `artifact_ingest` rejects
  arbitrary paths by design.
- Do not install, execute or contact the app. This workflow is static only.

## Fast path

Call `recipe_run` with recipe `triage`:

```json
{
  "recipe_id": "triage",
  "arguments": {"project_id": "prj_...", "path": "C:/samples/app.apk"}
}
```

The recipe ingests the artifact, runs the built-in static inspection, waits for
the job and returns the report plus evidence identifiers. Use the explicit
workflow below when you need control over stages or want to inspect each step.

## Explicit workflow

1. Call `capabilities_get`. Check the active profile, implemented tools and
   limitations. Do not assume a planned tool exists.
2. Call `project_create` with a descriptive name. A project is the scope
   boundary for evidence and policy.
3. Call `artifact_ingest` with the project ID and path. Record the artifact ID,
   SHA-256, size and detected container type from the result.
4. Call `analysis_start` with the artifact ID. The default stages are
   `container`, `inventory`, `manifest`, `resources`, `code`, `frameworks` and
   `signatures`.
5. Poll `analysis_get_status` until the job is `completed`, `failed` or
   `cancelled`. Back off between polls; do not spin.
6. Call `analysis_get_report` with the job ID. Read `coverage.limitations`
   before summarizing.
7. Call `android_get_manifest`, `android_get_exported_surface` and
   `android_get_network_config` for package details, exported components and
   transport flags. Treat exported status as a manifest declaration, not proof
   of runtime reachability.
8. Call `android_list_resources` to inventory strings, layouts, styles and
   other values. Call `android_get_resource` by name or `0x...` ID when a
   specific value or file reference matters. References stay unresolved unless
   a later tool resolves them.
9. Call `source_search` to find classes, methods, fields and strings. Call
   `source_get_class` for hierarchy, source-file metadata and declared members.
   Call `source_get_method` for method metadata and bounded reference
   summaries; add `--include-source` only when the user explicitly accepts
   external engine execution and JADX is installed. Call
   `source_find_references`, `source_get_callers` and `source_get_callees`
   only when a bounded opcode scan is needed. Call `source_get_smali` only
   when Apktool execution is enabled. Label all of these as bounded or
   engine-derived evidence, not complete source or a complete call graph.
10. Call `framework_list_detected` and `packer_detect` to inspect those findings
    directly. Packer output is a filename heuristic in this build.
11. Call `evidence_list` and read the evidence for each claim you intend to
    repeat. Prefer `observed` evidence over `inferred` evidence.
12. Call `report_generate` with `format: "markdown"` or `"json"` to write the
    report inside the project export directory.

## Evidence rules

- Every material claim must cite an evidence ID from the report or
  `evidence_list`.
- Distinguish original container material, derived findings and inferred
  hypotheses. The report's `authority`, `representation` and `confidence`
  fields exist for this reason.
- A framework marker proves that files are present, not that the app was built
  with that framework alone. Report multiple frameworks when multiple markers
  exist.
- A packer marker is a suspicion. Say "marker detected" rather than "packed".
- If a stage failed or was skipped, report it. Do not fill gaps with guesses.
- Resource values describe the shipped `resources.arsc`. References are IDs,
  file paths are strings, and neither is proof of runtime use.
- DEX index results describe declared classes and members in root-level
  `classes*.dex` files. They do not prove that code runs. Reference, caller and
  callee tools scan declared bytecode under explicit budgets; the scan can be
  partial and is not decompilation or a complete call graph.

## Stop conditions

Stop and ask for authorization or better input when:

- The path is rejected by the input-root policy.
- The artifact is not a readable APK-family ZIP container.
- Limits block ingestion or inspection.
- The report has no DEX files, the manifest could not be decoded, or most
  entries are encrypted.

## Output contract

Return a short summary with: artifact hash, container type, package name, SDK
range, DEX count, class/method/field counts, ABI list, signature status,
exported-component and deep-link counts, cleartext/debuggable flags, resource
counts by type, detected frameworks, packer suspicions, findings, evidence IDs
and explicit limitations. Link the exported report path when one was written.
