---
name: raa-apk-triage
description: Fast APK triage, package inventory, framework detection, and attack surface assessment.
version: 1.0.0
tools: [capabilities_get, project_create, artifact_ingest, analysis_start, analysis_get_status, analysis_get_report, android_get_manifest, android_get_exported_surface, framework_list_detected, packer_detect]
---

# Fast APK Triage & Discovery

Use this skill when a new APK is introduced to obtain a rapid inventory of components, architecture, and packer defenses.

## Preconditions
- Authorized APK artifact path.

## Workflow
1. Ingest APK artifact with `artifact_ingest`.
2. Inspect manifest with `android_get_manifest` and `android_get_exported_surface`.
3. Detect runtime frameworks with `framework_list_detected`.
4. Check packer and protector signatures with `packer_detect`.
