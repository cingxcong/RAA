# Evidence checklist

Use this list before repeating any claim from a triage report.

| Question | Where to look |
|---|---|
| What exactly was hashed? | `artifact_ingest` evidence kind `artifact.hash` |
| How was the container classified? | evidence kind `artifact.container` |
| Which DEX and native files exist? | report `dex_files`, `native_libraries`; evidence `code.dex_inventory`, `native.library_inventory` |
| What does the manifest declare? | report `manifest`; evidence `manifest.parsed` |
| What resources are present and what are their values? | `android_list_resources`, `android_get_resource`; evidence `resources.inventory` |
| Which classes and members are declared? | report `dex_summary`; `source_search`, `source_get_class`; evidence `code.index` |
| Which symbols are referenced in bytecode? | `source_find_references`, `source_get_callers`, `source_get_callees`; report `coverage.limitations`; evidence `code.index` |
| Which engine output was used? | `source_get_method`, `source_get_smali`; engine id, operation, output file reference, duration and exit code |
| Which components are exported? | `android_get_exported_surface`; report `manifest.components` |
| Is cleartext traffic or debugging enabled? | `android_get_network_config`; report `manifest.application` |
| What signing material exists? | report `signature`; evidence `signature.inventory` |
| Which frameworks were detected? | report `frameworks`; evidence `framework.detection` |
| Which packer markers were detected? | report `packers`; evidence `packer.heuristic` |
| What was not examined? | report `coverage.limitations` |

## Language to avoid

- "The app is packed" when only a filename marker exists.
- "The app uses Flutter" when only an unrelated `libflutter.so` is present.
- "The source code does X" when no code was decompiled.
- "The complete call graph shows X" when only bounded direct references were scanned.
- "No vulnerabilities" when no vulnerability scan was run.

## Language to prefer

- "The container includes two DEX files and an arm64-v8a Flutter runtime."
- "Packer markers were detected; APKiD confirmation was not run."
- "The manifest declares no exported components; runtime reachability and
  permission enforcement were not tested."
- "Cleartext traffic is enabled in the manifest; network security config XML
  was not decoded in this build."
