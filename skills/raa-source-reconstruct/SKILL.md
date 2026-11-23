---
name: raa-source-reconstruct
description: Reconstruct and deobfuscate Java/Kotlin source code and call hierarchies from DEX bytecode.
version: 1.0.0
tools: [source_search, source_get_class, source_get_method, source_find_references, source_get_callers, source_get_callees, deobfuscate]
---

# Source Code Reconstruction

Reconstruct clean Java/Kotlin classes with persistent rename maps and call graph navigation.

## Workflow
1. Locate target classes using `source_search`.
2. Retrieve class definition and bytecode using `source_get_class`.
3. Traverse call relationships using `source_get_callers` and `source_get_callees`.
4. Suggest persistent deobfuscation renames via `deobfuscate`.
