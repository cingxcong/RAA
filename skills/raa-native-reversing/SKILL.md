---
name: raa-native-reversing
description: Analyze native C/C++ shared libraries, resolve JNI method bindings, extract symbols, and inspect Unity Il2Cpp metadata.
version: 1.0.0
tools: [native_get_symbols, native_analyze_library, jni_map, unity_dump_metadata]
---

# Native Library & JNI Audit

Audit native ELF shared libraries (`.so`) and Unity Il2Cpp metadata.

## Workflow
1. Enumerate dynamic symbols, exports, and imports using `native_get_symbols`.
2. Inspect JNI native bindings and recover method signatures via `native_analyze_library` or `jni_map`.
3. If Unity game, recover C# class prototypes and offsets from `global-metadata.dat` using `unity_dump_metadata`.
