# Release v0.1.0–v0.9.0 — Phases 1–10: Foundations, AAIR Graph, UI Redesign & API Studio

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v0.1.0–v0.9.0  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: October–November 2026 | Tools: 42–144 | Tests: 100–280 Passing*

---

## Overview & Highlights


- **Phase 1–2 (Static Core):** JADX Tier-1 decompilation, pure-Python Dalvik disassembly, binary AXML manifest decoding, resource table resolution (`resources.arsc`).
- **Phase 3 (Frameworks):** Framework adapters for Flutter Dart, React Native Hermes, Unity IL2CPP, and .NET Xamarin.
- **Phase 4 (UI Reconstruction):** ADB view hierarchy dumps, UIAutomator node parsing, Jetpack Compose and React Native code synthesis.
- **Phase 5 (AAIR Graph):** Android Application Intermediate Representation (AAIR) connecting components, classes, endpoints, and database schemas.
- **Phase 6 (Dynamic Instrumentation):** Frida script injection, process hooking, keystore secret dumping, and dynamic method tracing.
- **Phase 7 (API Studio):** Automatic HTTP endpoint clustering, parameter inferencing, OpenAPI 3.1 specification synthesis, and Postman collection generation.
- **Phase 8–10 (Security & Unpacking):** Commercial packer detection, payload dumping, taint analysis, and automated agent skill orchestration.

---

## Tool Progression Across Capability Profiles

| Profile | Target Audience | v0.1.0 | v1.0.0 | v1.3.0 | v1.8.0 | v2.0.0 (Current) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`minimal`** | Small local LLMs, triage | 12 | 12 | 12 | 12 | **12** |
| **`core`** | Default agents, static reversing | 40 | 94 | 104 | 118 | **135** |
| **`dynamic`**| Runtime ADB, Frida, network | 0 | 110 | 124 | 154 | **169** |
| **`api`** | API reverse engineering | 0 | 111 | 117 | 134 | **139** |
| **`ui`** | UI reconstruction & redesign | 0 | 110 | 118 | 134 | **140** |
| **`admin`** | Compliance, SBOM, telemetry | 4 | 14 | 14 | 19 | **19** |
| **`full`** | Frontier agents, human analysts | 42 | 151 | 170 | 197 | **244** |

---

## Verification & Upgrade Guide

### Upgrading to v2.0.0
To upgrade your local installation to `v2.0.0`:

```bash
# Pull latest repository updates and reinstall editable package
pip install -e . --no-deps

# Verify installation health and catalogued tools
raa doctor
```

Expected output:
```
                               RAA doctor                               
┌────────────────────┬─────────────────────────────────────────────────┐
│ Check              │ Value                                           │
├────────────────────┼─────────────────────────────────────────────────┤
│ ok                 │ True                                            │
│ profile            │ core                                            │
│ implemented_tools  │ 244                                             │
│ mcp_sdk            │ 2.3.0                                           │
│ database_ok        │ True                                            │
│ workspace_writable │ True                                            │
└────────────────────┴─────────────────────────────────────────────────┘
```

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
