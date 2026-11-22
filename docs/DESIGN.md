# RAA System Design & Specification

<p align="center">
  <img src="../images/raa.png" width="120" alt="RAA Logo">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Current_Release-v2.0.0_Production-success?style=flat-square" alt="Current Release: v2.0.0 Production">
  <img src="https://img.shields.io/badge/Total_Tools-244_Implemented-blue?style=flat-square" alt="Total Tools: 244 Implemented">
  <img src="https://img.shields.io/badge/Tests-437_Passing-brightgreen?style=flat-square" alt="Tests: 437 Passing">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Protocol-2026--07--28-informational?style=flat-square" alt="Protocol: 2026-07-28">
  <img src="https://img.shields.io/badge/License-MIT-4c1?style=flat-square" alt="License: MIT">
</p>

This document details the engineering specifications, domain models, truth hierarchy, design systems, and protocol contracts implemented across **RAA (Reverse Android Anything)**.

---

## 1. Evidence-First Truth Model

RAA enforces a strict data provenance hierarchy to prevent AI hallucinations and ensure that reverse-engineered facts are separated from inferences.

```mermaid
flowchart TD
    Raw["Raw Container Bytes (APK, DEX, AXML, ELF, ARSC)"] --> Obs["Level 1: Observations (Authority: OBSERVED_BYTECODE)"]
    Obs --> Der["Level 2: Derivations (Authority: DERIVED_AST / DERIVED_METRIC)"]
    Der --> Inf["Level 3: Inferences (Authority: ANALYST_INFERENCE / AI_PREDICTION)"]
    
    style Obs fill:#2E7D32,stroke:#1B5E20,color:#fff
    style Der fill:#0277BD,stroke:#01579B,color:#fff
    style Inf fill:#E65100,stroke:#BF360C,color:#fff
```

### Authority Levels

| Authority Level | Definition | Example Artifacts |
| :--- | :--- | :--- |
| **`OBSERVED_BYTECODE`** | Direct raw extractions from binary streams without semantic interpretation. | Dalvik opcodes, ELF dynamic symbol strings, AXML attribute integers, certificate fingerprints. |
| **`DERIVED_AST`** | Deterministically synthesized representations produced by deterministic compilers/engines. | Control-flow graphs (CFGs), Java ASTs, OpenAPI parameterized paths, decompiled Smali blocks. |
| **`ANALYST_INFERENCE`** | Heuristic, statistical, or AI-synthesised deductions. Must carry confidence ratings. | Inferred REST entity models, predicted screen transitions, deobfuscated variable name suggestions. |

Every piece of evidence stored in the SQLite `evidence` repository records:
- `id`: Opaque, prefixed identifier (`evi_...`).
- `artifact_id`: Source container hash reference.
- `authority`: One of the formal authority tiers.
- `confidence`: Decimal score between `0.0` and `1.0`.
- `representation`: Concrete data structure (JSON, AST, text).

---

## 2. Policy & Security Scope System

RAA's security model is **fail-closed**: access is denied unless an operation is explicitly permitted by granted scopes.

### Scope Taxonomy

```mermaid
graph TD
    Safe["Safe Baseline Scopes (Default)"] --> PR["project.read"]
    Safe --> SR["static.read"]
    Safe --> EW["export.write"]
    
    Priv["Privileged Scopes (Opt-in Required)"] --> PW["project.write"]
    Priv --> DD["dynamic.device"]
    Priv --> DH["dynamic.hook"]
    Priv --> AP["android.patch"]
    Priv --> AS["android.sign"]
    Priv --> AI["android.install"]
    
    style Safe fill:#1E88E5,color:#fff
    style Priv fill:#D81B60,color:#fff
```

1. **`project.read`:** Read project metadata, artifacts, and summary reports.
2. **`project.write`:** Mutate projects, ingest new artifacts, and restore backups.
3. **`static.read`:** Read decompiled code, manifest structures, resources, and strings.
4. **`dynamic.device`:** Connect to ADB daemons, acquire device leases, and capture screens.
5. **`dynamic.hook`:** Deploy Frida scripts, attach to processes, and dump memory/storage.
6. **`android.patch`:** Rewrite Dalvik bytecode, inject Frida gadgets, or modify AXML flags.
7. **`android.sign`:** Sign APK containers with project or test certificates.
8. **`android.install`:** Install modified or rebuilt APKs onto physical or virtual devices.
9. **`export.write`:** Generate OpenAPI specifications, Postman collections, and UI wireframes.

---

## 3. UI Reconstruction & Design System Engine

The UI engine in `src/raa/services/android/ui_design_system.py` converts extracted layout hierarchies into high-fidelity, accessible mobile interfaces.

### Core Design Principles

1. **8-Point Spatial Grid:**
   All margins, paddings, element heights, and component dimensions snap to multiples of 8dp (`8dp`, `16dp`, `24dp`, `32dp`, `48dp`). Small icon adjustments allow 4dp increments.
2. **Thumb-Zone Optimization:**
   Interactive buttons, primary navigation, and input triggers are positioned in the bottom 40% of the screen ("easy thumb reach"). Destructive or secondary controls are isolated at the top.
3. **60/30/10 Color Rule:**
   - **60% Dominant (Background & Canvas):** Clean surface background (light `#FFFFFF` or dark `#121212`).
   - **30% Structural (Cards, Dividers, Surfaces):** Subtle contrast layer.
   - **10% Accent (CTAs, Badges, Highlights):** High-contrast primary action color.
4. **Touch Target Dimensions:**
   All touchable targets adhere to Material / WCAG minimums of at least **$48 \times 48\text{ dp}$**.
5. **Multi-Target Code Synthesis:**
   Generates clean, idiomatic code for:
   - **Jetpack Compose** (Kotlin with Material 3 styling)
   - **React Native** (TypeScript with StyleSheet)
   - **Flutter** (Dart with Material widgets)
   - **Tailwind CSS** (HTML5 for rapid prototyping)

---

## 4. API Reverse Engineering Studio Design

The API extraction engine in `src/raa/services/android/api_studio.py` recovers backend specifications through static AST analysis and dynamic proxy clustering.

### Processing Pipeline
1. **Endpoint Harvesting:** Regex and AST scanners extract URL strings and `@GET`, `@POST`, `@Path` annotations from Retrofit, OkHttp, Ktor, and Volley clients.
2. **Path Parameterization:** Heuristic clustering converts literal paths (`/v1/users/123/orders/99`) into normalized path templates (`/v1/users/{user_id}/orders/{order_id}`).
3. **Header & Auth Inference:** Analyzes headers to determine authentication schemes (Bearer JWT, OAuth2, API Key in Header).
4. **Schema Synthesis:** Converts observed query parameters, form fields, and JSON payloads into valid OpenAPI 3.1 parameter and schema objects.
5. **Artifact Generation:**
   - **OpenAPI 3.1 Document:** Complete Swagger-compatible API documentation.
   - **Postman Collection v2.1:** Runnable collection containing requests, sample headers, dynamic `{{base_url}}` variables, and test assertion scripts.

---

## 5. Storage Schema & Database Design

RAA uses an embedded SQLite database configured with **WAL (Write-Ahead Logging)** mode for concurrent readers.

```mermaid
erDiagram
    PROJECT ||--o{ ARTIFACT : contains
    PROJECT ||--o{ EVIDENCE : owns
    PROJECT ||--o{ JOB : runs
    ARTIFACT ||--o{ EVIDENCE : yields
    ARTIFACT ||--o{ JOB : targets

    PROJECT {
        string id PK
        string name
        string description
        string scopes_json
        datetime created_at
        datetime updated_at
    }

    ARTIFACT {
        string id PK
        string project_id FK
        string filename
        string media_type
        int size_bytes
        string sha256
        string stored_path
        string artifact_type
        datetime created_at
    }

    EVIDENCE {
        string id PK
        string project_id FK
        string artifact_id FK
        string authority
        float confidence
        string category
        string data_json
        datetime created_at
    }

    JOB {
        string id PK
        string project_id FK
        string artifact_id FK
        string job_type
        string status
        int progress_pct
        string result_json
        datetime created_at
        datetime updated_at
    }
```

---

## 6. Platform Compatibility Design

### Windows Sandbox Event Loop Workaround
On Windows inside network-restricted sandboxes (`BypassSandbox: false`), standard Python `asyncio.ProactorEventLoop` hangs indefinitely because its internal self-pipe calls `socket.socketpair()`, which attempts a TCP loopback connect to `127.0.0.1`. In sandboxed Windows environments, outbound TCP connect is denied by kernel security (`WinError 10013`).

RAA resolves this via `src/raa/compat.py`:
- Probes loopback socket connectivity on module import.
- If loopback connections are blocked by sandbox isolation, it equips `BaseProactorEventLoop` with a non-blocking dummy self-pipe (`_DummyLoopbackSocket`).
- Ensures RAA's CLI and test suite execute in **< 2 seconds** with zero stalls on any platform or sandboxed runner.
