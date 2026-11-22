# RAA (Reverse Android Anything) — Release History & Changelog

<p align="center">
  <img src="images/raa.png" width="140" alt="RAA Logo">
</p>

<p align="center">
  <strong>Agent-Native Multi-Platform Application Intelligence, Decompilation, UI Reconstruction & Security Engineering Platform</strong>
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

---

## Release Overview & Progression

| Version | Release Date | Implemented Tools | Passing Tests | Primary Focus & Highlights |
| :--- | :---: | :---: | :---: | :--- |
| [**v2.0.0**](#v200-production-release---phase-14-universal-platform-expansion) | Nov 21, 2026 | **244** | **437** | Universal Platform Expansion: Apple iOS `.ipa` & Mach-O, Huawei HarmonyOS `.hap` & ArkTS Panda ABC, Standalone PRoot Linux Engine, Warp Terminal Blocks, Multi-Target Parity Matrix, Security Zero-Defect Hardening. |
| [**v1.9.99**](#v1999---phase-13m-rasp-bypass-http-toolkit-vpn-shizuku-bridge--chaos-mutator) | Nov 2026 | 237 | 419 | RASP & Anti-Tamper Bypass Gen, HTTP Toolkit Zero-Config VPN, Shizuku Binder IPC Bridge, Device Chaos Mutator & Standalone CLI Bundle. |
| [**v1.9.98**](#v1998---phase-13l-accessibility-agent-appagent-recorder--appfunction-fuzzer) | Nov 2026 | 230 | 409 | On-Device Accessibility Agent, AppAgent Recording, QA Telemetry with Perfetto Trace Slicing, Android 16 AppFunction Fuzzer. |
| [**v1.9.95**](#v1995---phase-13k-interactive-architecture-diagrams-code-review--skip-swift) | Nov 2026 | 225 | 401 | Interactive SVG/HTML Architecture & Taint Flow Diagrams, Hybrid Decompiled Code Review, Skip Swift Transpiler Reverser. |
| [**v1.9.9**](#v1990---phase-13j-ephemeral-docker-android-sandbox--arm-translation) | Nov 2026 | 222 | 395 | Ephemeral Docker Android Sandbox, Genymotion Houdini ARM Translation Injector, Agent-Device Automation, Visual Diff Audit. |
| [**v1.9.8**](#v1980---phase-13i-automated-mastg-runner-apkleaks-harvester--privacy-tracer) | Nov 2026 | 215 | 388 | Automated OWASP MASTG Runner, APKLeaks Secret Harvester, Privacy Taint Tracer, Codeless RMS Crypto Interceptor. |
| [**v1.9.5**](#v1950---phase-13h-flutter-dart-aot--hermes-reverser-scrcpy-fast-injection) | Nov 2026 | 210 | 380 | Flutter Dart AOT Snapshot Inspector, BoringSSL Pinning Bypass, React Native Hermes Bytecode Decompiler, Scrcpy Fast Injection. |
| [**v1.9.0**](#v1900---phase-13g-headless-virtualdisplay-fuzzer--mobile-gui-agent) | Nov 2026 | 202 | 371 | Headless VirtualDisplay Fuzzer, Multimodal Mobile GUI Agent (OpenGUI/MobileAgent), Termux ARM64 PRoot Workspace Harness. |
| [**v1.8.0**](#v1800---phase-13f-cloud-rotating-proxy-burp-suite-mcp--p2p-tunnel) | Nov 2026 | 197 | 362 | AWS API Gateway Cloud Rotating Proxy, Burp Suite MCP Bridge, Passive Traffic Inspector, Iroh/WireGuard P2P Remote Device Tunnel. |
| [**v1.7.0**](#v1700---phase-13e-search-first-mcp-wasm-decompiler--ghost-adb-fleet) | Nov 2026 | 193 | 353 | Search-First MCP Capability Index, WebAssembly (.wasm) Decompiler, 401/403 Bypass Engine, Ghost Wireless ADB Fleet Discoverer. |
| [**v1.6.0**](#v1600---phase-13d-wireguard-tunnel-bug-bounty-vrt-reporter--crowdsec-cti) | Nov 2026 | 188 | 342 | WireGuard Zero-Trust Tunnel, HackerOne/Bugcrowd VRT Bug Bounty Reporter, CrowdSec Threat Intel, SafeLine Semantic WAF Audit. |
| [**v1.5.0**](#v1500---phase-15-exploit-poc-validator-masvs-copilot--iot-sniffer) | Nov 2026 | 182 | 331 | Exploit PoC Validator, OWASP MASVS Checklist Copilot, Shodan/Censys Backend IP Intel, BLE/mDNS IoT Traffic Sniffer. |
| [**v1.4.0**](#v1400---phase-13b-2-perfetto-dynamic-tracing--semantic-compose-parity) | Nov 2026 | 177 | 323 | Perfetto Dynamic Tracing & Binder Storm Detection, Semantic Jetpack Compose Parity Engine, XML-to-Compose Code Synthesis. |
| [**v1.3.5**](#v1350---phase-13b-1-automated-android-asset-studio--play-store-banners) | Nov 2026 | 173 | 316 | Automated Android Asset Studio, Adaptive Icon Generator, 1024x500 Google Play Store Feature Graphic Banner Synthesizer. |
| [**v1.3.0**](#v1300---phase-13a-in-app-webview-cdp-agent-crawl4ai-osint--on-device-ai) | Nov 2026 | 170 | 311 | In-App WebView Chrome DevTools Protocol (CDP) Agent, Crawl4AI OSINT Endpoint Crawler, On-Device AI Model Reverser (TFLite/ONNX). |
| [**v1.2.0**](#v1200---phase-12b-play-protect-pre-flight-mobsf-parity--sarif-stride) | Nov 2026 | 158 | 301 | Google Play Protect Pre-Flight Policy Engine, MobSF Static Rule Parity, OASIS SARIF 2.1 Exporter, Mobile STRIDE Threat Modeling. |
| [**v1.1.0**](#v1100---phase-12a-native-v2v3-signing-block--16kb-elf-alignment) | Nov 2026 | 153 | 295 | Pure-Python APK Signature Scheme v2/v3 Block Builder, Android 15 16KB Page Alignment Audit & Binary Auto-Patcher. |
| [**v1.0.0**](#v1000---phase-11-production-hardening-tamper-evident-audit--multi-tenancy) | Nov 2026 | 151 | 291 | Enterprise Production Hardening, SHA-256 Hash-Chained Audit Trail, CycloneDX 1.5 & SPDX 2.3 SBOM Generation, Multi-Tenancy Quotas. |
| [**v0.1.0–v0.9.0**](#v010v090---phases-110-foundations-aair-ui-redesign--api-studio) | Oct–Nov 2026 | 42–144 | 100–280 | Core Analysis Foundations, JADX Tier-1 Decompilation, AAIR Graph Model, Framework Adapters, API Studio, Frida Hooks. |

---

## Detailed Version Changelogs

### v2.0.0 (Production Release — Phase 14: Universal Platform Expansion)
*Released: November 21, 2026 | Tools: 244 | Tests: 437 Passing | Stability: Production/Stable*

#### Highlights
- **Apple iOS Application Container & Mach-O Disassembler (`ios_ipa_inspect`, `ios_macho_disassemble`):**
  - Full ingestion and parsing of Apple iOS `.ipa` packages.
  - In-memory parsing of `Info.plist` bundle IDs, version strings, minimum OS versions, App Transport Security (ATS) rules, and custom URL schemes.
  - Automated extraction of embedded XML entitlement dictionaries from Apple PKCS#7 signed `embedded.mobileprovision` profiles.
  - 64-bit Mach-O binary parsing: segments (`__PAGEZERO`, `__TEXT`, `__DATA`, `__LINKEDIT`), dynamic dylibs (`LC_LOAD_DYLIB`), FairPlay DRM status check (`cryptid == 0`), code signatures (`LC_CODE_SIGNATURE`), and Swift runtime detection.
- **Huawei HarmonyOS & OpenHarmony Package & ArkTS ABC Inspector (`harmony_hap_inspect`, `harmony_abc_disassemble`):**
  - Ingestion of Huawei `.hap` archives with support for both Stage model (`module.json`) and FA legacy model (`config.json`).
  - Ability extraction, system permission discovery (`ohos.permission.*`), and device target profiling.
  - Disassembly of ArkTS `classes.abc` Panda bytecode (`PANDA` and `qzbc` magic headers).
  - Detection of ArkTS decorators (`@Component`, `@Entry`, `@State`, `@Builder`) and ArkUI components (`Column`, `Row`, `Text`, `Button`, `NavDestination`).
- **On-Device Standalone PRoot Linux Container Engine (`termux_proot_workspace_manage`):**
  - Manages rootless userspace Linux containers directly on target Android devices via PRoot and ADB without PC tethering or device rooting.
  - Actions supported: `status`, `init`, `exec`, `install_pkg`, `purge`.
- **Interactive Warp Terminal Block Sessions & Audit Runbooks (`warp_block_session_manage`):**
  - Records, tags, bookmarks, and exports interactive terminal command blocks into Markdown audit runbooks detailing commands, outputs, exit codes, durations, and timestamps.
- **Cross-Platform Parity Compare Matrix (`platform_cross_target_compare`):**
  - Comparative analysis evaluating parity across Android APK, Apple iOS IPA, and Huawei HarmonyOS HAP targets side-by-side.
  - Mapped permission matrices (Camera, Location, Microphone, Photos, Bluetooth) with automated parity scoring.
- **Security Hardening & Production Zero-Defect Audit:**
  - Complete elimination of production `assert` statements across all domain logic.
  - Full compliance with Bandit security rules (`ruff check --select S src`: 0 errors).
  - Production HTTP security headers enforced via ASGI middleware (`nosniff`, `DENY`, `strict-origin-when-cross-origin`, `mode=block`).
  - Constant-time authentication token comparison via `secrets.compare_digest`.
- **Surface Expansion:**
  - Added CLI Typer group: `raa platform [ios-inspect|macho-disassemble|harmony-inspect|harmony-disassemble|proot|warp-session|cross-compare]`.
  - Added dedicated E2E test suite [`tests/test_production_e2e.py`](tests/test_production_e2e.py).

---

### v1.9.99 — Phase 13M: RASP Bypass, HTTP Toolkit VPN, Shizuku Bridge & Chaos Mutator
*Released: November 2026 | Tools: 237 | Tests: 419 Passing*

- **Zero-Config VPN HTTP/HTTPS Interceptor (`dyn_httptoolkit_vpn_intercept`):**
  - Transparent zero-config VPN socket capture, reverse ADB proxy routing, and automatic user/system CA certificate injection.
- **RASP Signature Detector & Bypass Generator (`sec_rasp_signature_scan`, `dyn_rasp_bypass_gen`):**
  - Bytecode and native signature scanner for freeRASP, Promon SHIELD, DexGuard, RootBeer, and anti-hooking traps.
  - Targeted Frida script generation neutralizing root detection, emulator heuristics, and debugger hooks.
- **BetterAndroid Notification Silhouette Audit (`ui_notification_icon_audit`):**
  - Audits Android notification icons for monochrome compliance, contrast ratios against notification shades, and manifest metadata.
- **Privileged On-Device Shizuku Bridge (`shizuku_privileged_exec`):**
  - Executes package management, appops, and system permission grants without root using Shizuku Binder IPC.
- **Dynamic Device Chaos Mutator & CLI Bundle (`dyn_device_env_mutate`, `termux_ondevice_binary_bundle`):**
  - Mutates dark mode, network throttling, battery levels, and display density over ADB.
  - Bundles and deploys standalone AOSP analysis binaries (`sqlite3`, `dexdump`, `busybox`, `strace`, `tcpdump`, `socat`).

---

### v1.9.98 — Phase 13L: Accessibility Agent, AppAgent Recorder & AppFunction Fuzzer
*Released: November 2026 | Tools: 230 | Tests: 409 Passing*

- **On-Device Accessibility & GUI Agent (`dyn_accessibility_agent_control`):**
  - Inspects accessibility nodes, synthesizes gestures, clicks, scrolls, and text input without developer options or ADB.
- **AppAgent Autonomous GUI Recorder (`gui_appagent_record_trace`):**
  - Records multi-step interactive workflows, element coordinates, and screenshots into structured behavioral traces.
- **QA Telemetry Replayer with Perfetto Trace Slicing (`qa_telemetry_replay_trace`):**
  - Replays behavioral test traces while concurrently slicing Perfetto trace buffers for jank and frame drops.
- **Android 16 AppFunction Fuzzer (`appfunction_contract_fuzz`):**
  - Discovers and fuzzes Android 16 AppFunctions exposed to on-device AI assistants, validating parameter bounds and schema contracts.
- **Agent Self-Documentation (`agent_contract_spec_gen`):**
  - Generates comprehensive `AGENTS.md` specifications detailing tool boundaries, scopes, and recipes.

---

### v1.9.95 — Phase 13K: Interactive Architecture Diagrams, Code Review & Skip Swift
*Released: November 2026 | Tools: 225 | Tests: 401 Passing*

- **Interactive Architecture & Taint Flow Diagrams (`sec_arch_diagram_gen`):**
  - Generates interactive, pan-and-zoom SVG and standalone HTML diagrams visualizing components, IPC, and taint flows.
- **Hybrid Decompiled Source Code Reviewer (`sec_code_review_audit`):**
  - Multi-engine source audit reviewing decompiled Java/Kotlin ASTs for OWASP Top 10 Mobile vulnerabilities.
- **Skip Swift Transpiler Reverser (`framework_skip_swift_inspect`):**
  - Reverses Swift-to-Kotlin applications compiled with Skip Tools, extracting dual-platform models and bridge definitions.

---

### v1.9.9 — Phase 13J: Ephemeral Docker Android Sandbox & ARM Translation
*Released: November 2026 | Tools: 222 | Tests: 395 Passing*

- **Ephemeral Docker Android Sandbox (`dyn_docker_android_sandbox`):**
  - Automates provisioning, health checking, and clean teardown of isolated Docker-Android containerized emulators.
- **Agent-Device Automation Bridge (`dyn_agent_device_bridge`):**
  - High-level autonomous agent device control executing deep links, multi-touch gestures, and UI element targeting.
- **Visual Diff & Regression Engine (`ui_visual_diff_audit`):**
  - Performs pixel-by-pixel perceptual visual regression auditing between original and redesigned UI screens.
- **Genymotion Houdini ARM Translation Injector (`dyn_arm_translation_inject`):**
  - Injects Intel Houdini / ARM translation libraries into x86/x86_64 emulators for running ARM-only native libraries.

---

### v1.9.8 — Phase 13I: Automated MASTG Runner, APKLeaks Harvester & Privacy Tracer
*Released: November 2026 | Tools: 215 | Tests: 388 Passing*

- **Automated OWASP MASTG Runner (`sec_mastg_compliance_run`):**
  - Runs automated static and dynamic audit suites validating compliance against all OWASP MASTG test cases.
- **APKLeaks Secret Harvester (`sec_apkleaks_secret_scan`):**
  - High-throughput regex scanning engine harvesting API keys, JWTs, AWS credentials, and OAuth tokens from bytecode.
- **Sensitive API Privacy Taint Tracer (`privacy_taint_trace_scan`):**
  - Tracks propagation of sensitive user data (IMEI, GPS, contacts, camera) to external network sockets.
- **Codeless RMS Interceptor (`dyn_rms_crypto_intercept`):**
  - Generates and injects codeless Frida hooks capturing runtime encryption keys, IVs, and plaintext payloads.

---

### v1.9.5 — Phase 13H: Flutter Dart AOT & Hermes Reverser, Scrcpy Fast Injection
*Released: November 2026 | Tools: 210 | Tests: 380 Passing*

- **Flutter Dart AOT Reverser (`framework_flutter_dart_inspect`):**
  - Disassembles Dart AOT snapshot objects from `libapp.so`, extracting class hierarchies and method string pools.
- **React Native Hermes Bytecode Decompiler (`framework_hermes_bytecode_decompile`):**
  - Decompiles Facebook Hermes bytecode (`.hbc`) into readable JavaScript abstract syntax trees.
- **Scrcpy Fast Injection & Screen Streamer (`dyn_scrcpy_fast_inject`):**
  - Low-latency virtual frame streaming and high-frequency touch injection over ADB socket tunnels.
- **Deterministic State Verifier (`dyn_mobilegym_state_verify`):**
  - Verifies reproducibility of dynamic testing paths against deterministic state graphs.

---

### v1.9.0 — Phase 13G: Headless VirtualDisplay Fuzzer & Mobile GUI Agent
*Released: November 2026 | Tools: 202 | Tests: 371 Passing*

- **Headless VirtualDisplay Fuzzer (`dyn_virtual_display_fuzz`):**
  - Spawns isolated virtual display surfaces over ADB to execute concurrent UI fuzzing without taking over the physical screen.
- **Multimodal Mobile GUI Agent (`ui_mobile_gui_agent_crawl`):**
  - Vision-language agent driving screen exploration, text input, and state transitions on Flutter/Canvas UIs.
- **Termux ARM64 PRoot Workspace (`termux_proot_workspace_manage`):**
  - Deploys on-device Linux userspace environments for native command execution.

---

### v1.8.0 — Phase 13F: Cloud Rotating Proxy, Burp Suite MCP & P2P Tunnel
*Released: November 2026 | Tools: 197 | Tests: 362 Passing*

- **Cloud Rotating Proxy Generator (`api_cloud_proxy_rotate`):**
  - Provisions automated AWS API Gateway IP rotator endpoints to bypass IP-based rate limits during API mapping.
- **Burp Suite MCP Bridge (`api_burp_mcp_bridge`):**
  - Bi-directional bridge connecting RAA with running Burp Suite Professional instances for live traffic ingestion.
- **Passive Traffic Inspector (`api_traffic_security_audit`):**
  - Analyzes recorded HTTP/HTTPS streams for PII leakage, insecure cookies, and missing security headers.
- **P2P Remote Tunnel (`dyn_p2p_remote_tunnel`):**
  - Establishes encrypted peer-to-peer WireGuard tunnels directly to remote physical test devices behind NATs.

---

### v1.7.0 — Phase 13E: Search-First MCP, WASM Decompiler & Ghost ADB Fleet
*Released: November 2026 | Tools: 193 | Tests: 353 Passing*

- **Search-First MCP Capability Index (`mcp_tool_search`):**
  - High-speed index enabling AI agents to query tool capabilities by keywords without saturating context windows.
- **Android WebAssembly Decompiler (`wasm_decompile`):**
  - Decodes and disassembles `.wasm` binary modules embedded in hybrid apps into WebAssembly Text (`.wat`).
- **401/403 HTTP Bypass Engine (`api_bypass_403_generate`):**
  - Generates HTTP header and URI path permutations to bypass misconfigured WAF and reverse proxy access controls.
- **Ghost Wireless ADB Fleet Discoverer (`dyn_adb_fleet_discover`):**
  - Scans local subnets for open ADB ports and manages multi-device test fleets simultaneously.

---

### v1.6.0 — Phase 13D: WireGuard Tunnel, Bug Bounty VRT Reporter & CrowdSec CTI
*Released: November 2026 | Tools: 188 | Tests: 342 Passing*

- **WireGuard Zero-Trust Dynamic Tunnel (`dyn_wireguard_tunnel_manage`):**
  - Configures on-device WireGuard VPN profiles to route target app traffic through security inspection points.
- **Bug Bounty VRT Reporter (`sec_bugbounty_report_gen`):**
  - Maps discovered vulnerabilities to Bugcrowd VRT and HackerOne taxonomies, formatting professional disclosure reports.
- **CrowdSec Cyber Threat Intelligence (`api_crowdsec_cti_query`):**
  - Queries CrowdSec CTI databases for IP reputation and attack behaviors of discovered backend hosts.
- **Semantic AST WAF Security Audit (`api_semantic_waf_audit`):**
  - Audits backend APIs against WAF bypass patterns using SQL/XSS abstract syntax tree representations.

---

### v1.5.0 — Phase 13C: Exploit PoC Validator, MASVS Copilot & IoT Sniffer
*Released: November 2026 | Tools: 182 | Tests: 331 Passing*

- **Exploit PoC Validator (`sec_poc_exploit_validate`):**
  - Validates exploitability of exported components, deep links, and path traversal vulnerabilities in sandboxes.
- **OWASP MASVS Checklist Copilot (`sec_masvs_copilot_audit`):**
  - Automated compliance assessment against all controls of the OWASP Mobile Application Security Verification Standard (MASVS v2.0).
- **Backend IP Intelligence (`api_ip_intel_query`):**
  - Queries Shodan and Censys telemetry for exposed backend server ports, services, and TLS certificates.
- **BLE & mDNS IoT Sniffer (`dyn_iot_traffic_sniff`):**
  - Sniffs and decodes Bluetooth Low Energy and mDNS discovery broadcasts from smart device companion apps.

---

### v1.4.0 — Phase 13B-2: Perfetto Dynamic Tracing & Semantic Compose Parity
*Released: November 2026 | Tools: 177 | Tests: 323 Passing*

- **Perfetto Dynamic Trace Profiler (`dyn_perfetto_trace_record`):**
  - Records Linux kernel ftrace events, Binder transactions, and app scheduling slices via `perfetto`.
- **Binder Storm Analyzer (`dyn_binder_storm_analyze`):**
  - Identifies excessive IPC bottlenecks and Binder transaction storms causing app UI freezes.
- **Semantic Jetpack Compose Parity Engine (`ui_semantic_compose_parity`):**
  - Compares decompiled XML layout hierarchies against synthesized Compose code for design parity.

---

### v1.3.5 — Phase 13B-1: Automated Android Asset Studio & Play Store Banners
*Released: November 2026 | Tools: 173 | Tests: 316 Passing*

- **Adaptive Icon Generator (`ui_adaptive_icon_generate`):**
  - Generates Android adaptive icon sets across `mdpi`, `hdpi`, `xhdpi`, `xxhdpi`, and `xxxhdpi` densities.
- **Play Store Feature Graphic Banner (`ui_play_store_banner_generate`):**
  - Synthesizes 1024x500 marketing feature graphic banners adhering to Google Play Developer requirements.
- **Notification Silhouette Studio (`ui_notification_icon_generate`):**
  - Generates monochrome status bar notification silhouettes compliant with Material Design guidelines.

---

### v1.3.0 — Phase 13A: In-App WebView CDP Agent, Crawl4AI OSINT & On-Device AI
*Released: November 2026 | Tools: 170 | Tests: 311 Passing*

- **In-App WebView Chrome DevTools Protocol (`ui_webview_cdp_inspect`):**
  - Connects to internal Android WebViews over local UNIX abstract sockets to inspect DOM trees and JS consoles.
- **Crawl4AI OSINT Endpoint Crawler (`api_endpoint_crawl_osint`):**
  - Crawls public documentation, swagger pages, and deep links associated with analyzed application domains.
- **On-Device AI Model Reverser (`ai_model_inspect`, `ai_prompt_extract`):**
  - Inspects on-device TensorFlow Lite (`.tflite`), LiteRT, and ONNX models, extracting system prompts and tensor shapes.
- **Android 16 AppFunction Discovery (`ai_appfunction_discover`):**
  - Discovers on-device AI system actions exposed to assistant agents.

---

### v1.2.0 — Phase 12B: Play Protect Pre-Flight, MobSF Parity & SARIF STRIDE
*Released: November 2026 | Tools: 158 | Tests: 301 Passing*

- **Google Play Protect Pre-Flight Engine (`sec_play_protect_audit`):**
  - Validates applications against Google Play Developer Program policies: Foreground Service permissions, Dynamic Code Loading (DCL), and sensitive data collection.
- **MobSF Static Rule Parity (`sec_mobsf_rule_scan`):**
  - Complete static rule parity with Mobile Security Framework (MobSF) including CVSS v3.1 severity scores.
- **OASIS SARIF 2.1 Export & Mobile STRIDE (`sec_sarif_stride_export`):**
  - Exports security findings into standardized OASIS SARIF v2.1 format for GitHub Code Scanning and maps threats to STRIDE categories.

---

### v1.1.0 — Phase 12A: Native v2/v3 Signing Block & 16KB ELF Alignment
*Released: November 2026 | Tools: 153 | Tests: 295 Passing*

- **Native APK Signature Scheme v2/v3 Block Builder (`android_sign_v2v3`):**
  - Pure-Python implementation of APK Signing Block structures passing `apksigner verify -v` without external JDK dependencies.
- **Android 15 16KB Page Alignment Auto-Patcher (`elf_16kb_align_audit`, `elf_16kb_align_patch`):**
  - Audits and patches ELF shared library segment headers to comply with Android 15 16KB memory page requirements.

---

### v1.0.0 — Phase 11: Production Hardening, Tamper-Evident Audit & Multi-Tenancy
*Released: November 2026 | Tools: 151 | Tests: 291 Passing*

- **Cryptographic Hash-Chained Audit Trail (`admin_audit_verify`):**
  - Append-only SHA-256 hash chaining of all tool invocations with tamper detection.
- **Software Bill of Materials (SBOM) Generator (`admin_sbom_generate`):**
  - Generates compliant CycloneDX v1.5 and SPDX v2.3 SBOM manifests.
- **Multi-Tenancy Quotas & Disaster Recovery (`admin_tenancy_quota`, `admin_backup_restore`):**
  - Enforces project limits, concurrent execution caps, and workspace backup/restore archives.

---

### v0.1.0–v0.9.0 — Phases 1–10: Foundations, AAIR Graph, UI Redesign & API Studio
*Released: October–November 2026 | Tools: 42–144 | Tests: 100–280 Passing*

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
