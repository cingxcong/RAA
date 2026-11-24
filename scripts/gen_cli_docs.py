import json

with open("cli_dump.json", encoding="utf-8") as f:
    cmds = json.load(f)

# Group by category
groups = {}
for c in cmds:
    parts = c["command"].split()
    grp = parts[1] if len(parts) > 2 else "global"
    groups.setdefault(grp, []).append(c)

with open("docs/CLI_REFERENCE.md", "w", encoding="utf-8") as out:
    out.write("# RAA (Reverse Android Anything) — Complete CLI Reference Guide\n\n")
    out.write("> **Platform:** Reverse Android Anything (RAA) v3.0.0 Production  \n")
    out.write("> **Total Available CLI Commands:** 311 commands  \n")
    out.write("> **Protocol Version:** 2026-07-28 | **Tool Equivalents:** 322 Tools\n\n")
    out.write(
        "This document provides an exhaustive, production-grade reference for all 311 command-line commands across all sub-apps in RAA.\n\n"
    )
    out.write(
        "Every CLI command is backed by the exact same capability registry and runtime models that power RAA's MCP, REST, and Python SDK surfaces.\n\n"
    )
    out.write("## Table of Subcommand Groups\n\n")
    out.write("| Subcommand Group | Commands Count | Purpose & Domain |\n")
    out.write("|---|:---:|---|\n")

    group_descriptions = {
        "global": "Core CLI bootstrap, status, doctor, report, manifest & permissions",
        "project": "Workspace project creation, lifecycle and scope inspection",
        "artifact": "Artifact ingestion, cataloguing, and binary file enumeration",
        "tools": "Tool discovery, schema inspection, and raw profile-scoped invocation",
        "recipe": "Multi-stage automated analysis and workflow macro execution",
        "source": "DEX decompiler dispatch, class searching, and source recovery",
        "skill": "Antigravity Agent Skills catalogue, install and execution",
        "serve": "MCP stdio / SSE and REST API daemon servers",
        "framework": "Framework detection and application capability querying",
        "flutter": "Flutter asset, symbol, BoringSSL pinning, and engine inspection",
        "react-native": "React Native Hermes bytecode, bundle, and module inspection",
        "unity": "Unity il2cpp, metadata, and asset bundle extraction",
        "dotnet": "Xamarin / .NET MAUI DLL assembly inspection",
        "native": "ELF shared library symbol extraction and ARM64 disassembly",
        "ui": "View hierarchies, Jetpack Compose, Apple HIG, and shaders",
        "graph": "AAIR dependency and cross-reference call graph querying",
        "device": "ADB device management, USB hardware, and screen mirrors",
        "dynamic": "Frida hooks, memory dumps, network tracing, and dynamic fuzzer",
        "api": "API endpoint discovery, OpenAPI schemas, and traffic capturing",
        "unpack": "APK/AAB/XAPK/APKM unpacking, extraction, and rebuilding",
        "diff": "Binary, manifest, DEX, and permission differential comparison",
        "security": "MASTG audits, Play Protect pre-flight, and vulnerability triage",
        "test": "Automated UI and unit testing harness runs",
        "rebuild": "Patching, re-alignment, and v2/v3 APK signing block synthesis",
        "admin": "Engine catalogs, ZTNA gateways, quotas, and audit trails",
        "ai": "On-device AI model extraction (TFLite, ONNX, PyTorch Mobile)",
        "platform": "Multi-OS cross-platform target inspection (iOS, HarmonyOS, Linux)",
        "swarm": "Multi-agent swarm governance, token budgeting, and blackboard",
        "cognitive": "Dual-context adversarial audit and exploit payoff simulation",
        "binary": "Next-gen decompilers (RetDec LLVM, Kuna Rust), GDB/MI, and Apple Mach-O",
        "canvas": "Autonomous UI screen reconstruction, shaders, and Sodu CI/CD",
        "enterprise": "Enterprise MCP mesh, universal 7-CLI dispatcher, Nacos, WASM",
        "offensive": "Offensive security operations, Yaklang playbooks, and v3 benchmarks",
    }

    for grp in sorted(groups.keys()):
        desc = group_descriptions.get(grp, "Subsystem commands")
        out.write(f"| [`raa {grp}`](#{grp}-commands) | {len(groups[grp])} | {desc} |\n")
    out.write("\n---\n\n")

    for grp in sorted(groups.keys()):
        commands = groups[grp]
        out.write(f"## {grp.capitalize()} Commands\n\n")
        out.write(f"**Group:** `raa {grp}` | **Total Commands:** {len(commands)}\n\n")
        out.write("| Command | Description |\n")
        out.write("|---|---|\n")
        for c in commands:
            cmd_code = f"`{c['command']}`"
            help_text = c["help"].replace("|", "\\|")
            out.write(f"| {cmd_code} | {help_text} |\n")
        out.write("\n")

print("Generated docs/CLI_REFERENCE.md successfully.")
