# Release v1.9.5 — Phase 13H: Flutter Dart AOT & Hermes Reverser, Scrcpy Fast Injection

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v1.9.5  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: November 2026 | Tools: 210 | Tests: 380 Passing*

---

## Overview & Highlights


- **Flutter Dart AOT Reverser (`framework_flutter_dart_inspect`):**
  - Disassembles Dart AOT snapshot objects from `libapp.so`, extracting class hierarchies and method string pools.
- **React Native Hermes Bytecode Decompiler (`framework_hermes_bytecode_decompile`):**
  - Decompiles Facebook Hermes bytecode (`.hbc`) into readable JavaScript abstract syntax trees.
- **Scrcpy Fast Injection & Screen Streamer (`dyn_scrcpy_fast_inject`):**
  - Low-latency virtual frame streaming and high-frequency touch injection over ADB socket tunnels.
- **Deterministic State Verifier (`dyn_mobilegym_state_verify`):**
  - Verifies reproducibility of dynamic testing paths against deterministic state graphs.

---

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
