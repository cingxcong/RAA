# Release v1.4.0 — Phase 13B-2: Perfetto Dynamic Tracing & Semantic Compose Parity

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v1.4.0  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: November 2026 | Tools: 177 | Tests: 323 Passing*

---

## Overview & Highlights


- **Perfetto Dynamic Trace Profiler (`dyn_perfetto_trace_record`):**
  - Records Linux kernel ftrace events, Binder transactions, and app scheduling slices via `perfetto`.
- **Binder Storm Analyzer (`dyn_binder_storm_analyze`):**
  - Identifies excessive IPC bottlenecks and Binder transaction storms causing app UI freezes.
- **Semantic Jetpack Compose Parity Engine (`ui_semantic_compose_parity`):**
  - Compares decompiled XML layout hierarchies against synthesized Compose code for design parity.

---

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
