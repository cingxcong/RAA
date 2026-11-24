# Release v1.3.0 — Phase 13A: In-App WebView CDP Agent, Crawl4AI OSINT & On-Device AI

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v1.3.0  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: November 2026 | Tools: 170 | Tests: 311 Passing*

---

## Overview & Highlights


- **In-App WebView Chrome DevTools Protocol (`ui_webview_cdp_inspect`):**
  - Connects to internal Android WebViews over local UNIX abstract sockets to inspect DOM trees and JS consoles.
- **Crawl4AI OSINT Endpoint Crawler (`api_endpoint_crawl_osint`):**
  - Crawls public documentation, swagger pages, and deep links associated with analyzed application domains.
- **On-Device AI Model Reverser (`ai_model_inspect`, `ai_prompt_extract`):**
  - Inspects on-device TensorFlow Lite (`.tflite`), LiteRT, and ONNX models, extracting system prompts and tensor shapes.
- **Android 16 AppFunction Discovery (`ai_appfunction_discover`):**
  - Discovers on-device AI system actions exposed to assistant agents.

---

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
