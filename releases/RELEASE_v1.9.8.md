# Release v1.9.8 — Phase 13I: Automated MASTG Runner, APKLeaks Harvester & Privacy Tracer

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v1.9.8  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: November 2026 | Tools: 215 | Tests: 388 Passing*

---

## Overview & Highlights


- **Automated OWASP MASTG Runner (`sec_mastg_compliance_run`):**
  - Runs automated static and dynamic audit suites validating compliance against all OWASP MASTG test cases.
- **APKLeaks Secret Harvester (`sec_apkleaks_secret_scan`):**
  - High-throughput regex scanning engine harvesting API keys, JWTs, AWS credentials, and OAuth tokens from bytecode.
- **Sensitive API Privacy Taint Tracer (`privacy_taint_trace_scan`):**
  - Tracks propagation of sensitive user data (IMEI, GPS, contacts, camera) to external network sockets.
- **Codeless RMS Interceptor (`dyn_rms_crypto_intercept`):**
  - Generates and injects codeless Frida hooks capturing runtime encryption keys, IVs, and plaintext payloads.

---

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
