# Release v1.8.0 — Phase 13F: Cloud Rotating Proxy, Burp Suite MCP & P2P Tunnel

> **Platform:** Reverse Android Anything (RAA)  
> **Release Tag:** v1.8.0  
> **Production Reference:** [v3.0.0 Production Release](RELEASE_v3.0.0.md) | [Release History](../RELEASES.md)  
*Released: November 2026 | Tools: 197 | Tests: 362 Passing*

---

## Overview & Highlights


- **Cloud Rotating Proxy Generator (`api_cloud_proxy_rotate`):**
  - Provisions automated AWS API Gateway IP rotator endpoints to bypass IP-based rate limits during API mapping.
- **Burp Suite MCP Bridge (`api_burp_mcp_bridge`):**
  - Bi-directional bridge connecting RAA with running Burp Suite Professional instances for live traffic ingestion.
- **Passive Traffic Inspector (`api_traffic_security_audit`):**
  - Analyzes recorded HTTP/HTTPS streams for PII leakage, insecure cookies, and missing security headers.
- **P2P Remote Tunnel (`dyn_p2p_remote_tunnel`):**
  - Establishes encrypted peer-to-peer WireGuard tunnels directly to remote physical test devices behind NATs.

---

---

### Links & Navigation
- 🔗 **Current Production Release:** [RELEASE_v3.0.0.md](RELEASE_v3.0.0.md)
- 📚 **Documentation Hub:** [docs/README.md](../docs/README.md)
- 📦 **Master Changelog:** [RELEASES.md](../RELEASES.md)
