---
name: raa-flutter-reversing
description: Reverse engineer Flutter Android applications, patch TLS certificate pinning, and extract Dart AOT strings.
version: 1.0.0
tools: [flutter_list_assets, flutter_patch_tls, flutter_dump_strings]
---

# Flutter Deep Reverse Engineering

Perform deep analysis on Flutter applications compiled to Ahead-Of-Time (AOT) `libapp.so`.

## Workflow
1. Inspect asset bundles, fonts, and icons with `flutter_list_assets`.
2. Patch BoringSSL TLS verification offsets for Burp Suite/mitmproxy interception using `flutter_patch_tls`.
3. Scrape Dart snapshot string pools, API URLs, and secrets using `flutter_dump_strings`.
