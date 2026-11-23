---
name: raa-api-discovery
description: Discover API endpoints, extract parameters and auth headers, synthesize OpenAPI 3.1 specs, and export Postman collections.
version: 1.0.0
tools: [api_list_operations, api_synthesize_spec, api_export_postman]
---

# API Reverse Engineering Studio

Reverse engineer mobile backend APIs from static decompilation and dynamic network traffic.

## Workflow
1. Harvest static and dynamic routes via `api_list_operations`.
2. Cluster routes and synthesize data schemas into OpenAPI 3.1 specification via `api_synthesize_spec`.
3. Export an actionable test suite via `api_export_postman`.
