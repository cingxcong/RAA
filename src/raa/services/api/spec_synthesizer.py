"""Synthesizes OpenAPI 3.1 specifications from observed app traffic and static evidence."""

from __future__ import annotations

import json
from typing import Any

from raa.services.api.clustering import template_path


def synthesize_openapi_spec(
    project_id: str,
    raw_endpoints: list[dict[str, Any]],
    title: str = "Reconstructed Android Application API",
    version: str = "1.0.0",
    min_occurrences: int = 1,
    include_headers: bool = False,
    format: str = "json",
) -> dict[str, Any]:
    """Cluster endpoints, synthesize parameters/schemas, and build an OpenAPI 3.1 document."""
    paths_dict: dict[str, dict[str, Any]] = {}
    auth_schemes: set[str] = set()

    for ep in raw_endpoints:
        raw_path = ep.get("path", "/")
        method = ep.get("method", "get").lower()

        # Run path clustering / templating
        templated_path, path_params = template_path(raw_path)
        if templated_path not in paths_dict:
            paths_dict[templated_path] = {}

        clean_path = templated_path.replace("/", "_").strip("_")
        operation_id = ep.get("operation_id") or f"{method}_{clean_path}"
        summary = ep.get("summary", f"{method.upper()} {templated_path}")

        parameters: list[dict[str, Any]] = []
        for p in path_params:
            parameters.append(
                {
                    "name": p["name"],
                    "in": "path",
                    "required": True,
                    "schema": {"type": p.get("type", "string")},
                }
            )

        # Detect auth
        auth_type = ep.get("auth", "none")
        security_requirement: list[dict[str, list[str]]] = []
        if auth_type == "bearer":
            auth_schemes.add("BearerAuth")
            security_requirement.append({"BearerAuth": []})
        elif auth_type == "api_key":
            auth_schemes.add("ApiKeyAuth")
            security_requirement.append({"ApiKeyAuth": []})

        op_obj: dict[str, Any] = {
            "operationId": operation_id,
            "summary": summary,
            "description": "Synthesized from Android application evidence by RAA.",
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful operation",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"status": {"type": "string"}},
                            }
                        }
                    },
                }
            },
        }

        if security_requirement:
            op_obj["security"] = security_requirement

        # Request body for mutation methods
        if method in ("post", "put", "patch"):
            sample_body = ep.get("sample_body", {})
            properties: dict[str, Any] = {}
            for k, v in sample_body.items():
                val_type = "string"
                if isinstance(v, bool):
                    val_type = "boolean"
                elif isinstance(v, (int, float)):
                    val_type = "number"
                elif isinstance(v, dict):
                    val_type = "object"
                elif isinstance(v, list):
                    val_type = "array"
                properties[k] = {"type": val_type}

            op_obj["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": properties,
                        }
                    }
                },
            }

        paths_dict[templated_path][method] = op_obj

    # Build security schemes
    security_components: dict[str, Any] = {}
    if "BearerAuth" in auth_schemes:
        security_components["BearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    if "ApiKeyAuth" in auth_schemes:
        security_components["ApiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
        }

    spec: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": version,
            "description": (
                f"OpenAPI 3.1 specification synthesized by RAA Studio for project {project_id}."
            ),
        },
        "servers": [{"url": "https://api.example.com", "description": "Synthesized endpoint base"}],
        "paths": paths_dict,
        "components": {
            "securitySchemes": security_components,
            "schemas": {},
        },
    }

    spec_str = json.dumps(spec, indent=2)
    return {
        "openapi_version": "3.1.0",
        "specification": spec_str,
        "total_endpoints": sum(len(methods) for methods in paths_dict.values()),
        "auth_schemes": sorted(auth_schemes),
        "spec_dict": spec,
    }
