"""OpenAPI 3.1 contract generator, schema assembler, and specification validator."""

from __future__ import annotations

import json
from typing import Any

from raa.domain.api import (
    AuthSchemeType,
    OpenAPISpec,
    OperationCluster,
    SchemaInference,
)
from raa.utils.ids import new_id
from raa.utils.time import utc_now


def generate_openapi_spec(
    project_id: str,
    clusters: list[OperationCluster],
    inferences: dict[str, SchemaInference],
    title: str = "App Reverse-Engineered API",
    version: str = "1.0.0",
) -> OpenAPISpec:
    """Generate a clean, conforming OpenAPI 3.1 specification from clusters and inferred schemas."""
    # Build servers
    hosts = sorted({c.host for c in clusters if c.host})
    servers = [{"url": f"https://{h}", "description": f"Observed host {h}"} for h in hosts]
    if not servers:
        servers = [{"url": "https://api.example.com", "description": "Default host"}]

    # Build security schemes
    security_schemes: dict[str, Any] = {}
    has_bearer = any(c.auth_scheme == AuthSchemeType.BEARER for c in clusters)
    has_api_key = any(c.auth_scheme == AuthSchemeType.API_KEY for c in clusters)

    if has_bearer:
        security_schemes["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Observed Bearer token authentication",
        }
    if has_api_key:
        security_schemes["apiKeyAuth"] = {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Observed API Key header authentication",
        }

    paths: dict[str, Any] = {}

    for cluster in clusters:
        path_template = cluster.path_template
        method = cluster.method.lower()
        inference = inferences.get(cluster.operation_id)

        # Merge path parameters and query parameters
        params: list[dict[str, Any]] = []
        seen_param_names: set[str] = set()

        for pp in cluster.path_parameters:
            p_name = pp["name"]
            if p_name not in seen_param_names:
                seen_param_names.add(p_name)
                params.append(pp)

        for qp in cluster.query_parameters:
            q_name = qp["name"]
            if q_name not in seen_param_names:
                seen_param_names.add(q_name)
                params.append(
                    {
                        "name": q_name,
                        "in": "query",
                        "required": qp.get("required", False),
                        "schema": qp.get("schema", {"type": "string"}),
                    }
                )

        # Build responses
        responses: dict[str, Any] = {}
        if inference and inference.response_schemas:
            for status_code, schema in inference.response_schemas.items():
                responses[status_code] = {
                    "description": f"Status {status_code} response",
                    "content": {
                        "application/json": {
                            "schema": schema,
                        }
                    },
                }
        else:
            responses["200"] = {
                "description": "Successful response",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }

        operation_def: dict[str, Any] = {
            "operationId": cluster.operation_id,
            "summary": f"{cluster.method} {cluster.path_template}",
            "description": f"Inferred operation from {cluster.sample_count} observed flow(s).",
            "parameters": params,
            "responses": responses,
            "x-raa-confidence": cluster.confidence,
            "x-raa-samples": cluster.sample_count,
            "x-raa-source": "runtime-observed",
            "x-raa-flow-count": len(cluster.flow_ids),
        }

        # Add requestBody for POST/PUT/PATCH if schema present
        if method in ("post", "put", "patch") and inference and inference.request_schema:
            operation_def["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": inference.request_schema,
                    }
                },
            }

        # Add security requirement
        if cluster.auth_scheme == AuthSchemeType.BEARER:
            operation_def["security"] = [{"bearerAuth": []}]
        elif cluster.auth_scheme == AuthSchemeType.API_KEY:
            operation_def["security"] = [{"apiKeyAuth": []}]

        paths.setdefault(path_template, {})[method] = operation_def

    components: dict[str, Any] = {}
    if security_schemes:
        components["securitySchemes"] = security_schemes

    spec_dict = {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": version,
            "description": "Specification automatically extracted and normalized by RAA.",
            "x-raa-generator": "raa-api-studio",
            "x-raa-generated-at": utc_now().isoformat(),
        },
        "servers": servers,
        "paths": paths,
        "components": components,
    }

    # Validate specification structure
    validate_openapi_spec(spec_dict)

    spec_id = new_id("spec")
    return OpenAPISpec(
        spec_id=spec_id,
        project_id=project_id,
        openapi_version="3.1.0",
        title=title,
        version=version,
        servers=servers,
        paths=paths,
        components=components,
        extensions={"operation_count": len(clusters)},
        generated_at=utc_now(),
        raw_yaml=json.dumps(spec_dict, indent=2),
    )


def validate_openapi_spec(spec: dict[str, Any]) -> None:
    """Validate that the spec satisfies OpenAPI 3.1 structure requirements."""
    if not isinstance(spec, dict):
        raise ValueError("OpenAPI specification must be a dictionary.")
    if spec.get("openapi") != "3.1.0":
        raise ValueError(f"Expected OpenAPI version '3.1.0', got '{spec.get('openapi')}'.")
    info = spec.get("info")
    if not isinstance(info, dict) or not info.get("title") or not info.get("version"):
        raise ValueError("OpenAPI specification must contain info.title and info.version.")
    if "paths" not in spec or not isinstance(spec["paths"], dict):
        raise ValueError("OpenAPI specification must contain a paths dictionary.")
