"""Operation clustering and path templating with stable identity."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from raa.domain.api import (
    AuthSchemeType,
    FlowRecord,
    OperationCluster,
    ParamKind,
)
from raa.utils.time import utc_now

# Variable path segment detection patterns
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_NUMERIC_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_BASE64_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")


def is_variable_segment(segment: str) -> bool:
    """Check if a path segment represents an ID, UUID, hash, or slug."""
    if not segment:
        return False
    if _NUMERIC_RE.match(segment):
        return True
    if _UUID_RE.match(segment):
        return True
    if _HEX_RE.match(segment):
        return True
    is_slug = _BASE64_SLUG_RE.match(segment)
    return bool(is_slug and not segment.startswith("v1") and not segment.startswith("v2"))


def template_path(path: str) -> tuple[str, list[dict[str, Any]]]:
    """Transform concrete URL path into templated path and parameter definitions."""
    clean = "/" + path.strip("/")
    if clean == "/":
        return clean, []

    segments = clean.split("/")
    new_segments: list[str] = []
    path_params: list[dict[str, Any]] = []

    for i, seg in enumerate(segments):
        if not seg:
            continue
        if is_variable_segment(seg):
            prev_seg = segments[i - 1] if i > 0 else ""
            if prev_seg and prev_seg.endswith("s"):
                param_name = prev_seg[:-1] + "Id"
            elif prev_seg:
                param_name = prev_seg + "Id"
            else:
                param_name = f"param{len(path_params) + 1}"

            new_segments.append(f"{{{param_name}}}")
            schema_type = "integer" if seg.isdigit() else "string"
            path_params.append(
                {
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": schema_type},
                    "example": seg,
                }
            )
        else:
            new_segments.append(seg)

    templated = "/" + "/".join(new_segments)
    return templated, path_params


def compute_operation_id(host: str, method: str, path_template: str) -> str:
    """Compute stable, reproducible operation ID: op:<host>:<method>:<path-hash>."""
    clean_host = host.lower().replace(":", "_")
    norm_path = path_template.strip("/").lower()
    path_hash = hashlib.sha256(norm_path.encode("utf-8")).hexdigest()[:12]
    return f"op:{clean_host}:{method.lower()}:{path_hash}"


def detect_auth_scheme(headers: list[Any]) -> tuple[AuthSchemeType | None, dict[str, Any]]:
    """Inspect request headers to classify authentication scheme."""
    for h in headers:
        name = h.name.lower()
        val = h.value
        if name == "authorization":
            if "bearer" in val.lower() or h.redacted:
                return AuthSchemeType.BEARER, {"scheme": "bearer", "header": "Authorization"}
            if "basic" in val.lower():
                return AuthSchemeType.BASIC, {"scheme": "basic", "header": "Authorization"}
        elif name in ("x-api-key", "api-key", "apikey"):
            return AuthSchemeType.API_KEY, {"scheme": "apiKey", "in": "header", "header": h.name}
        elif name == "cookie" and any(k in val.lower() for k in ("session", "token", "auth")):
            return AuthSchemeType.COOKIE, {"scheme": "cookie", "cookie": "session"}
    return None, {}


def cluster_flows(flows: list[FlowRecord]) -> list[OperationCluster]:
    """Group normalized flows into de-duplicated operation clusters with stable identities."""
    groups: dict[str, list[FlowRecord]] = {}

    for flow in flows:
        req = flow.request
        templated_path, _ = template_path(req.path)
        op_id = compute_operation_id(req.host, req.method, templated_path)
        groups.setdefault(op_id, []).append(flow)

    clusters: list[OperationCluster] = []
    for op_id, op_flows in groups.items():
        sample = op_flows[0]
        req = sample.request
        templated_path, path_params = template_path(req.path)

        timestamps = [f.timestamp for f in op_flows]
        first_seen = min(timestamps) if timestamps else utc_now()
        last_seen = max(timestamps) if timestamps else utc_now()

        # Aggregate query parameters
        query_dict: dict[str, dict[str, Any]] = {}
        for f in op_flows:
            for q in f.request.query:
                if q.name not in query_dict:
                    query_dict[q.name] = {
                        "name": q.name,
                        "in": "query",
                        "required": True,
                        "kind": q.kind.value,
                        "schema": {"type": "string"},
                        "examples": [q.value],
                        "count": 1,
                    }
                else:
                    entry = query_dict[q.name]
                    entry["count"] += 1
                    if len(entry["examples"]) < 5:
                        entry["examples"].append(q.value)

        # Mark query parameters required only if present in all flows
        query_params: list[dict[str, Any]] = []
        for q_entry in query_dict.values():
            q_entry["required"] = q_entry["count"] == len(op_flows)
            query_params.append(q_entry)

        # Detect auth scheme across samples
        auth_scheme: AuthSchemeType | None = None
        auth_details: dict[str, Any] = {}
        for f in op_flows:
            scheme, details = detect_auth_scheme(f.request.headers)
            if scheme:
                auth_scheme = scheme
                auth_details = details
                break

        # Collect call sites
        call_sites = sorted({f.call_site for f in op_flows if f.call_site})

        clusters.append(
            OperationCluster(
                operation_id=op_id,
                method=req.method.upper(),
                host=req.host.lower(),
                path_template=templated_path,
                sample_count=len(op_flows),
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=1.0 if len(op_flows) >= 2 else 0.85,
                auth_scheme=auth_scheme,
                auth_details=auth_details,
                flow_ids=[f.flow_id for f in op_flows],
                path_parameters=path_params,
                query_parameters=query_params,
                headers=[
                    h.model_dump(mode="json") for h in req.headers if h.kind != ParamKind.VOLATILE
                ],
                call_sites=call_sites,
            )
        )

    return sorted(clusters, key=lambda c: c.operation_id)
