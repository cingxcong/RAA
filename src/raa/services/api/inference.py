"""JSON Schema inference with type widening and required field determination."""

from __future__ import annotations

from typing import Any

from raa.domain.api import FlowRecord, SchemaInference
from raa.utils.time import utc_now


def _infer_type(val: Any) -> str:
    """Infer single JSON primitive type."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "number"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return "string"


def _widen_types(existing: str, new_t: str) -> str:
    """Widen types safely (e.g., integer -> number)."""
    if existing == new_t:
        return existing
    if {existing, new_t} == {"integer", "number"}:
        return "number"
    return "string"


def infer_json_schema(samples: list[Any]) -> dict[str, Any]:
    """Infer merged JSON schema across multiple JSON payload samples."""
    if not samples:
        return {"type": "object", "additionalProperties": True}

    # If top-level is primitive or array
    first = samples[0]
    if isinstance(first, list):
        item_samples: list[Any] = []
        for s in samples:
            if isinstance(s, list):
                item_samples.extend(s)
        items_schema = infer_json_schema(item_samples) if item_samples else {"type": "string"}
        return {"type": "array", "items": items_schema}

    if not isinstance(first, dict):
        t = _infer_type(first)
        return {"type": t, "example": first}

    # Dict / Object merging
    total_samples = len(samples)
    prop_types: dict[str, str] = {}
    prop_samples: dict[str, list[Any]] = {}
    prop_counts: dict[str, int] = {}
    nullable_props: set[str] = set()

    for sample in samples:
        if not isinstance(sample, dict):
            continue
        for k, v in sample.items():
            prop_counts[k] = prop_counts.get(k, 0) + 1
            prop_samples.setdefault(k, []).append(v)
            val_type = _infer_type(v)
            if v is None:
                nullable_props.add(k)
            elif k not in prop_types:
                prop_types[k] = val_type
            else:
                prop_types[k] = _widen_types(prop_types[k], val_type)

    properties: dict[str, Any] = {}
    required: list[str] = []

    for prop_name, count in prop_counts.items():
        # Required only when present in 100% of samples
        if count == total_samples and prop_name not in nullable_props:
            required.append(prop_name)

        p_type = prop_types.get(prop_name, "string")
        val_list = prop_samples.get(prop_name, [])
        non_null_vals = [x for x in val_list if x is not None]

        if p_type == "object" and non_null_vals:
            sub_schema = infer_json_schema(non_null_vals)
        elif p_type == "array" and non_null_vals:
            flat_items = [
                item for sublist in non_null_vals if isinstance(sublist, list) for item in sublist
            ]
            sub_items = infer_json_schema(flat_items) if flat_items else {"type": "string"}
            sub_schema = {"type": "array", "items": sub_items}
        else:
            sub_schema = {"type": p_type}
            if non_null_vals:
                sub_schema["example"] = non_null_vals[0]

        if prop_name in nullable_props:
            sub_schema["nullable"] = True

        properties[prop_name] = sub_schema

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
    if required:
        schema["required"] = sorted(required)
    return schema


def infer_operation_schemas(operation_id: str, flows: list[FlowRecord]) -> SchemaInference:
    """Infer request schema and status-coded response schemas for an operation cluster."""
    req_samples: list[Any] = []
    res_samples_by_status: dict[str, list[Any]] = {}

    for flow in flows:
        if flow.request.body and flow.request.body.parsed_json is not None:
            req_samples.append(flow.request.body.parsed_json)
        status_code = str(flow.response.status)
        if flow.response.body and flow.response.body.parsed_json is not None:
            res_samples_by_status.setdefault(status_code, []).append(flow.response.body.parsed_json)

    request_schema = infer_json_schema(req_samples) if req_samples else {}

    response_schemas: dict[str, dict[str, Any]] = {}
    for status_str, samples in res_samples_by_status.items():
        response_schemas[status_str] = infer_json_schema(samples)

    # If no response body parsed, create default 200/204 response schema
    if not response_schemas:
        response_schemas["200"] = {"type": "object", "additionalProperties": True}

    field_metadata: dict[str, Any] = {
        "request_samples": len(req_samples),
        "total_flows": len(flows),
        "statuses": sorted(res_samples_by_status.keys()),
    }

    return SchemaInference(
        operation_id=operation_id,
        request_schema=request_schema,
        response_schemas=response_schemas,
        field_metadata=field_metadata,
        inferred_at=utc_now(),
    )
