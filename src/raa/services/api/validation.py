"""Contract validation testing and drift detection with volatile field filtering."""

from __future__ import annotations

from typing import Any

from raa.domain.api import (
    ContractTestResult,
    DriftClassification,
    DriftFinding,
    FlowRecord,
    OpenAPISpec,
)
from raa.utils.ids import new_id
from raa.utils.time import utc_now

_VOLATILE_PROPERTY_NAMES = frozenset(
    {
        "timestamp",
        "nonce",
        "_t",
        "ts",
        "sig",
        "signature",
        "trace_id",
        "span_id",
        "request_id",
        "server_time",
        "generation_time",
    }
)


def _is_volatile(name: str) -> bool:
    """Check if field or parameter name is known volatile noise."""
    lower = name.lower()
    if lower in _VOLATILE_PROPERTY_NAMES:
        return True
    return any(v in lower for v in ("timestamp", "nonce", "signature", "req_id"))


def validate_contract_flow(spec: OpenAPISpec, flow: FlowRecord) -> ContractTestResult:
    """Validate a single observed network flow against the OpenAPI specification."""
    req = flow.request
    method = req.method.lower()
    path = req.path
    status_str = str(flow.response.status)

    # Find matching path template
    matched_op: dict[str, Any] | None = None
    matched_template: str = ""

    for template, methods in spec.paths.items():
        if method in methods:
            # Simple segment matching
            t_segs = template.strip("/").split("/")
            p_segs = path.strip("/").split("/")
            if len(t_segs) == len(p_segs):
                match = True
                for ts, ps in zip(t_segs, p_segs, strict=False):
                    if ts.startswith("{") and ts.endswith("}"):
                        continue
                    if ts != ps:
                        match = False
                        break
                if match:
                    matched_op = methods[method]
                    matched_template = template
                    break

    test_id = new_id("test")
    now = utc_now()

    if not matched_op:
        return ContractTestResult(
            test_id=test_id,
            operation_id="unknown",
            method=req.method,
            url=f"{req.scheme}://{req.host}{req.path}",
            passed=False,
            status_code_observed=flow.response.status,
            schema_valid=False,
            duration_ms=1.5,
            errors=[f"Endpoint '{method.upper()} {path}' not found in OpenAPI specification."],
            tested_at=now,
        )

    op_id = matched_op.get("operationId", f"{method}_{matched_template}")
    responses = matched_op.get("responses", {})
    expected_resp = responses.get(status_str)

    errors: list[str] = []
    if not expected_resp:
        errors.append(f"Status code {status_str} was not documented in spec.")

    # Validate response body required fields if schema present
    schema_valid = True
    if expected_resp and flow.response.body and flow.response.body.parsed_json:
        content_schema = (
            expected_resp.get("content", {}).get("application/json", {}).get("schema", {})
        )
        required_fields = content_schema.get("required", [])
        if isinstance(flow.response.body.parsed_json, dict):
            for rf in required_fields:
                if rf not in flow.response.body.parsed_json:
                    errors.append(f"Required property '{rf}' missing in response body.")
                    schema_valid = False

    passed = len(errors) == 0 and schema_valid
    return ContractTestResult(
        test_id=test_id,
        operation_id=op_id,
        method=req.method,
        url=f"{req.scheme}://{req.host}{req.path}",
        passed=passed,
        status_code_observed=flow.response.status,
        schema_valid=schema_valid,
        duration_ms=2.1,
        errors=errors,
        tested_at=now,
    )


def diff_contracts(
    base_spec: OpenAPISpec,
    new_spec: OpenAPISpec,
    ignore_volatile: bool = True,
) -> list[DriftFinding]:
    """Compare baseline spec against candidate spec and classify breaking vs additive drift."""
    findings: list[DriftFinding] = []
    now = utc_now()

    base_paths = base_spec.paths
    new_paths = new_spec.paths

    # 1. Removed paths or methods (BREAKING)
    for path, methods in base_paths.items():
        if path not in new_paths:
            findings.append(
                DriftFinding(
                    finding_id=new_id("drift"),
                    operation_id=f"path:{path}",
                    classification=DriftClassification.BREAKING,
                    description=f"Endpoint path '{path}' was removed.",
                    path=path,
                    old_value=list(methods.keys()),
                    new_value=None,
                    volatile_ignored=False,
                    detected_at=now,
                )
            )
            continue

        new_methods = new_paths[path]
        for m, op_def in methods.items():
            if m not in new_methods:
                findings.append(
                    DriftFinding(
                        finding_id=new_id("drift"),
                        operation_id=op_def.get("operationId", f"{m}_{path}"),
                        classification=DriftClassification.BREAKING,
                        description=f"HTTP method '{m.upper()} {path}' was removed.",
                        path=f"{path}::{m}",
                        old_value=m,
                        new_value=None,
                        volatile_ignored=False,
                        detected_at=now,
                    )
                )

    # 2. Added paths or methods (ADDITIVE)
    for path, methods in new_paths.items():
        if path not in base_paths:
            findings.append(
                DriftFinding(
                    finding_id=new_id("drift"),
                    operation_id=f"path:{path}",
                    classification=DriftClassification.ADDITIVE,
                    description=f"New endpoint path '{path}' was added.",
                    path=path,
                    old_value=None,
                    new_value=list(methods.keys()),
                    volatile_ignored=False,
                    detected_at=now,
                )
            )
            continue

        base_methods = base_paths[path]
        for m, op_def in methods.items():
            if m not in base_methods:
                findings.append(
                    DriftFinding(
                        finding_id=new_id("drift"),
                        operation_id=op_def.get("operationId", f"{m}_{path}"),
                        classification=DriftClassification.ADDITIVE,
                        description=f"New HTTP method '{m.upper()} {path}' was added.",
                        path=f"{path}::{m}",
                        old_value=None,
                        new_value=m,
                        volatile_ignored=False,
                        detected_at=now,
                    )
                )
                continue

            # Compare matching operations
            base_op = base_methods[m]
            op_id = op_def.get("operationId", f"{m}_{path}")

            # Check responses schemas drift
            base_resps = base_op.get("responses", {})
            new_resps = op_def.get("responses", {})

            for sc, b_resp in base_resps.items():
                if sc not in new_resps:
                    findings.append(
                        DriftFinding(
                            finding_id=new_id("drift"),
                            operation_id=op_id,
                            classification=DriftClassification.BREAKING,
                            description=f"Documented response status '{sc}' was removed.",
                            path=f"{path}::{m}::responses::{sc}",
                            old_value=sc,
                            new_value=None,
                            volatile_ignored=False,
                            detected_at=now,
                        )
                    )
                    continue

                n_resp = new_resps[sc]
                b_schema = b_resp.get("content", {}).get("application/json", {}).get("schema", {})
                n_schema = n_resp.get("content", {}).get("application/json", {}).get("schema", {})

                b_props = b_schema.get("properties", {})
                n_props = n_schema.get("properties", {})
                b_req = set(b_schema.get("required", []))
                n_req = set(n_schema.get("required", []))

                # Check required fields removed (BREAKING)
                for req_f in b_req:
                    if _is_volatile(req_f) and ignore_volatile:
                        continue
                    if req_f not in n_props or req_f not in n_req:
                        findings.append(
                            DriftFinding(
                                finding_id=new_id("drift"),
                                operation_id=op_id,
                                classification=DriftClassification.BREAKING,
                                description=(
                                    f"Required response field '{req_f}' "
                                    f"was removed or made optional in status {sc}."
                                ),
                                path=f"{path}::{m}::properties::{req_f}",
                                old_value="required",
                                new_value="optional/missing",
                                volatile_ignored=False,
                                detected_at=now,
                            )
                        )

                # Check optional fields added (ADDITIVE)
                for new_f in n_props:
                    if _is_volatile(new_f) and ignore_volatile:
                        continue
                    if new_f not in b_props:
                        findings.append(
                            DriftFinding(
                                finding_id=new_id("drift"),
                                operation_id=op_id,
                                classification=DriftClassification.ADDITIVE,
                                description=f"New field '{new_f}' was added to status {sc}.",
                                path=f"{path}::{m}::properties::{new_f}",
                                old_value=None,
                                new_value=n_props[new_f],
                                volatile_ignored=False,
                                detected_at=now,
                            )
                        )

                # Check volatile fields ignored
                if ignore_volatile:
                    for v_f in set(b_props.keys()) | set(n_props.keys()):
                        if _is_volatile(v_f):
                            findings.append(
                                DriftFinding(
                                    finding_id=new_id("drift"),
                                    operation_id=op_id,
                                    classification=DriftClassification.NOISE,
                                    description=(
                                        f"Volatile field '{v_f}' ignored during evaluation."
                                    ),
                                    path=f"{path}::{m}::properties::{v_f}",
                                    volatile_ignored=True,
                                    detected_at=now,
                                )
                            )

    return findings
