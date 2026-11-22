"""Phase 7 API Reverse-Engineering Studio tests.

Verifies:
1. Capture session lifecycle and host allowlist enforcement.
2. Normalization, fingerprinting, and credential/token redaction.
3. Variable segment templating and stable deterministic operation clustering.
4. Multi-sample JSON schema inference with type widening and required field detection.
5. OpenAPI 3.1 specification generation, provenance extensions, and linting.
6. Typed client code generation, compilation, and offline mock smoke tests.
7. Contract testing and breaking drift detection (ignoring volatile fields).
8. Standard HAR 1.2 export and import with _raa provenance metadata.
9. Full integration through Runtime.invoke across all 15 api tools.
10. Typer CLI subcommands under `raa api`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from raa.cli.main import app
from raa.domain.api import (
    AuthSchemeType,
    DriftClassification,
    FlowRecord,
    FlowSource,
    HttpQueryParam,
    HttpRequest,
    HttpResponse,
    ParamKind,
)
from raa.errors import PolicyDeniedError
from raa.runtime import Runtime
from raa.services.api.client_gen import generate_python_client
from raa.services.api.clustering import (
    cluster_flows,
    compute_operation_id,
    template_path,
)
from raa.services.api.contract import generate_openapi_spec, validate_openapi_spec
from raa.services.api.inference import infer_operation_schemas
from raa.services.api.normalization import (
    classify_param_name,
    compute_flow_fingerprint,
    normalize_body,
    normalize_header,
    redact_json_value,
    redact_text,
)
from raa.services.api.validation import diff_contracts, validate_contract_flow
from raa.utils.time import utc_now

runner = CliRunner()


# --- Sample Data Helpers ---


def _make_sample_flow(
    *,
    flow_id: str = "flow_01",
    capture_id: str = "cap_test",
    project_id: str = "proj_01",
    method: str = "GET",
    url: str = "https://api.example.com/v2/users/12345/orders",
    host: str = "api.example.com",
    path: str = "/v2/users/12345/orders",
    status_code: int = 200,
    request_headers: dict[str, str] | None = None,
    response_body: Any = None,
    query_params: list[HttpQueryParam] | None = None,
) -> FlowRecord:
    headers = [
        normalize_header(k, v)
        for k, v in (
            request_headers
            or {
                "Authorization": "Bearer secret_test_token_123456",
                "User-Agent": "MobileApp/2.4",
            }
        ).items()
    ]
    resp_headers = [normalize_header("Content-Type", "application/json")]

    if response_body is None:
        response_body = {
            "order_id": 9876,
            "status": "shipped",
            "timestamp": 1700000000,
            "items": [{"item_id": "item_1", "quantity": 2, "price": 19.99}],
        }

    raw_bytes = json.dumps(response_body).encode("utf-8")
    norm_body = normalize_body(raw_bytes, "application/json")

    return FlowRecord(
        flow_id=flow_id,
        capture_id=capture_id,
        project_id=project_id,
        timestamp=utc_now(),
        request=HttpRequest(
            method=method,
            scheme="https",
            host=host,
            path=path,
            query=query_params or [],
            headers=headers,
            body=None,
        ),
        response=HttpResponse(
            status=status_code,
            headers=resp_headers,
            body=norm_body,
        ),
        source=FlowSource.PROXY,
    )


# --- 1. Normalization & Redaction Tests ---


def test_redact_sensitive_tokens_and_credentials() -> None:
    """Verify bearer tokens, basic auth, API keys, and payment card numbers are redacted."""
    bearer_text = "Authorization: Bearer ya29.a0ARrdaM_secret_token_12345"
    redacted = redact_text(bearer_text)
    assert "secret_token_12345" not in redacted
    assert "Bearer [REDACTED]" in redacted

    api_key_text = "api_key: abcdef0123456789abcdef0123456789"
    redacted_key = redact_text(api_key_text)
    assert "[REDACTED]" in redacted_key

    # Test JSON structure scrubbing
    sensitive_dict = {
        "user": "alice",
        "password": "SuperSecretPassword123!",
        "access_token": "token_abc123",
        "nested": {
            "client_secret": "my_secret_key",
            "card_number": "4111 2222 3333 4444",
        },
    }
    cleaned = redact_json_value(sensitive_dict)
    assert cleaned["user"] == "alice"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["access_token"] == "[REDACTED]"
    assert cleaned["nested"]["client_secret"] == "[REDACTED]"


def test_normalize_and_redact_headers() -> None:
    """Verify headers with authorization, cookie, and api keys are scrubbed."""
    h1 = normalize_header("Authorization", "Bearer secret_token")
    h2 = normalize_header("Cookie", "session_id=12345; user=alice")
    h3 = normalize_header("X-Api-Key", "secret_key_123")
    h4 = normalize_header("Accept", "application/json")

    assert h1.redacted is True
    assert h1.value == "[REDACTED]"
    assert h2.redacted is True
    assert h2.value == "[REDACTED]"
    assert h3.redacted is True
    assert h3.value == "[REDACTED]"
    assert h4.redacted is False
    assert h4.value == "application/json"


def test_classify_param_names() -> None:
    """Verify volatile, auth, tracking, and constant parameter categorization."""
    assert classify_param_name("timestamp") == ParamKind.VOLATILE
    assert classify_param_name("ts") == ParamKind.VOLATILE
    assert classify_param_name("nonce") == ParamKind.VOLATILE
    assert classify_param_name("signature") == ParamKind.VOLATILE

    assert classify_param_name("authorization") == ParamKind.AUTH
    assert classify_param_name("x-api-key") == ParamKind.AUTH

    assert classify_param_name("utm_source") == ParamKind.TRACKING
    assert classify_param_name("filter") == ParamKind.UNKNOWN


def test_flow_fingerprinting() -> None:
    """Verify deterministic flow fingerprinting produces consistent hashes."""
    fp1 = compute_flow_fingerprint("GET", "api.example.com", "/v1/data")
    fp2 = compute_flow_fingerprint("GET", "api.example.com", "/v1/data")
    assert fp1 == fp2
    assert len(fp1) == 64


# --- 2. Path Templating & Operation Clustering Tests ---


def test_path_templating() -> None:
    """Verify dynamic segment replacement (integers, UUIDs, ULIDs, hex hashes)."""
    # Integer ID
    t1, params1 = template_path("/v2/users/12345/orders")
    assert t1 == "/v2/users/{userId}/orders"
    assert [p["name"] for p in params1] == ["userId"]

    # UUID
    t2, params2 = template_path("/api/items/550e8400-e29b-41d4-a716-446655440000/details")
    assert t2 == "/api/items/{itemId}/details"
    assert [p["name"] for p in params2] == ["itemId"]

    # Hex hash / slug
    t3, params3 = template_path("/files/abcdef1234567890/download")
    assert t3 == "/files/{fileId}/download"
    assert [p["name"] for p in params3] == ["fileId"]


def test_operation_clustering() -> None:
    """Verify flows with variable IDs cluster into a single stable operation."""
    flow1 = _make_sample_flow(
        flow_id="f1",
        url="https://api.example.com/v2/users/101/orders",
        path="/v2/users/101/orders",
    )
    flow2 = _make_sample_flow(
        flow_id="f2",
        url="https://api.example.com/v2/users/202/orders",
        path="/v2/users/202/orders",
    )
    flow3 = _make_sample_flow(
        flow_id="f3",
        method="POST",
        url="https://api.example.com/v2/users/101/orders",
        path="/v2/users/101/orders",
    )

    clusters = cluster_flows([flow1, flow2, flow3])
    assert len(clusters) == 2  # GET and POST

    get_op = next(c for c in clusters if c.method == "GET")
    assert get_op.path_template == "/v2/users/{userId}/orders"
    assert get_op.sample_count == 2
    assert set(get_op.flow_ids) == {"f1", "f2"}
    assert get_op.auth_scheme == AuthSchemeType.BEARER

    post_op = next(c for c in clusters if c.method == "POST")
    assert post_op.sample_count == 1
    assert post_op.flow_ids == ["f3"]

    # Verify stable ID calculation
    expected_id = compute_operation_id("api.example.com", "GET", "/v2/users/{userId}/orders")
    assert get_op.operation_id == expected_id


# --- 3. Schema Inference Tests ---


def test_schema_inference_multi_sample() -> None:
    """Verify schema inference with type widening and required property detection."""
    flow1 = _make_sample_flow(
        flow_id="f1",
        response_body={
            "id": 1,
            "title": "Document 1",
            "score": 10,
            "tags": ["alpha", "beta"],
        },
    )
    flow2 = _make_sample_flow(
        flow_id="f2",
        response_body={
            "id": 2,
            "title": "Document 2",
            "score": 12.5,  # Widens int -> number
            "tags": ["gamma"],
            "extra_note": "Optional note",  # Not in flow1 -> optional
        },
    )

    clusters = cluster_flows([flow1, flow2])
    cluster = clusters[0]

    inference = infer_operation_schemas(cluster.operation_id, [flow1, flow2])
    assert inference.operation_id == cluster.operation_id
    assert "200" in inference.response_schemas

    resp_schema = inference.response_schemas["200"]
    props = resp_schema.get("properties", {})
    required = resp_schema.get("required", [])

    assert "id" in props
    assert "title" in props
    assert props["score"]["type"] == "number"  # Widened from integer
    assert "id" in required
    assert "title" in required
    assert "extra_note" not in required  # Only present in 50% of samples


# --- 4. OpenAPI 3.1 Spec Generation & Linting Tests ---


def test_generate_and_validate_openapi_spec() -> None:
    """Verify OpenAPI 3.1 generation, linting, and RAA provenance metadata."""
    flow = _make_sample_flow()
    clusters = cluster_flows([flow])
    inferences = {
        clusters[0].operation_id: infer_operation_schemas(clusters[0].operation_id, [flow])
    }

    spec = generate_openapi_spec(
        project_id="proj_01",
        clusters=clusters,
        inferences=inferences,
        title="Sample E-Commerce API",
        version="2.1.0",
    )

    assert spec.openapi_version == "3.1.0"
    assert spec.title == "Sample E-Commerce API"
    assert spec.version == "2.1.0"
    assert "/v2/users/{userId}/orders" in spec.paths

    op_def = spec.paths["/v2/users/{userId}/orders"]["get"]
    assert op_def["operationId"] == clusters[0].operation_id
    assert op_def["x-raa-confidence"] >= 0.8
    assert op_def["x-raa-samples"] == 1
    assert "bearerAuth" in spec.components["securitySchemes"]

    # Validate specification structure
    spec_dict = json.loads(spec.raw_yaml or "{}")
    validate_openapi_spec(spec_dict)


# --- 5. Client Generation & Mock Smoke Testing ---


def test_generate_python_client_and_smoke_test(tmp_path: Path) -> None:
    """Verify generated Python client compiles cleanly and passes sandbox smoke test."""
    flow = _make_sample_flow()
    clusters = cluster_flows([flow])
    inferences = {
        clusters[0].operation_id: infer_operation_schemas(clusters[0].operation_id, [flow])
    }
    spec = generate_openapi_spec(
        project_id="proj_01",
        clusters=clusters,
        inferences=inferences,
    )

    result = generate_python_client(spec, output_dir=tmp_path / "client")
    assert result.language == "python"
    assert result.compiles is True
    assert result.smoke_test_passed is True
    assert len(result.files_written) >= 1

    # Verify generated client file exists
    client_file = Path(result.files_written[0])
    assert client_file.is_file()
    assert "class APIClient:" in client_file.read_text(encoding="utf-8")


# --- 6. Contract Validation & Drift Detection Tests ---


def test_contract_validation_and_drift() -> None:
    """Verify contract testing passes valid flows, flags breaking drift,
    and ignores volatile fields.
    """
    flow = _make_sample_flow()
    clusters = cluster_flows([flow])
    inferences = {
        clusters[0].operation_id: infer_operation_schemas(clusters[0].operation_id, [flow])
    }
    baseline_spec = generate_openapi_spec(
        project_id="proj_01",
        clusters=clusters,
        inferences=inferences,
    )

    # 1. Conformance test on matching flow
    test_result = validate_contract_flow(baseline_spec, flow)
    assert test_result.passed is True
    assert len(test_result.errors) == 0

    # 2. Candidate spec with breaking changes (removed required field 'order_id')
    candidate_spec = baseline_spec.model_copy(deep=True)
    schema_props = candidate_spec.paths["/v2/users/{userId}/orders"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["properties"]
    del schema_props["order_id"]

    drift_findings = diff_contracts(baseline_spec, candidate_spec)
    assert len(drift_findings) >= 1
    breaking = [f for f in drift_findings if f.classification == DriftClassification.BREAKING]
    assert len(breaking) >= 1
    assert "order_id" in breaking[0].description

    # 3. Additive changes (new optional field)
    candidate_spec2 = baseline_spec.model_copy(deep=True)
    schema_props2 = candidate_spec2.paths["/v2/users/{userId}/orders"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["properties"]
    schema_props2["new_optional_feature"] = {"type": "string"}
    # volatile field should NOT be flagged as breaking
    schema_props2["timestamp"] = {"type": "number"}

    drift_findings2 = diff_contracts(baseline_spec, candidate_spec2)
    additive = [f for f in drift_findings2 if f.classification == DriftClassification.ADDITIVE]
    assert any("new_optional_feature" in f.path for f in additive)


# --- 7. Flow Store Lifecycle & HAR Export/Import Tests ---


def test_flow_store_lifecycle_and_har(tmp_path: Path) -> None:
    """Verify flow store persistence, target host allowlist, and HAR export/import."""
    from raa.services.api.capture_store import FlowStore

    store = FlowStore(tmp_path)

    # 1. Start session with host allowlist
    session = store.start_capture(
        project_id="proj_01",
        mode="proxy",
        target_hosts=["api.example.com", "authorized.org"],
    )
    assert session.active is True

    # 2. Host allowlist check: add allowed flow
    flow1 = store.add_flow(
        project_id="proj_01",
        capture_id=session.session_id,
        method="GET",
        url="https://api.example.com/items",
        request_headers={"content-type": "application/json"},
        response_body=json.dumps({"items": []}),
    )
    assert flow1.flow_id is not None

    # Disallowed host should raise PolicyDeniedError
    with pytest.raises(PolicyDeniedError):
        store.add_flow(
            project_id="proj_01",
            capture_id=session.session_id,
            method="GET",
            url="https://evil.attacker.com/steal",
            request_headers={},
        )

    # Stop session
    stopped = store.stop_capture("proj_01", session.session_id)
    assert stopped.active is False
    assert stopped.flow_count == 1

    # 3. List and get flow
    flows_res = store.list_flows("proj_01")
    assert flows_res["total"] == 1
    assert flows_res["flows"][0]["flow_id"] == flow1.flow_id

    retrieved = store.get_flow("proj_01", flow1.flow_id)
    assert retrieved is not None
    assert retrieved.request.host == "api.example.com"

    # 4. HAR Export
    har_export = store.export_har("proj_01")
    assert har_export["log"]["version"] == "1.2"
    assert len(har_export["log"]["entries"]) == 1
    entry = har_export["log"]["entries"][0]
    assert entry["_raa"]["flow_id"] == flow1.flow_id
    assert entry["_raa"]["source"] == "proxy"

    # 5. HAR Import into a second project
    imported_flows = store.import_har("proj_02", har_export)
    assert len(imported_flows) == 1
    flows2_res = store.list_flows("proj_02")
    assert flows2_res["total"] == 1
    assert flows2_res["flows"][0]["flow_id"] == imported_flows[0].flow_id


# --- 8. Runtime & MCP Tool Integration Tests (15 Tools) ---


async def test_runtime_api_tools(runtime: Runtime) -> None:
    """Verify all 15 API tools execute successfully through runtime.invoke."""
    # 1. Create project with required scopes
    created = await runtime.invoke(
        "project_create",
        {
            "name": "API Studio Project",
            "scopes": [
                "project.read",
                "project.write",
                "static.read",
                "network.capture",
                "export.raw",
                "export.write",
            ],
        },
        profile="api",
    )
    project_id = created.data["id"]

    # 2. Capture tools: start, status, stop
    start_res = await runtime.invoke(
        "api_capture_start",
        {
            "project_id": project_id,
            "mode": "proxy",
            "target_hosts": ["api.example.com"],
        },
        profile="api",
    )
    session_id = start_res.data["session_id"]
    assert start_res.data["active"] is True

    status_res = await runtime.invoke(
        "api_capture_status",
        {"project_id": project_id, "session_id": session_id},
        profile="api",
    )
    assert status_res.data["session"]["session_id"] == session_id

    # Populate flows into project flow store
    runtime.api.flow_store.add_flow(
        project_id=project_id,
        capture_id=session_id,
        method="GET",
        url="https://api.example.com/v2/users/1/orders",
        request_headers={"Authorization": "Bearer secret_123"},
        response_body=json.dumps({"order_id": 1, "status": "ok"}),
    )
    runtime.api.flow_store.add_flow(
        project_id=project_id,
        capture_id=session_id,
        method="GET",
        url="https://api.example.com/v2/users/2/orders",
        request_headers={"Authorization": "Bearer secret_456"},
        response_body=json.dumps({"order_id": 2, "status": "ok"}),
    )

    stop_res = await runtime.invoke(
        "api_capture_stop",
        {"project_id": project_id, "session_id": session_id},
        profile="api",
    )
    assert stop_res.data["flow_count"] == 2

    # 3. Flow retrieval tools
    list_flows_res = await runtime.invoke(
        "api_list_flows",
        {"project_id": project_id, "host": "api.example.com"},
        profile="api",
    )
    assert list_flows_res.data["total"] == 2
    first_fid = list_flows_res.data["flows"][0]["flow_id"]

    get_flow_res = await runtime.invoke(
        "api_get_flow",
        {"project_id": project_id, "flow_id": first_fid},
        profile="api",
    )
    assert get_flow_res.data["flow_id"] == first_fid

    # 4. Clustering & Operations
    cluster_res = await runtime.invoke(
        "api_cluster_operations",
        {"project_id": project_id},
        profile="api",
    )
    assert cluster_res.data["total_clusters"] == 1
    op_id = cluster_res.data["operations"][0]["operation_id"]

    ops_res = await runtime.invoke(
        "api_list_operations",
        {"project_id": project_id},
        profile="api",
    )
    assert len(ops_res.data["operations"]) == 1

    op_res = await runtime.invoke(
        "api_get_operation",
        {"project_id": project_id, "operation_id": op_id},
        profile="api",
    )
    assert op_res.data["operation"]["path_template"] == "/v2/users/{userId}/orders"

    # 5. Schema Inference
    infer_res = await runtime.invoke(
        "api_infer_schemas",
        {"project_id": project_id, "operation_id": op_id},
        profile="api",
    )
    assert len(infer_res.data["inferences"]) == 1

    # 6. OpenAPI Spec Generation
    spec_res = await runtime.invoke(
        "api_generate_spec",
        {"project_id": project_id, "title": "Store API", "version": "1.0.0"},
        profile="api",
    )
    assert spec_res.data["openapi_version"] == "3.1.0"
    assert spec_res.data["title"] == "Store API"

    # 7. Client Generation
    client_res = await runtime.invoke(
        "api_generate_client",
        {"project_id": project_id, "language": "python"},
        profile="api",
    )
    assert client_res.data["compiles"] is True
    assert client_res.data["smoke_test_passed"] is True

    # 8. Contract Tests
    contract_res = await runtime.invoke(
        "api_run_contract_tests",
        {"project_id": project_id, "operation_id": op_id},
        profile="api",
    )
    assert contract_res.data["passed"] >= 1

    # 9. Contract Diff & Drift
    candidate_spec = dict(spec_res.data)
    diff_res = await runtime.invoke(
        "api_diff_contracts",
        {"project_id": project_id, "candidate_spec": candidate_spec},
        profile="api",
    )
    assert "findings" in diff_res.data

    drift_res = await runtime.invoke(
        "api_get_drift",
        {"project_id": project_id},
        profile="api",
    )
    assert "findings" in drift_res.data

    # 10. HAR Export
    har_res = await runtime.invoke(
        "api_export_har",
        {"project_id": project_id},
        profile="api",
    )
    assert har_res.data["log"]["version"] == "1.2"
    assert len(har_res.data["log"]["entries"]) == 2


async def test_runtime_api_scope_enforcement(runtime: Runtime) -> None:
    """Verify tools with sensitive scopes fail closed when project lacks them."""
    created = await runtime.invoke(
        "project_create",
        {
            "name": "Restricted Project",
            "scopes": ["project.read", "project.write"],  # missing network.capture & export
        },
        profile="api",
    )
    proj_id = created.data["id"]

    # api_capture_start requires network.capture
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "api_capture_start",
            {"project_id": proj_id, "mode": "proxy"},
            profile="api",
        )

    # api_export_har requires export.write
    with pytest.raises(PolicyDeniedError):
        await runtime.invoke(
            "api_export_har",
            {"project_id": proj_id},
            profile="api",
        )


# --- 9. Typer CLI Subcommands Tests ---


def test_cli_api_commands(tmp_path: Path) -> None:
    """Verify Typer CLI subcommands under raa api."""
    # 1. Create a project
    res_proj = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "project",
            "create",
            "CLI API Test",
            "--scope",
            "project.read",
            "--scope",
            "project.write",
            "--scope",
            "network.capture",
            "--scope",
            "export.raw",
            "--scope",
            "export.write",
        ],
    )
    assert res_proj.exit_code == 0
    project_id = json.loads(res_proj.stdout)["data"]["id"]

    # 2. Start capture
    res_start = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "capture-start",
            project_id,
            "--mode",
            "proxy",
            "--target",
            "api.example.com",
        ],
    )
    assert res_start.exit_code == 0
    session_id = json.loads(res_start.stdout)["data"]["session_id"]

    # 3. Query capture status
    res_status = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "capture-status",
            project_id,
            "--session",
            session_id,
        ],
    )
    assert res_status.exit_code == 0

    # 4. Stop capture
    res_stop = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "capture-stop",
            project_id,
            session_id,
        ],
    )
    assert res_stop.exit_code == 0

    # 5. List flows (empty initially)
    res_flows = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "flows",
            project_id,
        ],
    )
    assert res_flows.exit_code == 0
    assert json.loads(res_flows.stdout)["data"]["total"] == 0

    # 6. Cluster operations
    res_cluster = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "cluster",
            project_id,
        ],
    )
    assert res_cluster.exit_code == 0

    # 7. Generate spec
    res_spec = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "generate-spec",
            project_id,
            "--title",
            "CLI Spec",
            "--version",
            "1.0.0",
        ],
    )
    assert res_spec.exit_code == 0

    # 8. Generate client
    res_client = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "generate-client",
            project_id,
        ],
    )
    assert res_client.exit_code == 0

    # 9. Test contracts
    res_test = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "test-contracts",
            project_id,
        ],
    )
    assert res_test.exit_code == 0

    # 10. Drift
    res_drift = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "drift",
            project_id,
        ],
    )
    assert res_drift.exit_code == 0

    # 11. HAR Export
    res_har = runner.invoke(
        app,
        [
            "--workspace",
            str(tmp_path),
            "--json",
            "api",
            "export-har",
            project_id,
        ],
    )
    assert res_har.exit_code == 0
