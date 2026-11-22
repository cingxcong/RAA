"""Domain models for API reverse engineering studio: flows, operations, schemas, and contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from raa.utils.time import utc_now


class CaptureMode(StrEnum):
    """Network capture acquisition mode."""

    STATIC_ONLY = "static-only"
    PROXY = "proxy"
    IN_APP = "in-app"
    REPLAY = "replay"


class FlowSource(StrEnum):
    """Source provider for captured traffic flow."""

    INTERCEPTOR = "interceptor"
    PROXY = "proxy"
    PCAP = "pcap"
    HAR_IMPORT = "har_import"
    STATIC_CODE = "static_code"


class ParamKind(StrEnum):
    """Classification of header or query parameter volatility and purpose."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    CONSTANT = "constant"
    VOLATILE = "volatile"
    AUTH = "auth"
    TRACKING = "tracking"
    UNKNOWN = "unknown"


class DriftClassification(StrEnum):
    """Classification of contract evolution drift."""

    BREAKING = "breaking"
    POTENTIALLY_BREAKING = "potentially_breaking"
    ADDITIVE = "additive"
    COSMETIC = "cosmetic"
    NOISE = "noise"


class AuthSchemeType(StrEnum):
    """Detected authentication paradigm."""

    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    COOKIE = "cookie"
    UNKNOWN = "unknown"


class HttpHeader(BaseModel):
    """HTTP request or response header with redaction metadata."""

    name: str
    value: str
    redacted: bool = False
    kind: ParamKind = ParamKind.UNKNOWN


class HttpQueryParam(BaseModel):
    """HTTP URL query parameter with redaction metadata."""

    name: str
    value: str
    redacted: bool = False
    kind: ParamKind = ParamKind.UNKNOWN


class HttpBody(BaseModel):
    """HTTP payload body metadata and parsed contents."""

    content_type: str = "application/json"
    size: int = 0
    sha256: str = ""
    raw_text: str | None = None
    parsed_json: Any | None = None


class HttpRequest(BaseModel):
    """Normalized HTTP request record."""

    method: str
    scheme: str = "https"
    host: str
    path: str
    query: list[HttpQueryParam] = Field(default_factory=list)
    headers: list[HttpHeader] = Field(default_factory=list)
    body: HttpBody | None = None


class HttpResponse(BaseModel):
    """Normalized HTTP response record."""

    status: int
    headers: list[HttpHeader] = Field(default_factory=list)
    body: HttpBody | None = None


class FlowRecord(BaseModel):
    """Immutable, redacted app-to-backend network flow record."""

    flow_id: str
    capture_id: str
    project_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    request: HttpRequest
    response: HttpResponse
    source: FlowSource = FlowSource.PROXY
    call_site: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class OperationCluster(BaseModel):
    """De-duplicated operation catalogue entity with path templating."""

    operation_id: str
    method: str
    host: str
    path_template: str
    sample_count: int = 0
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    confidence: float = 1.0
    auth_scheme: AuthSchemeType | None = None
    auth_details: dict[str, Any] = Field(default_factory=dict)
    flow_ids: list[str] = Field(default_factory=list)
    path_parameters: list[dict[str, Any]] = Field(default_factory=list)
    query_parameters: list[dict[str, Any]] = Field(default_factory=list)
    headers: list[dict[str, Any]] = Field(default_factory=list)
    call_sites: list[str] = Field(default_factory=list)


class SchemaInference(BaseModel):
    """Inferred JSON schemas and field confidence metadata."""

    operation_id: str
    request_schema: dict[str, Any] = Field(default_factory=dict)
    response_schemas: dict[str, dict[str, Any]] = Field(default_factory=dict)
    field_metadata: dict[str, Any] = Field(default_factory=dict)
    inferred_at: datetime = Field(default_factory=utc_now)


class OpenAPISpec(BaseModel):
    """Complete OpenAPI 3.1 specification document model."""

    spec_id: str
    project_id: str
    openapi_version: str = "3.1.0"
    title: str = "Inferred App API"
    version: str = "1.0.0"
    servers: list[dict[str, Any]] = Field(default_factory=list)
    paths: dict[str, Any] = Field(default_factory=dict)
    components: dict[str, Any] = Field(default_factory=dict)
    extensions: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=utc_now)
    raw_yaml: str | None = None


class ClientGenerationResult(BaseModel):
    """Result of generating and smoke-testing an API client."""

    client_id: str
    project_id: str
    language: str = "python"
    spec_digest: str
    target_dir: str
    files_written: list[str] = Field(default_factory=list)
    compiles: bool = True
    smoke_test_passed: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class ContractTestResult(BaseModel):
    """Result of validating an operation against an authorized test environment."""

    test_id: str
    operation_id: str
    method: str
    url: str
    passed: bool
    status_code_observed: int
    schema_valid: bool
    duration_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)
    tested_at: datetime = Field(default_factory=utc_now)


class DriftFinding(BaseModel):
    """Detected schema or contract drift between two captures or versions."""

    finding_id: str
    operation_id: str
    classification: DriftClassification
    description: str
    path: str
    old_value: Any | None = None
    new_value: Any | None = None
    volatile_ignored: bool = False
    detected_at: datetime = Field(default_factory=utc_now)


class CaptureSession(BaseModel):
    """Authorized network capture session tracking flows and targets."""

    session_id: str
    project_id: str
    mode: CaptureMode = CaptureMode.PROXY
    target_hosts: list[str] = Field(default_factory=list)
    active: bool = True
    flow_count: int = 0
    started_at: datetime = Field(default_factory=utc_now)
    stopped_at: datetime | None = None
