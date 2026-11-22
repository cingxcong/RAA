"""HTTP flow normalization, redaction, and header/parameter volatility classification."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from raa.domain.api import (
    HttpBody,
    HttpHeader,
    HttpQueryParam,
    ParamKind,
)

# Patterns for scrubbing credentials, bearer tokens, passwords, and credit card numbers
_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password|pwd|auth)[\s:=]+([a-zA-Z0-9_\-\.]{8,})"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
)

_AUTH_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "apikey",
        "x-access-token",
    }
)

_VOLATILE_NAMES = frozenset(
    {
        "nonce",
        "timestamp",
        "_t",
        "ts",
        "signature",
        "sig",
        "x-request-id",
        "x-amz-date",
        "x-amz-security-token",
        "client-timestamp",
        "traceparent",
    }
)

_CONSTANT_NAMES = frozenset(
    {
        "content-type",
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "host",
        "connection",
    }
)

_TRACKING_NAMES = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "gclid",
        "fbclid",
        "_ga",
    }
)


def redact_text(text: str) -> str:
    """Scrub sensitive credentials, tokens, and payment card numbers from text."""
    redacted = text
    redacted = _SECRET_PATTERNS[2].sub("Bearer [REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[0].sub(r"\1: [REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[1].sub("[REDACTED_CARD]", redacted)
    return redacted


def redact_json_value(val: Any) -> Any:
    """Recursively scrub sensitive fields in JSON objects or lists."""
    if isinstance(val, str):
        return redact_text(val)
    if isinstance(val, dict):
        out: dict[str, Any] = {}
        sensitive = ("password", "token", "secret", "apikey", "api_key", "credit_card")
        for k, v in val.items():
            k_lower = k.lower()
            if any(s in k_lower for s in sensitive):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_json_value(v)
        return out
    if isinstance(val, list):
        return [redact_json_value(item) for item in val]
    return val


def classify_param_name(name: str) -> ParamKind:
    """Classify volatility and purpose of a header or query parameter name."""
    lower = name.lower()
    if lower in _AUTH_HEADER_NAMES:
        return ParamKind.AUTH
    if lower in _VOLATILE_NAMES or any(v in lower for v in ("timestamp", "nonce", "sig")):
        return ParamKind.VOLATILE
    if lower in _TRACKING_NAMES or any(t in lower for t in ("utm_", "fbclid", "gclid")):
        return ParamKind.TRACKING
    if lower in _CONSTANT_NAMES:
        return ParamKind.CONSTANT
    return ParamKind.UNKNOWN


def normalize_header(name: str, value: str) -> HttpHeader:
    """Normalize and redact an HTTP header."""
    lower = name.lower()
    kind = classify_param_name(lower)
    is_auth = kind == ParamKind.AUTH
    redacted = is_auth or any(s in lower for s in ("token", "secret", "password", "key"))

    val = "[REDACTED]" if redacted else redact_text(value)

    return HttpHeader(
        name=name,
        value=val,
        redacted=redacted,
        kind=kind,
    )


def normalize_query_param(name: str, value: str) -> HttpQueryParam:
    """Normalize and redact an HTTP query parameter."""
    lower = name.lower()
    kind = classify_param_name(lower)
    is_auth = kind == ParamKind.AUTH or any(s in lower for s in ("token", "secret", "key", "auth"))
    redacted = is_auth

    val = "[REDACTED]" if redacted else redact_text(value)

    return HttpQueryParam(
        name=name,
        value=val,
        redacted=redacted,
        kind=kind,
    )


def normalize_body(
    raw_bytes: bytes | str | None, content_type: str = "application/json"
) -> HttpBody | None:
    """Normalize, hash, and redact request or response body content."""
    if raw_bytes is None:
        return None

    byte_data = raw_bytes.encode("utf-8") if isinstance(raw_bytes, str) else raw_bytes

    size = len(byte_data)
    sha256 = hashlib.sha256(byte_data).hexdigest()

    parsed_json: Any | None = None
    raw_text: str | None = None

    if "json" in content_type.lower():
        try:
            decoded = byte_data.decode("utf-8")
            obj = json.loads(decoded)
            parsed_json = redact_json_value(obj)
            raw_text = json.dumps(parsed_json)
        except Exception:
            raw_text = redact_text(byte_data.decode("utf-8", errors="replace"))
    elif any(t in content_type.lower() for t in ("text", "xml", "html", "form")):
        raw_text = redact_text(byte_data.decode("utf-8", errors="replace"))
    else:
        # Binary content stored by digest
        raw_text = f"[BINARY CONTENT: {size} bytes, sha256: {sha256[:12]}]"

    return HttpBody(
        content_type=content_type,
        size=size,
        sha256=sha256,
        raw_text=raw_text,
        parsed_json=parsed_json,
    )


def compute_flow_fingerprint(method: str, host: str, path: str, body_sha256: str = "") -> str:
    """Compute deterministic fingerprint for flow de-duplication."""
    key = f"{method.upper()}|{host.lower()}|{path.rstrip('/')}|{body_sha256}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
