"""SafeLine-inspired Semantic WAF and AST Injection Vulnerability Scanner.

Parses mobile API request payloads, query strings, and headers into syntactic
token streams to detect SQLi, CMDi, NoSQLi, and Path Traversal anomalies without
relying solely on fragile regular expression signatures.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

# Semantic token definitions for SQLi AST analysis
SQL_KEYWORDS = {
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "union",
    "where",
    "having",
    "or",
    "and",
    "xor",
    "sleep",
    "benchmark",
    "waitfor",
}

CMDI_PATTERNS = [
    r"(\||;|&&|\$\(|\`)\s*(cat|ls|whoami|id|sh|bash|curl|wget|nc|netcat|rm|kill)\b",
    r"(\/bin\/(sh|bash|dash|zsh))",
    r"(\bcmd\.exe|\bpowershell\.exe)",
]

TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f)",
    r"(\/etc\/(passwd|shadow|hosts)|c:\\boot\.ini)",
]


def _tokenize_sql(val: str) -> list[str]:
    """Tokenize a string into syntactic tokens for SQL AST analysis."""
    # Split by operators, whitespace, quotes, and punctuation
    tokens = re.findall(r"[a-zA-Z0-9_]+|'|\"|--|\/\*|\*\/|[=<>!]+|;|\(|\)", val)
    return [t.lower() for t in tokens]


def _detect_sqli_anomaly(value_str: str) -> dict[str, Any] | None:
    """Analyze token sequence for SQL syntax tree anomalies."""
    tokens = _tokenize_sql(value_str)
    if not tokens:
        return None

    # Tautology check on unquoted token stream (e.g. ["or", "1", "=", "1"])
    clean_tokens = [t for t in tokens if t not in {"'", '"'}]
    for i in range(len(clean_tokens) - 3):
        if (
            clean_tokens[i] in {"or", "and"}
            and clean_tokens[i + 2] in {"=", "=="}
            and clean_tokens[i + 1] == clean_tokens[i + 3]
        ):
            return {
                "type": "SQLI_TAUTOLOGY",
                "severity": "CRITICAL",
                "matched_tokens": clean_tokens[i : i + 4],
                "detail": "Boolean tautology condition identified in token stream",
            }

    # UNION SELECT pattern
    if "union" in tokens and "select" in tokens:
        return {
            "type": "SQLI_UNION_SELECT",
            "severity": "CRITICAL",
            "matched_tokens": ["union", "select"],
            "detail": "UNION SELECT injection vector detected",
        }

    # Stacked queries with dangerous DDL/DML
    if ";" in tokens:
        semi_idx = tokens.index(";")
        following = tokens[semi_idx + 1 : semi_idx + 4]
        if any(f in {"drop", "delete", "truncate", "update"} for f in following):
            return {
                "type": "SQLI_STACKED_QUERY",
                "severity": "CRITICAL",
                "matched_tokens": [";", *following],
                "detail": "Stacked SQL query statement found",
            }

    # Time-based blind execution
    if any(k in tokens for k in {"sleep", "benchmark", "waitfor"}):
        return {
            "type": "SQLI_TIME_BLIND",
            "severity": "HIGH",
            "matched_tokens": [t for t in tokens if t in {"sleep", "benchmark", "waitfor"}],
            "detail": "Time-delay blind injection signature detected",
        }

    return None


def _detect_cmdi_anomaly(value_str: str) -> dict[str, Any] | None:
    """Analyze string for shell command execution chaining."""
    decoded = unquote(value_str)
    for pattern in CMDI_PATTERNS:
        match = re.search(pattern, decoded, re.IGNORECASE)
        if match:
            return {
                "type": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "matched_pattern": match.group(0),
                "detail": f"Shell command metacharacter and execution pattern: {match.group(0)}",
            }
    return None


def _detect_traversal_anomaly(value_str: str) -> dict[str, Any] | None:
    """Analyze string for path traversal and file inclusion."""
    decoded = unquote(value_str)
    for pattern in TRAVERSAL_PATTERNS:
        match = re.search(pattern, decoded, re.IGNORECASE)
        if match:
            return {
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "matched_pattern": match.group(0),
                "detail": f"Directory traversal sequence detected: {match.group(0)}",
            }
    return None


def _detect_nosqli_anomaly(value: Any) -> dict[str, Any] | None:
    """Analyze structure for NoSQL query operator injection ($gt, $ne, $where)."""
    val_str = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
    if re.search(r'("\$ne"|"\$gt"|"\$gte"|"\$where"|"\$regex")', val_str):
        return {
            "type": "NOSQL_OPERATOR_INJECTION",
            "severity": "HIGH",
            "matched_pattern": "NoSQL special selector operators ($ne, $gt, $where)",
            "detail": "Object keys contain unescaped NoSQL operator syntax",
        }
    return None


def audit_semantic_waf(
    endpoint_url: str,
    http_method: str = "GET",
    query_params: dict[str, Any] | None = None,
    request_body: str | dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Execute SafeLine-inspired AST semantic audit on mobile API requests."""
    parsed_url = urlparse(endpoint_url)
    all_inputs: list[tuple[str, str, Any]] = []

    # Parse query parameters from URL and explicit query_params dict
    if parsed_url.query:
        for k, vals in parse_qs(parsed_url.query).items():
            for v in vals:
                all_inputs.append(("query", k, v))

    if query_params:
        for k, v in query_params.items():
            all_inputs.append(("query_dict", k, v))

    # Headers
    if headers:
        for k, v in headers.items():
            if k.lower() in {"authorization", "user-agent", "x-forwarded-for", "cookie"}:
                all_inputs.append(("header", k, v))

    # Body
    if request_body:
        if isinstance(request_body, dict):
            for k, v in request_body.items():
                all_inputs.append(("body_param", k, v))
        else:
            all_inputs.append(("body_raw", "raw", request_body))

    anomalies = []
    for loc, name, val in all_inputs:
        val_str = str(val)

        # SQLi
        sqli = _detect_sqli_anomaly(val_str)
        if sqli:
            anomalies.append({**sqli, "location": loc, "parameter": name, "value": val_str})

        # CMDi
        cmdi = _detect_cmdi_anomaly(val_str)
        if cmdi:
            anomalies.append({**cmdi, "location": loc, "parameter": name, "value": val_str})

        # Traversal
        traversal = _detect_traversal_anomaly(val_str)
        if traversal:
            anomalies.append({**traversal, "location": loc, "parameter": name, "value": val_str})

        # NoSQLi
        nosqli = _detect_nosqli_anomaly(val)
        if nosqli:
            anomalies.append({**nosqli, "location": loc, "parameter": name, "value": val_str})

    has_critical = any(a.get("severity") == "CRITICAL" for a in anomalies)
    has_high = any(a.get("severity") == "HIGH" for a in anomalies)

    risk_level = "CLEAN"
    if has_critical:
        risk_level = "CRITICAL"
    elif has_high:
        risk_level = "HIGH"
    elif anomalies:
        risk_level = "MEDIUM"

    recommendations = []
    if any("SQLI" in a.get("type", "") for a in anomalies):
        recommendations.append("Enforce parameterized queries (PreparedStatements / ORM bindings).")
    if any("COMMAND" in a.get("type", "") for a in anomalies):
        recommendations.append("Disallow system shell invocations; validate against strict regex.")
    if any("TRAVERSAL" in a.get("type", "") for a in anomalies):
        recommendations.append("Sanitize file paths with basename() or canonical path resolution.")
    if any("NOSQL" in a.get("type", "") for a in anomalies):
        recommendations.append("Strip dollar-sign operator prefixes ($) from JSON input objects.")
    if not recommendations:
        recommendations.append("Request conforms to syntactic baseline; continue defense-in-depth.")

    return {
        "status": "AUDIT_COMPLETE",
        "endpoint_url": endpoint_url,
        "http_method": http_method.upper(),
        "total_inputs_analyzed": len(all_inputs),
        "anomalies_detected": len(anomalies),
        "risk_level": risk_level,
        "blocked_by_waf": len(anomalies) > 0,
        "anomalies": anomalies,
        "recommendations": recommendations,
    }
