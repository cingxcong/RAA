"""Secret and credential scanner with mandatory redaction and entropy scoring."""

from __future__ import annotations

import math
import re
import uuid
import zipfile
from collections import Counter
from pathlib import Path

from raa.domain.security import SecretFinding

# Secret patterns with capture groups
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("google_api_key", re.compile(r"\b(AIzaSy[0-9A-Za-z-_]{33})\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")),
    (
        "jwt_token",
        re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
    ),
    (
        "private_key",
        re.compile(
            r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC )?PRIVATE KEY-----)"
        ),
    ),
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a text string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact_secret(raw: str, visible_prefix: int = 6) -> str:
    """Mask sensitive string content so plaintext is never exposed."""
    if len(raw) <= visible_prefix:
        return "****"
    prefix = raw[:visible_prefix]
    return f"{prefix}...****"


def scan_secrets(
    apk_path: Path,
    artifact_id: str,
    *,
    min_entropy: float = 4.2,
) -> list[SecretFinding]:
    """Scan container files, resources, and DEX strings for embedded credentials."""
    findings: list[SecretFinding] = []
    if not apk_path.is_file():
        return findings

    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            # Skip large media and font assets
            if name.endswith((".png", ".jpg", ".webp", ".ttf", ".otf", ".wav", ".mp3")):
                continue

            try:
                content_bytes = zf.read(name)
            except (KeyError, zipfile.BadZipFile, OSError):
                continue

            if len(content_bytes) > 5_000_000:
                continue

            text = content_bytes.decode("latin1", errors="replace")

            # 1. Pattern-based secret matching
            for kind, pat in _SECRET_PATTERNS:
                for match in pat.finditer(text):
                    secret_val = match.group(1)
                    entropy = _shannon_entropy(secret_val)
                    redacted = _redact_secret(secret_val)

                    findings.append(
                        SecretFinding(
                            secret_id=f"sec_{uuid.uuid4().hex[:10]}",
                            artifact_id=artifact_id,
                            kind=kind,
                            location=name,
                            redacted_value=redacted,
                            entropy=round(entropy, 2),
                        )
                    )

            # 2. High-entropy generic secret strings (skip binary tables and long bytecode blocks)
            if name.startswith("res/values/") or name.endswith(".json") or name.endswith(".xml"):
                for token in re.findall(r'"([a-zA-Z0-9+/=_-]{24,64})"', text):
                    ent = _shannon_entropy(token)
                    if ent >= min_entropy:
                        findings.append(
                            SecretFinding(
                                secret_id=f"sec_{uuid.uuid4().hex[:10]}",
                                artifact_id=artifact_id,
                                kind="generic_high_entropy_secret",
                                location=name,
                                redacted_value=_redact_secret(token, visible_prefix=4),
                                entropy=round(ent, 2),
                            )
                        )

    return findings
