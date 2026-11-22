"""Opaque, prefixed identifiers."""

from __future__ import annotations

import uuid


def new_id(prefix: str) -> str:
    """Return a stable-shaped identifier such as ``prj_9f2c...``."""

    return f"{prefix}_{uuid.uuid4().hex}"


def new_request_id() -> str:
    return new_id("req")


def new_project_id() -> str:
    return new_id("prj")
