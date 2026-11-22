"""Interactive Warp-style terminal block session manager and audit runbook engine."""

from __future__ import annotations

import hashlib
import time
from typing import Any

# In-memory session store (keyed by session_id)
_WARP_SESSIONS: dict[str, list[dict[str, Any]]] = {}


def manage_warp_block_session(
    action: str = "record_block",
    session_id: str | None = None,
    command: str | None = None,
    output: str | None = None,
    exit_code: int = 0,
    duration_ms: int = 150,
    tags: list[str] | None = None,
    block_id: str | None = None,
    bookmarked: bool = False,
) -> dict[str, Any]:
    """Record, filter, bookmark, or export interactive Warp terminal command blocks."""
    sess_id = session_id or "default_session"
    if sess_id not in _WARP_SESSIONS:
        _WARP_SESSIONS[sess_id] = []

    blocks = _WARP_SESSIONS[sess_id]
    valid_actions = {"record_block", "get_session", "bookmark_block", "export_runbook", "clear"}
    if action not in valid_actions:
        raise ValueError(f"Invalid action '{action}'. Expected one of {sorted(valid_actions)}")

    if action == "record_block":
        if not command:
            raise ValueError("command is required for action='record_block'")

        ts = int(time.time() * 1000)
        h = hashlib.sha256(f"{sess_id}:{command}:{ts}".encode()).hexdigest()[:8]
        new_block = {
            "block_id": f"block_{h}",
            "command": command,
            "output": (output or "").strip(),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "timestamp_ms": ts,
            "tags": tags or ["reversing"],
            "bookmarked": bookmarked,
        }
        blocks.append(new_block)
        return {
            "action": "record_block",
            "session_id": sess_id,
            "block": new_block,
            "total_blocks": len(blocks),
        }

    if action == "get_session":
        return {
            "action": "get_session",
            "session_id": sess_id,
            "total_blocks": len(blocks),
            "blocks": blocks,
            "bookmarked_count": sum(1 for b in blocks if b.get("bookmarked")),
        }

    if action == "bookmark_block":
        if not block_id:
            raise ValueError("block_id is required for action='bookmark_block'")
        found = False
        for b in blocks:
            if b["block_id"] == block_id:
                b["bookmarked"] = True
                found = True
                break
        return {
            "action": "bookmark_block",
            "session_id": sess_id,
            "block_id": block_id,
            "bookmarked": found,
        }

    if action == "export_runbook":
        lines = [
            f"# RAA Terminal Audit Runbook: Session `{sess_id}`",
            f"*Generated blocks count: {len(blocks)}*\n",
        ]
        for idx, b in enumerate(blocks, start=1):
            mark = " ⭐ [BOOKMARKED]" if b.get("bookmarked") else ""
            lines.append(f"### Block {idx}: `{b['command']}`{mark}")
            lines.append(
                f"- **Exit Code:** `{b['exit_code']}` | **Duration:** `{b['duration_ms']}ms`"
            )
            lines.append(f"- **Tags:** {', '.join(b.get('tags', []))}")
            lines.append("```bash")
            lines.append(b["output"] or "# (no output)")
            lines.append("```\n")

        runbook_md = "\n".join(lines)
        return {
            "action": "export_runbook",
            "session_id": sess_id,
            "total_blocks": len(blocks),
            "runbook_markdown": runbook_md,
        }

    if action == "clear":
        _WARP_SESSIONS[sess_id] = []
        return {
            "action": "clear",
            "session_id": sess_id,
            "status": "cleared",
        }

    return {"status": "unrecognized_action"}
