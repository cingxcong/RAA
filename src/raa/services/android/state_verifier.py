"""Deterministic Mobile State Verification & Agent Simulation Engine.

Inspired by Purewhiter/mobilegym: validates mobile GUI agent action-state transitions
against structured, deterministic JSON application states rather than relying solely
on fuzzy visual LLM judging, providing verifiable mock simulation and assertion checks.
"""

from __future__ import annotations

import time
from typing import Any


def verify_gui_state(
    current_state: dict[str, Any] | None = None,
    expected_state: dict[str, Any] | None = None,
    transition_action: str | None = None,
    match_tolerance: float = 0.9,
) -> dict[str, Any]:
    """Verify GUI agent state transitions against deterministic state machine schemas."""
    curr = current_state or {
        "activity": "MainActivity",
        "visible_elements": ["login_button", "username_input", "password_input"],
        "screen_title": "Sign In",
    }
    exp = expected_state or {
        "activity": "MainActivity",
        "visible_elements": ["login_button", "username_input", "password_input"],
        "screen_title": "Sign In",
    }

    # Evaluate component match
    curr_elems = set(curr.get("visible_elements", []))
    exp_elems = set(exp.get("visible_elements", []))

    if exp_elems:
        elem_intersection = curr_elems.intersection(exp_elems)
        elem_similarity = len(elem_intersection) / len(exp_elems)
    else:
        elem_similarity = 1.0

    activity_matches = curr.get("activity") == exp.get("activity")
    title_matches = curr.get("screen_title") == exp.get("screen_title")

    overall_parity = (
        (0.4 if activity_matches else 0.0)
        + (0.4 * elem_similarity)
        + (0.2 if title_matches else 0.0)
    )

    passed = overall_parity >= match_tolerance
    missing_elements = list(exp_elems - curr_elems)
    unexpected_elements = list(curr_elems - exp_elems)

    return {
        "verified": passed,
        "parity_score": round(overall_parity, 3),
        "match_tolerance": match_tolerance,
        "activity_matches": activity_matches,
        "title_matches": title_matches,
        "element_similarity": round(elem_similarity, 3),
        "transition_action": transition_action or "tap_login",
        "missing_elements": missing_elements,
        "unexpected_elements": unexpected_elements,
        "current_activity": curr.get("activity"),
        "expected_activity": exp.get("activity"),
        "evaluated_at": int(time.time()),
    }
