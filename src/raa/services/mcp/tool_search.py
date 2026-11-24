"""Search-First MCP Tool Dynamic Index Service.

Allows AI agents to discover tools in the capability registry by semantic keywords,
operational goals, and category filters, avoiding context window bloat across 190+ tools.
Inspired by jshookmcp.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from raa.registry.models import CapabilityRegistry


def search_tools(
    registry: CapabilityRegistry,
    query: str,
    profile: str | None = None,
    family: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Search registered capabilities by query string, profile, and family."""
    all_tools = registry.for_profile(cast(Any, profile)) if profile else registry.all()

    tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) >= 2]
    if not tokens:
        tokens = [query.strip().lower()] if query.strip() else []

    matches: list[dict[str, Any]] = []

    for spec in all_tools:
        if family and spec.family.lower() != family.lower():
            continue

        score = 0
        name_lower = spec.name.lower()
        title_lower = spec.title.lower()
        desc_lower = spec.description.lower()
        family_lower = spec.family.lower()

        # Collect parameter names from input model
        param_names: list[str] = []
        if hasattr(spec.input_model, "model_fields"):
            param_names = [f.lower() for f in spec.input_model.model_fields]

        for token in tokens:
            if token == name_lower:
                score += 100
            elif token in name_lower:
                score += 45
            if token in title_lower:
                score += 35
            if token in desc_lower:
                score += 25
            if token in family_lower:
                score += 20
            if any(token in p for p in param_names):
                score += 15

        if score > 0 or not tokens:
            # Build parameter summary
            params_summary = []
            if hasattr(spec.input_model, "model_fields"):
                for p_name, field in spec.input_model.model_fields.items():
                    req = field.is_required()
                    desc = field.description or ""
                    params_summary.append(
                        {
                            "name": p_name,
                            "required": req,
                            "description": desc,
                        }
                    )

            matches.append(
                {
                    "name": spec.name,
                    "title": spec.title,
                    "description": spec.description,
                    "family": spec.family,
                    "profiles": sorted(spec.profiles),
                    "scopes": sorted(spec.scopes),
                    "read_only": spec.annotations.read_only,
                    "cost": spec.cost,
                    "relevance_score": score,
                    "parameters": params_summary,
                }
            )

    matches.sort(key=lambda m: m["relevance_score"], reverse=True)
    selected = matches[:limit]

    return {
        "status": "SEARCH_COMPLETE",
        "query": query,
        "profile_filter": profile or "all",
        "family_filter": family or "all",
        "total_matched": len(matches),
        "returned_count": len(selected),
        "tools": selected,
    }
