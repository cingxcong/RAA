"""Screen graph and UI coverage analysis service.

Assembles static and runtime screens into a unified navigation graph,
links transitions, and computes exploration coverage.
"""

from __future__ import annotations

from raa.domain.ui import (
    ScreenCoverageItem,
    ScreenGraph,
    ScreenModel,
    ScreenTransition,
    UICoverageReport,
)


def build_screen_graph(
    static_screens: list[ScreenModel],
    runtime_screens: list[ScreenModel] | None = None,
    transitions: list[ScreenTransition] | None = None,
) -> ScreenGraph:
    """Build a unified ScreenGraph combining static candidate and runtime screens."""
    all_screens: list[ScreenModel] = list(static_screens)
    if runtime_screens:
        all_screens.extend(runtime_screens)

    all_transitions: list[ScreenTransition] = list(transitions or [])

    # Identify start screen
    start_screen_id: str | None = None
    for sc in all_screens:
        if sc.state.parameters.get("launcher"):
            start_screen_id = sc.screen_id
            break
    if not start_screen_id and all_screens:
        start_screen_id = all_screens[0].screen_id

    # Populate transition references
    for trans in all_transitions:
        for sc in all_screens:
            if (
                sc.screen_id == trans.source_screen_id
                and trans.target_screen_id not in sc.transitions
            ):
                sc.transitions.append(trans.target_screen_id)

    return ScreenGraph(
        screens=all_screens,
        transitions=all_transitions,
        start_screen_id=start_screen_id,
        total_screens=len(all_screens),
        total_transitions=len(all_transitions),
    )


def compute_ui_coverage(graph: ScreenGraph) -> UICoverageReport:
    """Compute exploration and discovery coverage over the screen graph."""
    if not graph.screens:
        return UICoverageReport(
            discovered_screens=0,
            visited_screens=0,
            unvisited_screens=0,
            unreachable_screens=0,
            coverage_percentage=0.0,
            screens=[],
        )

    targets_with_incoming: set[str] = {t.target_screen_id for t in graph.transitions}
    coverage_items: list[ScreenCoverageItem] = []

    visited_count = 0
    unvisited_count = 0
    unreachable_count = 0

    for sc in graph.screens:
        has_runtime = sc.is_runtime or len(sc.capture_ids) > 0
        is_start = sc.screen_id == graph.start_screen_id
        is_exported = bool(sc.state.parameters.get("exported", False))
        has_incoming = sc.screen_id in targets_with_incoming

        if has_runtime:
            status = "visited"
            visited_count += 1
        elif not has_incoming and not is_start and not is_exported:
            status = "unreachable"
            unreachable_count += 1
        else:
            status = "unvisited"
            unvisited_count += 1

        coverage_items.append(
            ScreenCoverageItem(
                screen_id=sc.screen_id,
                title=sc.title or sc.screen_id,
                status=status,
                has_runtime_capture=has_runtime,
                capture_count=len(sc.capture_ids),
            )
        )

    discovered = len(graph.screens)
    pct = round((visited_count / discovered) * 100.0, 1) if discovered > 0 else 0.0

    return UICoverageReport(
        discovered_screens=discovered,
        visited_screens=visited_count,
        unvisited_screens=unvisited_count,
        unreachable_screens=unreachable_count,
        coverage_percentage=pct,
        screens=coverage_items,
    )
