"""Built-in tool registration.

Modules are imported inside ``build_registry`` so the registry has no import
cycle with the runtime or surface packages.
"""

from __future__ import annotations

from raa.registry.models import CapabilityRegistry


def build_registry() -> CapabilityRegistry:
    from raa.tools import (
        admin,
        analysis,
        api,
        artifacts,
        diff,
        dynamic,
        evidence,
        frameworks,
        graph,
        native,
        platform,
        rebuild,
        recipes,
        security,
        ui,
        unpacking,
    )

    registry = CapabilityRegistry()
    for module in (
        platform,
        artifacts,
        analysis,
        frameworks,
        native,
        graph,
        ui,
        dynamic,
        evidence,
        admin,
        recipes,
        api,
        unpacking,
        diff,
        security,
        rebuild,
    ):
        module.register(registry)
    return registry


__all__ = ["build_registry"]
