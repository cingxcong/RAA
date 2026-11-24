"""Built-in tool registration.

Modules are imported inside ``build_registry`` so the registry has no import
cycle with the runtime or surface packages.
"""

from __future__ import annotations

from raa.registry.models import CapabilityRegistry


def build_registry() -> CapabilityRegistry:
    from raa.tools import (
        admin,
        advanced_binary,
        analysis,
        api,
        artifacts,
        cognitive,
        diff,
        dynamic,
        enterprise,
        evidence,
        frameworks,
        graph,
        native,
        offensive,
        platform,
        rebuild,
        recipes,
        security,
        swarm,
        ui,
        ui_reconstruction,
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
        swarm,
        cognitive,
        advanced_binary,
        ui_reconstruction,
        enterprise,
        offensive,
    ):
        module.register(registry)
    return registry


__all__ = ["build_registry"]
