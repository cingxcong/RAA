"""Named tool profiles used by every surface."""

from __future__ import annotations

from raa.config import ProfileName

ALL_PROFILES: tuple[ProfileName, ...] = (
    "minimal",
    "core",
    "full",
    "dynamic",
    "api",
    "ui",
    "admin",
    "swarm",
)

DEFAULT_PROFILE: ProfileName = "core"

PROFILE_DESCRIPTIONS: dict[ProfileName, str] = {
    "minimal": "Small local models and single-question triage.",
    "core": "Default agent profile for static triage and reporting.",
    "full": "Every implemented tool; frontier agents and analysts.",
    "dynamic": "Core plus device and runtime work as it is implemented.",
    "api": "Core plus API reverse-engineering tools as they are implemented.",
    "ui": "Core plus UI capture and reconstruction tools as they are implemented.",
    "admin": "Toolchain, policy, licence and diagnostics.",
    "swarm": "Multi-agent swarm governance, memory federation, SOP and long-horizon reversing mesh.",
}

# Profile membership sets. Every tool appears in ``full``.
MINIMAL = frozenset({"minimal", "core", "full", "dynamic", "api", "ui"})
CORE = frozenset({"core", "full", "dynamic", "api", "ui", "swarm"})
UI = frozenset({"ui", "full"})
DYNAMIC = frozenset({"dynamic", "full"})
API = frozenset({"api", "full"})
ADMIN = frozenset({"admin", "full"})
SWARM = frozenset({"swarm", "full"})
ADMIN_AND_SWARM = frozenset({"admin", "swarm", "full"})
CORE_AND_ADMIN = CORE | {"admin"}
CORE_AND_SWARM = frozenset({"core", "swarm", "full"})


def is_profile(value: str) -> bool:
    return value in ALL_PROFILES
