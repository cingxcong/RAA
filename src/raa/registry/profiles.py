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
}

# Profile membership sets. Every tool appears in ``full``.
MINIMAL = frozenset({"minimal", "core", "full", "dynamic", "api", "ui"})
CORE = frozenset({"core", "full", "dynamic", "api", "ui"})
UI = frozenset({"ui", "full"})
DYNAMIC = frozenset({"dynamic", "full"})
API = frozenset({"api", "full"})
ADMIN = frozenset({"admin", "full"})
CORE_AND_ADMIN = CORE | {"admin"}


def is_profile(value: str) -> bool:
    return value in ALL_PROFILES
