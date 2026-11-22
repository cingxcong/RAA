"""Programmatic device environment mutator for chaos and UI resilience testing."""

from __future__ import annotations

import logging
from typing import Any

from raa.services.android.adb import AdbService

logger = logging.getLogger(__name__)


def get_environment_status(
    adb: AdbService,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Inspect current runtime device environment settings."""
    ui_mode = adb.shell("cmd uimode night", device_id=device_id).strip()
    battery = adb.shell("dumpsys battery", device_id=device_id)
    density = adb.shell("wm density", device_id=device_id).strip()
    size = adb.shell("wm size", device_id=device_id).strip()
    font_scale = adb.shell("settings get system font_scale", device_id=device_id).strip()

    bat_level = None
    for line in battery.splitlines():
        if "level:" in line:
            bat_level = line.split(":", 1)[1].strip()
            break

    return {
        "dark_mode_status": ui_mode,
        "battery_level": bat_level,
        "display_density": density,
        "display_size": size,
        "font_scale": font_scale or "1.0",
    }


def mutate_device_environment(
    action: str = "status",
    params: dict[str, Any] | None = None,
    device_id: str | None = None,
    adb_service: AdbService | None = None,
) -> dict[str, Any]:
    """Mutate device runtime properties (dark mode, battery, network, display)."""
    adb = adb_service or AdbService()
    p = params or {}
    mutations: list[str] = []

    if action == "status":
        state = get_environment_status(adb, device_id=device_id)
        return {
            "action": "status",
            "current_state": state,
            "status": "ready",
        }

    if action == "dark_mode":
        enable = p.get("enabled", True)
        arg = "yes" if enable else "no"
        adb.shell(f"cmd uimode night {arg}", device_id=device_id)
        mutations.append(f"dark_mode -> {arg}")

    elif action == "network":
        profile = str(p.get("profile", "offline")).lower()
        if profile == "offline":
            adb.shell("svc data disable", device_id=device_id)
            adb.shell("svc wifi disable", device_id=device_id)
            mutations.append("network -> offline (data=off, wifi=off)")
        elif profile == "wifi_only":
            adb.shell("svc data disable", device_id=device_id)
            adb.shell("svc wifi enable", device_id=device_id)
            mutations.append("network -> wifi_only (data=off, wifi=on)")
        elif profile == "data_only":
            adb.shell("svc data enable", device_id=device_id)
            adb.shell("svc wifi disable", device_id=device_id)
            mutations.append("network -> data_only (data=on, wifi=off)")
        else:  # online
            adb.shell("svc data enable", device_id=device_id)
            adb.shell("svc wifi enable", device_id=device_id)
            mutations.append("network -> online (data=on, wifi=on)")

    elif action == "battery":
        level = p.get("level")
        charging = p.get("charging", True)
        reset = p.get("reset", False)
        if reset:
            adb.shell("dumpsys battery reset", device_id=device_id)
            mutations.append("battery -> reset to hardware state")
        else:
            if level is not None:
                adb.shell(f"dumpsys battery set level {level}", device_id=device_id)
                mutations.append(f"battery level -> {level}%")
            if not charging:
                adb.shell("dumpsys battery unplug", device_id=device_id)
                mutations.append("battery -> unplugged")

    elif action == "display":
        dpi = p.get("density")
        size = p.get("size")
        reset = p.get("reset", False)
        if reset:
            adb.shell("wm density reset", device_id=device_id)
            adb.shell("wm size reset", device_id=device_id)
            mutations.append("display -> reset density and size")
        else:
            if dpi:
                adb.shell(f"wm density {dpi}", device_id=device_id)
                mutations.append(f"display density -> {dpi}")
            if size:
                adb.shell(f"wm size {size}", device_id=device_id)
                mutations.append(f"display size -> {size}")

    elif action == "font_scale":
        scale = p.get("scale", 1.0)
        adb.shell(f"settings put system font_scale {scale}", device_id=device_id)
        mutations.append(f"font_scale -> {scale}")

    elif action == "reset_all":
        adb.shell("dumpsys battery reset", device_id=device_id)
        adb.shell("wm density reset", device_id=device_id)
        adb.shell("wm size reset", device_id=device_id)
        adb.shell("cmd uimode night auto", device_id=device_id)
        adb.shell("svc data enable", device_id=device_id)
        adb.shell("svc wifi enable", device_id=device_id)
        adb.shell("settings put system font_scale 1.0", device_id=device_id)
        mutations.append("reset_all -> battery, display, dark_mode, network, font_scale restored")

    else:
        raise ValueError(
            f"Unknown action '{action}'. Valid actions: status, dark_mode, "
            "network, battery, display, font_scale, reset_all."
        )

    updated_state = get_environment_status(adb, device_id=device_id)
    return {
        "action": action,
        "status": "applied",
        "mutations_applied": mutations,
        "current_state": updated_state,
    }
