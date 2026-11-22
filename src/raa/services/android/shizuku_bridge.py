"""Shizuku Binder IPC and rish privileged command execution service."""

from __future__ import annotations

import logging
from typing import Any

from raa.services.android.adb import AdbService

logger = logging.getLogger(__name__)

SHIZUKU_PACKAGES = [
    "moe.shizuku.privileged.api",
    "rikka.shizuku",
]


def check_shizuku_status(
    adb: AdbService,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Check if Shizuku server or manager is present on the target device."""
    installed_pkgs = adb.shell("pm list packages", device_id=device_id)
    shizuku_pkg = None
    for pkg in SHIZUKU_PACKAGES:
        if pkg in installed_pkgs:
            shizuku_pkg = pkg
            break

    # Check for rish binary in /data/local/tmp
    rish_check = adb.shell(
        "ls -l /data/local/tmp/rish /system/bin/rish 2>/dev/null",
        device_id=device_id,
    ).strip()
    has_rish = "rish" in rish_check

    # Check if Shizuku binder service is active
    shizuku_running = False
    if shizuku_pkg:
        ps_out = adb.shell("ps -ef | grep shizuku", device_id=device_id)
        shizuku_running = "shizuku_server" in ps_out or "shizuku" in ps_out

    return {
        "shizuku_installed": bool(shizuku_pkg),
        "shizuku_package": shizuku_pkg,
        "shizuku_server_running": shizuku_running,
        "has_rish_binary": has_rish,
    }


def execute_shizuku_command(
    command: str,
    action: str = "exec",
    package_name: str | None = None,
    permission: str | None = None,
    appop: str | None = None,
    mode: str = "allow",
    use_rish: bool = True,
    device_id: str | None = None,
    timeout_seconds: int = 15,
    adb_service: AdbService | None = None,
) -> dict[str, Any]:
    """Execute privileged operations using Shizuku rish or ADB bridge."""
    adb = adb_service or AdbService()
    status_info = check_shizuku_status(adb, device_id=device_id)

    if action == "status":
        return {
            "action": "status",
            "status_info": status_info,
            "device_id": device_id,
        }

    # Format actual command based on action
    actual_cmd = command
    if action == "grant_permission":
        if not package_name or not permission:
            raise ValueError("package_name and permission are required for grant_permission")
        actual_cmd = f"pm grant {package_name} {permission}"
    elif action == "set_appop":
        if not package_name or not appop:
            raise ValueError("package_name and appop are required for set_appop")
        actual_cmd = f"appops set {package_name} {appop} {mode}"

    # Execution backend selection
    backend = "adb_shell"
    final_shell_cmd = actual_cmd

    if use_rish and status_info["has_rish_binary"] and status_info["shizuku_server_running"]:
        backend = "rish"
        final_shell_cmd = f"/data/local/tmp/rish -c '{actual_cmd}'"

    exit_code = 0
    try:
        output = adb.shell(final_shell_cmd, device_id=device_id)
        if "Error:" in output or "SecurityException" in output:
            exit_code = 1
    except Exception as err:
        output = str(err)
        exit_code = 1

    return {
        "action": action,
        "privileged_backend": backend,
        "command_executed": final_shell_cmd,
        "exit_code": exit_code,
        "output": output.strip(),
        "package_name": package_name,
        "shizuku_status": status_info,
    }
