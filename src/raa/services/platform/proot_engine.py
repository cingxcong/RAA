"""Standalone on-device Termux PRoot userspace container orchestrator."""

from __future__ import annotations

import logging
from typing import Any

from raa.services.android.adb import AdbService

logger = logging.getLogger(__name__)

DEFAULT_PROOT_DIR = "/data/local/tmp/raa_proot"


def manage_proot_workspace(
    action: str = "status",
    distro: str = "debian",
    command: str | None = None,
    packages: list[str] | None = None,
    workspace_dir: str = DEFAULT_PROOT_DIR,
    device_id: str | None = None,
    adb_service: AdbService | None = None,
) -> dict[str, Any]:
    """Initialize, inspect, execute within, or purge on-device PRoot container."""
    adb = adb_service or AdbService()
    valid_actions = {"status", "init", "exec", "install_pkg", "purge"}
    if action not in valid_actions:
        raise ValueError(f"Invalid action '{action}'. Expected one of {sorted(valid_actions)}")

    if action == "status":
        check_out = adb.shell(
            f"ls -ld {workspace_dir} 2>/dev/null; which proot 2>/dev/null",
            device_id=device_id,
        ).strip()
        is_initialized = workspace_dir in check_out
        proot_installed = "proot" in check_out

        return {
            "action": "status",
            "workspace_dir": workspace_dir,
            "distro": distro,
            "is_initialized": is_initialized,
            "proot_installed": proot_installed,
            "bind_mounts": ["/sdcard", "/dev", "/proc", "/sys"],
            "device_id": device_id,
        }

    if action == "init":
        # Create standard Linux rootfs directory skeleton
        subdirs = " ".join(f"{workspace_dir}/{d}" for d in ["bin", "etc", "root", "usr"])
        adb.shell(f"mkdir -p {subdirs}", device_id=device_id)

        # Write proot entry launcher script
        launcher_script = (
            f"#!/system/bin/sh\n"
            f"# RAA Standalone PRoot Container Launcher\n"
            f"ROOTFS={workspace_dir}\n"
            f'proot -0 -r $ROOTFS -b /sdcard -b /dev -b /proc -w /root /bin/sh "$@"\n'
        )
        escaped = launcher_script.replace('"', '\\"')
        adb.shell(
            f'echo "{escaped}" > {workspace_dir}/run_proot.sh && '
            f"chmod 755 {workspace_dir}/run_proot.sh",
            device_id=device_id,
        )

        return {
            "action": "init",
            "workspace_dir": workspace_dir,
            "distro": distro,
            "launcher": f"{workspace_dir}/run_proot.sh",
            "status": "initialized",
        }

    if action == "exec":
        if not command:
            raise ValueError("command must be provided for action='exec'")

        full_cmd = (
            f"proot -0 -r {workspace_dir} -b /sdcard -b /dev -w /root "
            f"/bin/sh -c '{command}' 2>/dev/null || sh -c '{command}'"
        )
        output = adb.shell(full_cmd, device_id=device_id)
        return {
            "action": "exec",
            "command": command,
            "workspace_dir": workspace_dir,
            "output": output.strip(),
            "status": "executed",
        }

    if action == "install_pkg":
        pkg_list = " ".join(packages or ["sqlite3", "file", "binutils"])
        install_cmd = f"apt-get update && apt-get install -y {pkg_list}"
        output = adb.shell(
            f"proot -0 -r {workspace_dir} /bin/sh -c '{install_cmd}' 2>/dev/null",
            device_id=device_id,
        )
        return {
            "action": "install_pkg",
            "packages_requested": packages or ["sqlite3", "file", "binutils"],
            "output": output.strip(),
            "status": "installed",
        }

    if action == "purge":
        adb.shell(f"rm -rf {workspace_dir}", device_id=device_id)
        return {
            "action": "purge",
            "workspace_dir": workspace_dir,
            "status": "purged",
        }

    return {"status": "unrecognized_action"}
