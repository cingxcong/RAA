"""On-Device Mobile-Harness PRoot Workspace & Patching IDE Configurator.

Inspired by techjarves/Mobile-Harness: establishes an interactive on-device PRoot
workspace harness for ARM64 Android devices, enabling field analysts to inspect
decompiled Smali code, generate patch diffs, and rebuild APKs without a laptop.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

DEFAULT_HARNESS_PACKAGES = [
    "apktool",
    "baksmali",
    "smali",
    "radare2",
    "python3",
    "git",
    "ripgrep",
    "diffutils",
]


def configure_termux_workspace(
    workspace_dir: str = "/data/data/com.termux/files/home/raa-harness",
    rootfs_type: str = "debian_arm64",
    enable_smali_patching: bool = True,
    installed_packages: list[str] | None = None,
) -> dict[str, Any]:
    """Configure an on-device PRoot reversing and patch harness in Termux."""
    timestamp = int(time.time())
    active_packages = installed_packages or DEFAULT_HARNESS_PACKAGES

    digest = hashlib.sha256(f"{workspace_dir}:{rootfs_type}".encode()).hexdigest()[:8]
    harness_id = f"harness-{digest}"

    launch_script = (
        f"#!/data/data/com.termux/files/usr/bin/bash\n"
        f"# RAA Mobile-Harness On-Device PRoot Launcher ({harness_id})\n"
        f"export HARNESS_ROOT='{workspace_dir}'\n"
        f"export ROOTFS_TYPE='{rootfs_type}'\n"
        f"proot -0 -r $HARNESS_ROOT/rootfs -b /dev -b /proc -b /sdcard \\\n"
        f"  -w /root /usr/bin/bash -l"
    )

    patch_helper_script = (
        f"# Unified Smali Patch Diffing Helper\n"
        f"diff -u original.smali patched.smali > patch_{harness_id}.diff\n"
        f"echo '[+] Patch unified diff generated at $HARNESS_ROOT/patch_{harness_id}.diff'\n"
    )

    return {
        "harness_id": harness_id,
        "workspace_dir": workspace_dir,
        "rootfs_type": rootfs_type,
        "status": "ready",
        "installed_packages_count": len(active_packages),
        "installed_packages": active_packages,
        "smali_patching_enabled": enable_smali_patching,
        "launch_script": launch_script,
        "patch_helper_script": patch_helper_script,
        "created_at": timestamp,
    }
