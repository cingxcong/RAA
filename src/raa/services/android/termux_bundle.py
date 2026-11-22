"""Termux and standalone on-device ARM64/x86_64 AOSP analysis binary bundle manager."""

from __future__ import annotations

import logging
from typing import Any

from raa.services.android.adb import AdbService

logger = logging.getLogger(__name__)

SUPPORTED_BINARIES: dict[str, str] = {
    "sqlite3": "Standalone SQLite3 database client for direct /data/data SQLite querying",
    "dexdump": "AOSP DEX file disassembler and class inspector",
    "busybox": "Multi-call POSIX toolkit (grep, find, awk, md5sum, nc, sed, tar)",
    "strace": "Native syscall tracer for analyzing JNI and native library activity",
    "tcpdump": "Network packet sniffer for raw socket analysis",
    "socat": "Multipurpose bidirectional relay and port forwarder",
}

DEFAULT_TARGET_DIR = "/data/local/tmp/raa_bin"


def manage_termux_bundle(
    action: str = "list",
    binaries: list[str] | None = None,
    target_dir: str = DEFAULT_TARGET_DIR,
    command: str | None = None,
    device_id: str | None = None,
    adb_service: AdbService | None = None,
) -> dict[str, Any]:
    """Deploy, list, execute, or clean standalone on-device analysis binaries."""
    adb = adb_service or AdbService()
    valid_actions = {"list", "deploy", "exec", "clean"}
    if action not in valid_actions:
        raise ValueError(f"Invalid action '{action}'. Expected one of {sorted(valid_actions)}")

    if action == "list":
        ls_out = adb.shell(f"ls -l {target_dir} 2>/dev/null", device_id=device_id).strip()
        deployed: list[str] = []
        if ls_out and "No such file" not in ls_out:
            for line in ls_out.splitlines():
                parts = line.split()
                if len(parts) >= 9:
                    fname = parts[-1]
                    if fname in SUPPORTED_BINARIES:
                        deployed.append(fname)

        return {
            "action": "list",
            "target_dir": target_dir,
            "deployed_binaries": deployed,
            "available_catalog": SUPPORTED_BINARIES,
            "raw_ls": ls_out,
        }

    if action == "clean":
        adb.shell(f"rm -rf {target_dir}", device_id=device_id)
        return {
            "action": "clean",
            "target_dir": target_dir,
            "status": "cleaned",
        }

    if action == "deploy":
        target_list = binaries or ["busybox", "sqlite3", "dexdump"]
        adb.shell(f"mkdir -p {target_dir}", device_id=device_id)

        deployed_now: list[str] = []
        for b in target_list:
            if b in SUPPORTED_BINARIES:
                wrapper_script = (
                    f'#!/system/bin/sh\n# RAA standalone wrapper for {b}\nexec {b} "$@"\n'
                )
                escaped = wrapper_script.replace('"', '\\"')
                adb.shell(
                    f'echo "{escaped}" > {target_dir}/{b} && chmod 755 {target_dir}/{b}',
                    device_id=device_id,
                )
                deployed_now.append(b)

        return {
            "action": "deploy",
            "target_dir": target_dir,
            "binaries_deployed": deployed_now,
            "status": "deployed",
        }

    if action == "exec":
        if not command:
            raise ValueError("command is required for action='exec'")

        full_cmd = f"export PATH={target_dir}:$PATH && {command}"
        output = adb.shell(full_cmd, device_id=device_id)
        return {
            "action": "exec",
            "target_dir": target_dir,
            "command": command,
            "output": output.strip(),
            "status": "executed",
        }

    return {"status": "unrecognized_action"}
