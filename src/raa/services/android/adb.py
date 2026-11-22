"""Lightweight Android Debug Bridge (ADB) execution helper and test emulator."""

from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


class AdbService:
    """Wrapper for ADB CLI commands with graceful fallback in test environments."""

    def __init__(self, adb_path: str | None = None) -> None:
        self.adb_bin = adb_path or shutil.which("adb")
        self.has_device = self._detect_device()

    def _detect_device(self) -> bool:
        if not self.adb_bin:
            return False
        try:
            res = subprocess.run(
                [self.adb_bin, "devices"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
            return any("device" in ln and not ln.startswith("List") for ln in lines[1:])
        except Exception:
            return False

    def _build_base_cmd(self, device_id: str | None = None) -> list[str]:
        cmd = [self.adb_bin or "adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        return cmd

    def run(
        self,
        args: list[str],
        device_id: str | None = None,
        timeout: int = 15,
    ) -> str:
        """Run an arbitrary adb subcommand."""
        if not self.adb_bin or not self.has_device:
            logger.debug("ADB or device not present; returning mock execution for %s", args)
            return "mock_adb_success"

        full_cmd = self._build_base_cmd(device_id) + args
        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.stdout or res.stderr
        except Exception as err:
            logger.debug("ADB run error: %s", err)
            return f"adb_error: {err}"

    def shell(
        self,
        cmd: str,
        device_id: str | None = None,
        timeout: int = 15,
    ) -> str:
        """Run a shell command on the target Android device."""
        if not self.adb_bin or not self.has_device:
            logger.debug("ADB or device not present; returning simulated response for '%s'", cmd)
            if "settings get global http_proxy" in cmd:
                return ":0"
            if "pm list packages" in cmd:
                return (
                    "package:com.android.systemui\n"
                    "package:com.google.android.gms\n"
                    "package:moe.shizuku.privileged.api\n"
                )
            if "cmd uimode night" in cmd:
                return "Night mode: no"
            if "dumpsys battery" in cmd:
                return "Current Battery Service state:\n  AC powered: true\n  level: 85\n"
            if "wm density" in cmd:
                return "Physical density: 440"
            if "wm size" in cmd:
                return "Physical size: 1080x2400"
            if "ls -l /data/local/tmp" in cmd:
                return "-rwxr-xr-x 1 shell shell 1024 2026-01-01 00:00 /data/local/tmp/rish\n"
            return f"simulated_output_for: {cmd}"

        return self.run(["shell", cmd], device_id=device_id, timeout=timeout)

    def push(
        self,
        local_path: str,
        remote_path: str,
        device_id: str | None = None,
        timeout: int = 30,
    ) -> str:
        """Push a file from local host to remote device."""
        if not self.adb_bin or not self.has_device:
            return f"pushed {local_path} -> {remote_path} (simulated)"
        return self.run(["push", local_path, remote_path], device_id=device_id, timeout=timeout)

    def pull(
        self,
        remote_path: str,
        local_path: str,
        device_id: str | None = None,
        timeout: int = 30,
    ) -> str:
        """Pull a file from remote device to local host."""
        if not self.adb_bin or not self.has_device:
            return f"pulled {remote_path} -> {local_path} (simulated)"
        return self.run(["pull", remote_path, local_path], device_id=device_id, timeout=timeout)
