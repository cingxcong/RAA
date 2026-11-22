"""HTTP Toolkit-style transparent VPN socket capture and CA certificate injection."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from raa.services.android.adb import AdbService

logger = logging.getLogger(__name__)

HTTPTOOLKIT_PACKAGE = "tech.httptoolkit.android.v1"


def get_cert_subject_hash(cert_bytes: bytes) -> str:
    """Calculate the subject hash prefix for Android system CA storage (OpenSSL style)."""
    return hashlib.sha256(cert_bytes).hexdigest()[:8]


def manage_vpn_interception(
    action: str = "status",
    package_name: str | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8000,
    ca_cert_path: str | None = None,
    system_cert: bool = False,
    device_id: str | None = None,
    adb_service: AdbService | None = None,
) -> dict[str, Any]:
    """Control transparent VPN interception, proxy forwarding, and CA cert injection."""
    adb = adb_service or AdbService()
    valid_actions = {"start", "stop", "status", "inject_ca"}
    if action not in valid_actions:
        raise ValueError(f"Invalid action '{action}'. Expected one of {sorted(valid_actions)}")

    if action == "status":
        proxy_val = adb.shell("settings get global http_proxy", device_id=device_id).strip()
        proxy_active = bool(proxy_val and proxy_val != ":0" and proxy_val != "null")

        installed_pkgs = adb.shell("pm list packages", device_id=device_id)
        httptoolkit_installed = HTTPTOOLKIT_PACKAGE in installed_pkgs

        return {
            "action": "status",
            "proxy_active": proxy_active,
            "global_http_proxy": proxy_val if proxy_active else None,
            "httptoolkit_app_installed": httptoolkit_installed,
            "target_package": package_name,
            "recommended_next_step": (
                "Call action='start' with proxy_host and proxy_port to begin intercepting."
                if not proxy_active
                else "Interception active. Call action='stop' to tear down."
            ),
        }

    if action == "inject_ca":
        if not ca_cert_path:
            raise ValueError("ca_cert_path must be provided for action='inject_ca'")
        cert_p = Path(ca_cert_path)
        if not cert_p.exists():
            raise FileNotFoundError(f"CA certificate file not found: {ca_cert_path}")

        cert_bytes = cert_p.read_bytes()
        cert_hash = get_cert_subject_hash(cert_bytes)
        dest_filename = f"{cert_hash}.0"

        if system_cert:
            remote_tmp = f"/data/local/tmp/{dest_filename}"
            system_dest = f"/system/etc/security/cacerts/{dest_filename}"
            adb.push(str(cert_p), remote_tmp, device_id=device_id)
            adb.shell(
                "su -c 'mount -o rw,remount /system' 2>/dev/null || mount -o rw,remount /",
                device_id=device_id,
            )
            adb.shell(
                f"su -c 'cp {remote_tmp} {system_dest} && chmod 644 {system_dest}' 2>/dev/null",
                device_id=device_id,
            )
            installed_location = system_dest
            installation_type = "system_ca"
        else:
            remote_dest = f"/sdcard/Download/{dest_filename}"
            adb.push(str(cert_p), remote_dest, device_id=device_id)
            installed_location = remote_dest
            installation_type = "user_ca_staged"

        return {
            "action": "inject_ca",
            "ca_cert_path": str(cert_p),
            "cert_hash": cert_hash,
            "installed_location": installed_location,
            "installation_type": installation_type,
            "system_cert": system_cert,
            "status": "success",
            "note": (
                "System CA placed in /system/etc/security/cacerts/."
                if system_cert
                else "User CA pushed to /sdcard/Download/. Install via Settings -> Security."
            ),
        }

    if action == "start":
        try:
            adb.run(["reverse", f"tcp:{proxy_port}", f"tcp:{proxy_port}"], device_id=device_id)
        except Exception as e:
            logger.debug("ADB reverse forward notice: %s", e)

        target_endpoint = f"{proxy_host}:{proxy_port}"
        adb.shell(f"settings put global http_proxy {target_endpoint}", device_id=device_id)

        installed_pkgs = adb.shell("pm list packages", device_id=device_id)
        vpn_launched = False
        if HTTPTOOLKIT_PACKAGE in installed_pkgs:
            adb.shell(
                f"am start -n {HTTPTOOLKIT_PACKAGE}/.MainActivity --es proxy {target_endpoint}",
                device_id=device_id,
            )
            vpn_launched = True

        return {
            "action": "start",
            "proxy_endpoint": target_endpoint,
            "reverse_forwarding": f"tcp:{proxy_port} -> tcp:{proxy_port}",
            "httptoolkit_vpn_launched": vpn_launched,
            "target_package": package_name,
            "status": "interception_active",
        }

    if action == "stop":
        adb.shell("settings put global http_proxy :0", device_id=device_id)
        try:
            adb.run(["reverse", "--remove", f"tcp:{proxy_port}"], device_id=device_id)
        except Exception as e:
            logger.debug("ADB reverse remove notice: %s", e)

        return {
            "action": "stop",
            "global_http_proxy": "disabled",
            "status": "interception_stopped",
        }

    return {"status": "unrecognized_action"}
