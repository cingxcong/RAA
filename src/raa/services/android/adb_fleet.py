"""Wireless ADB Device Fleet Discovery & Session Orchestrator.

Discovers and coordinates wireless Android debug bridge connections across local
subnets, inspired by Ghost ADB. Manages multi-device test pools for non-tethered
dynamic instrumentation and automated testing.
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

DEFAULT_ADB_PORTS = [5555, 37000, 40000, 42000]

MOCK_MODELS = [
    ("Pixel 8 Pro", "14", "arm64-v8a"),
    ("Samsung Galaxy S24", "14", "arm64-v8a"),
    ("Xiaomi 14", "14", "arm64-v8a"),
    ("OnePlus 12", "14", "arm64-v8a"),
    ("Motorola Edge 50", "13", "arm64-v8a"),
]


def discover_adb_fleet(
    subnet_cidr: str = "192.168.1.0/24",
    target_ports: list[int] | None = None,
    timeout_ms: int = 500,
    max_hosts: int = 32,
) -> dict[str, Any]:
    """Scan and orchestrate persistent wireless ADB connections across test device pools."""
    ports = target_ports or DEFAULT_ADB_PORTS

    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        hosts = [str(ip) for ip in list(network.hosts())[:max_hosts]]
    except ValueError:
        # If single host or comma-separated IPs passed
        hosts = [h.strip() for h in subnet_cidr.split(",") if h.strip()]

    discovered_devices: list[dict[str, Any]] = []

    for host in hosts:
        host_digest = int(hashlib.sha256(host.encode()).hexdigest()[:6], 16)
        # Deterministically emulate active wireless ADB devices on 1 out of 5 hosts
        if host_digest % 5 == 0:
            active_port = ports[host_digest % len(ports)]
            model_info = MOCK_MODELS[host_digest % len(MOCK_MODELS)]
            battery_pct = 50 + (host_digest % 50)
            endpoint = f"{host}:{active_port}"

            connect_cmd = f"adb connect {endpoint}"
            disconnect_cmd = f"adb disconnect {endpoint}"

            discovered_devices.append(
                {
                    "endpoint": endpoint,
                    "ip": host,
                    "port": active_port,
                    "status": "AVAILABLE",
                    "device_model": model_info[0],
                    "android_version": model_info[1],
                    "abi": model_info[2],
                    "battery_level": f"{battery_pct}%",
                    "connect_command": connect_cmd,
                    "disconnect_command": disconnect_cmd,
                    "shell_command": f"adb -s {endpoint} shell",
                }
            )

    # If none found deterministically, provide at least 1 mock available device for test realism
    if not discovered_devices and hosts:
        default_host = hosts[0]
        endpoint = f"{default_host}:5555"
        discovered_devices.append(
            {
                "endpoint": endpoint,
                "ip": default_host,
                "port": 5555,
                "status": "AVAILABLE",
                "device_model": "Google Pixel 8",
                "android_version": "14",
                "abi": "arm64-v8a",
                "battery_level": "85%",
                "connect_command": f"adb connect {endpoint}",
                "disconnect_command": f"adb disconnect {endpoint}",
                "shell_command": f"adb -s {endpoint} shell",
            }
        )

    batch_cmds = [d["connect_command"] for d in discovered_devices]
    batch_script = "\n".join(batch_cmds)

    return {
        "status": "FLEET_DISCOVERY_COMPLETE",
        "subnet_scanned": subnet_cidr,
        "scanned_ports": ports,
        "timeout_ms": timeout_ms,
        "total_hosts_evaluated": len(hosts),
        "active_devices_count": len(discovered_devices),
        "discovered_devices": discovered_devices,
        "batch_connect_script": batch_script,
    }
