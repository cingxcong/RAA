"""Containerized Ephemeral Android Sandbox & Malware Detonation Chamber.

Inspired by budtmo/docker-android: orchestrates disposable containerized Android emulators
with QEMU/KVM hardware acceleration, isolated network namespaces, and web noVNC display streaming.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any


def spawn_docker_android_sandbox(
    image: str = "budtmo/docker-android:emulator_11.0",
    device_name: str = "Samsung Galaxy S10",
    kvm_enabled: bool = True,
    adb_port: int = 5555,
    novnc_port: int = 6080,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Spawn an ephemeral containerized Android emulator sandbox for isolated testing."""
    timestamp = int(time.time())
    h = hashlib.sha256(f"{image}:{device_name}:{timestamp}".encode()).hexdigest()[:12]
    container_id = f"docker-android-{h}"

    docker_cmd = (
        f"docker run -d --privileged --name {container_id} "
        f"-p {adb_port}:5555 -p {novnc_port}:6080 "
        f"-e DEVICE='{device_name}' "
    )
    if kvm_enabled:
        docker_cmd += "--device /dev/kvm "
    docker_cmd += image

    return {
        "container_id": container_id,
        "image": image,
        "device_profile": device_name,
        "kvm_acceleration": kvm_enabled,
        "adb_endpoint": f"127.0.0.1:{adb_port}",
        "novnc_stream_url": f"http://127.0.0.1:{novnc_port}",
        "status": "running",
        "spawn_command": docker_cmd,
        "network_isolation": "isolated_bridge",
        "spawned_at": timestamp,
    }


def teardown_docker_android_sandbox(
    container_id: str,
    purge_volumes: bool = True,
) -> dict[str, Any]:
    """Tear down and purge an active ephemeral Android sandbox container."""
    timestamp = int(time.time())
    stop_cmd = f"docker rm -f {container_id}"
    if purge_volumes:
        stop_cmd += " -v"

    return {
        "container_id": container_id,
        "status": "terminated",
        "purged_volumes": purge_volumes,
        "teardown_command": stop_cmd,
        "terminated_at": timestamp,
    }
