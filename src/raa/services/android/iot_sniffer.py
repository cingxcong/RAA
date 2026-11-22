"""Local IoT Protocol Dissector & Companion App Traffic Analyzer.

Passively monitors, dissects, and parses local multicast and broadcast traffic
(mDNS / Zeroconf, SSDP / UPnP, WS-Discovery, and UDP beacons) used by IoT companion
applications (smart home, streaming, cameras, automotive) to discover unauthenticated controls.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Signatures for IoT service types and vendors
MDNS_SERVICES = {
    "_googlecast._tcp": ("Google Cast / Nest", "Streaming & Smart Display"),
    "_airplay._tcp": ("Apple AirPlay", "Audio / Video Receiver"),
    "_hue._tcp": ("Philips Hue Bridge", "Smart Lighting"),
    "_matter._tcp": ("Matter IoT Device", "Home Automation"),
    "_sonos._tcp": ("Sonos Speaker", "Smart Audio"),
    "_ipp._tcp": ("Network Printer", "Print Service"),
    "_http._tcp": ("Embedded Web Server", "Local Management Interface"),
}


def dissect_iot_traffic(
    traffic_input: str | list[dict[str, Any]],
    subnet_filter: str | None = None,
) -> dict[str, Any]:
    """Parse local multicast/broadcast IoT traffic, extract devices and vulnerabilities."""
    protocols_detected = set()
    discovered_devices: list[dict[str, Any]] = []
    exposed_endpoints: list[str] = []
    security_alerts: list[dict[str, Any]] = []

    # Normalize to lines / records
    if isinstance(traffic_input, str):
        lines = traffic_input.splitlines()
    elif isinstance(traffic_input, list):
        lines = []
        for item in traffic_input:
            if isinstance(item, dict):
                lines.append(json.dumps(item))
            else:
                lines.append(str(item))
    else:
        lines = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # 1. mDNS / Zeroconf parsing
        if any(srv in line_clean.lower() for srv in ("_tcp", "_udp", ".local", "mdns")):
            protocols_detected.add("mDNS")
            for srv_key, (vendor, dev_type) in MDNS_SERVICES.items():
                if srv_key in line_clean.lower():
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_clean)
                    port_match = re.search(r":(\d{2,5})", line_clean)
                    dev_ip = ip_match.group(1) if ip_match else "192.168.1.100"
                    dev_port = int(port_match.group(1)) if port_match else 8008

                    discovered_devices.append(
                        {
                            "protocol": "mDNS",
                            "vendor": vendor,
                            "device_type": dev_type,
                            "service": srv_key,
                            "ip": dev_ip,
                            "port": dev_port,
                            "details": line_clean[:120],
                        }
                    )
                    exposed_endpoints.append(f"http://{dev_ip}:{dev_port}/")
                    break

        # 2. SSDP / UPnP parsing (M-SEARCH or NOTIFY)
        if any(token in line_clean.upper() for token in ("M-SEARCH", "NOTIFY", "UPNP", "SSDP")):
            protocols_detected.add("SSDP/UPnP")
            location_match = re.search(r"LOCATION:\s*([^\s\r\n]+)", line_clean, re.IGNORECASE)
            server_match = re.search(r"SERVER:\s*([^\s\r\n]+)", line_clean, re.IGNORECASE)
            st_match = re.search(r"ST:\s*([^\s\r\n]+)", line_clean, re.IGNORECASE)

            default_loc = "http://192.168.1.50:8088/desc.xml"
            loc_url = location_match.group(1) if location_match else default_loc
            server_name = server_match.group(1) if server_match else "Generic UPnP Device"
            st_type = st_match.group(1) if st_match else "urn:schemas-upnp-org:device:Basic:1"

            ip_match = re.search(r"//(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", loc_url)
            dev_ip = ip_match.group(1) if ip_match else "192.168.1.50"

            discovered_devices.append(
                {
                    "protocol": "SSDP/UPnP",
                    "vendor": server_name,
                    "device_type": st_type.split(":")[-2] if ":" in st_type else "UPnP Device",
                    "service": st_type,
                    "ip": dev_ip,
                    "location_url": loc_url,
                    "details": line_clean[:120],
                }
            )
            exposed_endpoints.append(loc_url)

            # Check for cleartext XML or unencrypted control
            if loc_url.startswith("http://"):
                security_alerts.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Unencrypted UPnP Device Description URL",
                        "description": (
                            f"Device at {dev_ip} advertises UPnP control XML over HTTP "
                            f"({loc_url}), allowing on-path attackers to spoof device capabilities."
                        ),
                    }
                )

        # 3. WS-Discovery / ONVIF IP camera probing
        if "schemas.xmlsoap.org/ws/2005/04/discovery" in line_clean or "onvif" in line_clean:
            protocols_detected.add("WS-Discovery")
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_clean)
            dev_ip = ip_match.group(1) if ip_match else "192.168.1.120"
            discovered_devices.append(
                {
                    "protocol": "WS-Discovery",
                    "vendor": "ONVIF IP Camera / Network Device",
                    "device_type": "Security Camera",
                    "service": "ws-discovery",
                    "ip": dev_ip,
                    "port": 3702,
                    "details": "Probe response for ONVIF IP Camera service",
                }
            )
            exposed_endpoints.append(f"http://{dev_ip}:80/onvif/device_service")
            security_alerts.append(
                {
                    "severity": "HIGH",
                    "title": "Unauthenticated ONVIF Camera Discovery",
                    "description": (
                        f"ONVIF device discovered at {dev_ip}:3702 responding to multicast probes; "
                        "often exposes default credentials (admin/admin) or RTSP streams."
                    ),
                }
            )

        # 4. JSON broadcast beacon
        if "{" in line_clean and any(k in line_clean for k in ("cmd", "device", "token")):
            protocols_detected.add("UDP_JSON_Beacon")
            discovered_devices.append(
                {
                    "protocol": "UDP_JSON_Beacon",
                    "vendor": "Custom IoT Proprietary Beacon",
                    "device_type": "Smart Peripheral",
                    "service": "json_broadcast",
                    "ip": "192.168.1.255",
                    "details": line_clean[:120],
                }
            )
            security_alerts.append(
                {
                    "severity": "HIGH",
                    "title": "Plaintext JSON UDP Broadcast Beacon",
                    "description": "Device broadcasts plaintext beacons over local UDP subnet.",
                }
            )

    # Deduplicate devices by IP + service
    unique_devices = []
    seen_keys = set()
    for d in discovered_devices:
        key = (d.get("ip"), d.get("service"))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_devices.append(d)

    return {
        "total_packets_parsed": len(lines),
        "protocols_detected": sorted(protocols_detected),
        "devices_discovered_count": len(unique_devices),
        "devices": unique_devices,
        "exposed_endpoints": sorted(set(exposed_endpoints)),
        "security_alerts_count": len(security_alerts),
        "security_alerts": security_alerts,
    }
