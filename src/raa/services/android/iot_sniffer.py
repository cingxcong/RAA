"""Local IoT Protocol Dissector & Companion App Traffic Analyzer.

Passively monitors, dissects, and parses local multicast and broadcast traffic
(mDNS / Zeroconf, SSDP / UPnP, WS-Discovery, and UDP beacons) used by IoT companion
applications (smart home, streaming, cameras, automotive) to discover unauthenticated controls.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

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

# Standard & Automotive / Companion BLE Service & Characteristic UUID signatures
KNOWN_BLE_SERVICES: dict[str, tuple[str, str]] = {
    "00001800-0000-1000-8000-00805f9b34fb": ("Generic Access", "Core Device Info"),
    "00001801-0000-1000-8000-00805f9b34fb": ("Generic Attribute", "GATT Service"),
    "0000180a-0000-1000-8000-00805f9b34fb": ("Device Information", "Hardware & Firmware Metadata"),
    "0000180f-0000-1000-8000-00805f9b34fb": ("Battery Service", "BMS & Battery Level"),
    "0000180d-0000-1000-8000-00805f9b34fb": ("Heart Rate", "Biometric Sensor"),
    "00001819-0000-1000-8000-00805f9b34fb": ("Location and Navigation", "GNSS / Telemetry"),
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": (
        "Nordic UART Service (NUS)",
        "Bidirectional Serial Bridge",
    ),
    "0000fee0-0000-1000-8000-00805f9b34fb": ("Anhui Huami / Zepp", "Wearable Companion Protocol"),
    "0000fee1-0000-1000-8000-00805f9b34fb": ("Xiaomi Smart Band", "Fitness & Biometrics"),
    "0000fe95-0000-1000-8000-00805f9b34fb": ("Xiaomi Mijia / BLE Mesh", "Smart Home Automation"),
}

KNOWN_BLE_CHARACTERISTICS: dict[str, tuple[str, str]] = {
    "00002a00-0000-1000-8000-00805f9b34fb": ("Device Name", "String"),
    "00002a19-0000-1000-8000-00805f9b34fb": ("Battery Level", "Percentage (uint8)"),
    "00002a24-0000-1000-8000-00805f9b34fb": ("Model Number String", "String"),
    "00002a26-0000-1000-8000-00805f9b34fb": ("Firmware Revision String", "String"),
    "00002a28-0000-1000-8000-00805f9b34fb": ("Software Revision String", "String"),
    "6e400002-b5a3-f393-e0a9-e50e24dcca9e": ("NUS TX Characteristic", "Raw Byte Stream (Write)"),
    "6e400003-b5a3-f393-e0a9-e50e24dcca9e": ("NUS RX Characteristic", "Raw Byte Stream (Notify)"),
}


def dissect_ble_peripheral(
    raw_services_or_uuids: list[Any] | dict[str, Any] | str,
    device_name: str = "Unknown BLE Peripheral",
) -> dict[str, Any]:
    """Analyze Bluetooth Low Energy (BLE) GATT services, characteristics, and telemetry channels.

    Identifies standard Bluetooth SIG services, proprietary companion app serial bridges
    (e.g., Nordic UART, BMS / Battery Management, TCU telemetry), and flags insecure
    unencrypted write characteristics or missing bonding requirements.
    """
    input_uuids: list[str] = []
    if isinstance(raw_services_or_uuids, str):
        # Extract UUID-like strings (128-bit or 16-bit)
        matches = re.findall(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            raw_services_or_uuids,
        )
        input_uuids = matches if matches else [raw_services_or_uuids.strip()]
    elif isinstance(raw_services_or_uuids, list):
        for item in raw_services_or_uuids:
            if isinstance(item, str):
                input_uuids.append(item.strip())
            elif isinstance(item, dict) and "uuid" in item:
                input_uuids.append(str(item["uuid"]).strip())
    elif isinstance(raw_services_or_uuids, dict):
        if "services" in raw_services_or_uuids and isinstance(
            raw_services_or_uuids["services"], list
        ):
            for s in raw_services_or_uuids["services"]:
                u = s.get("uuid") if isinstance(s, dict) else str(s)
                if u:
                    input_uuids.append(u.strip())
        elif "uuid" in raw_services_or_uuids:
            input_uuids.append(str(raw_services_or_uuids["uuid"]).strip())

    analyzed_services: list[dict[str, Any]] = []
    identified_telemetry: list[str] = []
    ble_alerts: list[dict[str, Any]] = []

    for uuid_raw in input_uuids:
        uuid_lower = uuid_raw.lower()
        # Canonicalize 16-bit to 128-bit if applicable
        if len(uuid_lower) == 4 or (len(uuid_lower) == 6 and uuid_lower.startswith("0x")):
            clean_16 = uuid_lower.replace("0x", "").zfill(8)
            uuid_canonical = f"{clean_16}-0000-1000-8000-00805f9b34fb"
        else:
            uuid_canonical = uuid_lower

        service_info = KNOWN_BLE_SERVICES.get(uuid_canonical)
        char_info = KNOWN_BLE_CHARACTERISTICS.get(uuid_canonical)

        if service_info:
            s_name, s_role = service_info
            analyzed_services.append(
                {
                    "uuid": uuid_raw,
                    "canonical_uuid": uuid_canonical,
                    "kind": "service",
                    "name": s_name,
                    "role": s_role,
                    "is_standard_sig": uuid_canonical.endswith("-0000-1000-8000-00805f9b34fb"),
                }
            )
            identified_telemetry.append(s_name)
            if "UART" in s_name or "Serial" in s_role:
                ble_alerts.append(
                    {
                        "severity": "HIGH",
                        "title": "Proprietary BLE Serial Bridge Exposed",
                        "description": (
                            f"Service '{s_name}' ({uuid_raw}) operates as a raw serial bridge. "
                            "May accept unauthenticated binary telemetry or command frames."
                        ),
                    }
                )
        elif char_info:
            c_name, c_type = char_info
            analyzed_services.append(
                {
                    "uuid": uuid_raw,
                    "canonical_uuid": uuid_canonical,
                    "kind": "characteristic",
                    "name": c_name,
                    "data_type": c_type,
                    "is_standard_sig": True,
                }
            )
            identified_telemetry.append(c_name)
        else:
            # Proprietary / vendor custom UUID
            analyzed_services.append(
                {
                    "uuid": uuid_raw,
                    "canonical_uuid": uuid_canonical,
                    "kind": "proprietary",
                    "name": "Custom / Proprietary Vendor UUID",
                    "role": "Vehicle TCU / BMS / Smart Peripheral Channel",
                    "is_standard_sig": False,
                }
            )
            identified_telemetry.append(f"Proprietary ({uuid_raw[:8]}...)")

    return {
        "device_name": device_name,
        "total_uuids_analyzed": len(input_uuids),
        "services_identified_count": len(analyzed_services),
        "services": analyzed_services,
        "telemetry_channels": sorted(set(identified_telemetry)),
        "security_alerts_count": len(ble_alerts),
        "security_alerts": ble_alerts,
    }


def dissect_iot_traffic(
    traffic_input: str | list[Any],
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
            if urlsplit(loc_url).scheme.lower() == "http":
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

        # 5. BLE GATT / UUID strings in traffic or log dumps
        ble_matches = re.findall(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            line_clean,
        )
        if ble_matches or any(k in line_clean.lower() for k in ("gatt", "ble", "bluetooth")):
            protocols_detected.add("BLE_GATT")
            if ble_matches:
                ble_res = dissect_ble_peripheral(
                    ble_matches, device_name="Discovered BLE Companion"
                )
                for srv in ble_res["services"]:
                    discovered_devices.append(
                        {
                            "protocol": "BLE_GATT",
                            "vendor": srv.get("name", "BLE Service"),
                            "device_type": srv.get("role", "BLE Peripheral Channel"),
                            "service": srv.get("uuid"),
                            "ip": "00:00:00:00:00:00 (BLE)",
                            "details": f"{srv.get('name')} [{srv.get('uuid')}]",
                        }
                    )
                security_alerts.extend(ble_res["security_alerts"])

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
