"""Android Network Security Configuration decoder.

Parses network security config files from APK/AAB packages, whether stored
as binary AXML or plain XML, and extracts domain anchors, cleartext permits,
and certificate pinning policies.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from raa.services.android.axml import XmlElement, parse_binary_xml


def decode_network_security_config(data: bytes) -> dict[str, Any]:
    if data.startswith(b"\x03\x00"):
        # Binary AXML
        try:
            doc = parse_binary_xml(data)
            return _parse_axml_tree(doc.root)
        except Exception:  # noqa: S110
            pass

    # Try plain text XML
    try:
        text = data.decode("utf-8", errors="replace")
        root = ET.fromstring(text)  # noqa: S314
        return _parse_element_tree(root)
    except Exception as exc:
        return {
            "error": f"Failed to parse network security config: {exc}",
            "raw_byte_count": len(data),
        }


def _parse_axml_tree(root: XmlElement) -> dict[str, Any]:
    base_config: dict[str, Any] = {"cleartext_traffic_permitted": None, "trust_anchors": []}
    domain_configs: list[dict[str, Any]] = []
    debug_overrides: dict[str, Any] = {"trust_anchors": []}

    for child in root.children:
        tag = child.name
        if tag == "base-config":
            cleartext = child.value("cleartextTrafficPermitted")
            if cleartext is not None:
                base_config["cleartext_traffic_permitted"] = _to_bool(cleartext)
            for sub in child.children:
                if sub.name == "trust-anchors":
                    for cert in sub.children:
                        if cert.name == "certificates":
                            src = cert.value("src")
                            if src:
                                base_config["trust_anchors"].append(str(src))
        elif tag == "domain-config":
            domain_cfg = _parse_axml_domain_config(child)
            domain_configs.append(domain_cfg)
        elif tag == "debug-overrides":
            for sub in child.children:
                if sub.name == "trust-anchors":
                    for cert in sub.children:
                        if cert.name == "certificates":
                            src = cert.value("src")
                            if src:
                                debug_overrides["trust_anchors"].append(str(src))

    has_user_certs = ("user" in base_config["trust_anchors"]) or any(
        "user" in cfg["trust_anchors"] for cfg in domain_configs
    )
    has_pinning = any(bool(cfg.get("pin_set", {}).get("pins")) for cfg in domain_configs)

    return {
        "base_config": base_config,
        "domain_configs": domain_configs,
        "debug_overrides": debug_overrides,
        "has_user_certificates": has_user_certs,
        "has_pinning": has_pinning,
        "has_cleartext_traffic_permitted": base_config["cleartext_traffic_permitted"] is True
        or any(cfg.get("cleartext_traffic_permitted") is True for cfg in domain_configs),
    }


def _parse_axml_domain_config(elem: XmlElement) -> dict[str, Any]:
    cleartext = elem.value("cleartextTrafficPermitted")
    domains: list[dict[str, Any]] = []
    trust_anchors: list[str] = []
    pin_set: dict[str, Any] = {"expiration": None, "pins": []}

    for child in elem.children:
        if child.name == "domain":
            subdomains = child.value("includeSubdomains")
            domain_name = child.value("name") or getattr(child, "text", None)
            if domain_name:
                domains.append(
                    {
                        "domain": str(domain_name).strip(),
                        "include_subdomains": _to_bool(subdomains)
                        if subdomains is not None
                        else False,
                    }
                )
        elif child.name == "trust-anchors":
            for cert in child.children:
                if cert.name == "certificates":
                    src = cert.value("src")
                    if src:
                        trust_anchors.append(str(src))
        elif child.name == "pin-set":
            exp = child.value("expiration")
            if exp:
                pin_set["expiration"] = str(exp)
            for pin in child.children:
                if pin.name == "pin":
                    digest = pin.value("digest") or "SHA-256"
                    val = pin.value("value") or getattr(pin, "text", None)
                    if val:
                        pin_set["pins"].append({"digest": str(digest), "value": str(val).strip()})

    return {
        "domains": domains,
        "cleartext_traffic_permitted": _to_bool(cleartext) if cleartext is not None else None,
        "trust_anchors": trust_anchors,
        "pin_set": pin_set,
    }


def _parse_element_tree(root: ET.Element) -> dict[str, Any]:
    base_config: dict[str, Any] = {"cleartext_traffic_permitted": None, "trust_anchors": []}
    domain_configs: list[dict[str, Any]] = []
    debug_overrides: dict[str, Any] = {"trust_anchors": []}

    for child in root:
        tag = child.tag.split("}")[-1]
        if tag == "base-config":
            cleartext = child.attrib.get("cleartextTrafficPermitted")
            if cleartext is not None:
                base_config["cleartext_traffic_permitted"] = _to_bool(cleartext)
            for sub in child:
                if sub.tag.split("}")[-1] == "trust-anchors":
                    for cert in sub:
                        if cert.tag.split("}")[-1] == "certificates":
                            src = cert.attrib.get("src")
                            if src:
                                base_config["trust_anchors"].append(src)
        elif tag == "domain-config":
            domain_cfg = _parse_et_domain_config(child)
            domain_configs.append(domain_cfg)
        elif tag == "debug-overrides":
            for sub in child:
                if sub.tag.split("}")[-1] == "trust-anchors":
                    for cert in sub:
                        if cert.tag.split("}")[-1] == "certificates":
                            src = cert.attrib.get("src")
                            if src:
                                debug_overrides["trust_anchors"].append(src)

    has_user_certs = ("user" in base_config["trust_anchors"]) or any(
        "user" in cfg["trust_anchors"] for cfg in domain_configs
    )
    has_pinning = any(bool(cfg.get("pin_set", {}).get("pins")) for cfg in domain_configs)

    return {
        "base_config": base_config,
        "domain_configs": domain_configs,
        "debug_overrides": debug_overrides,
        "has_user_certificates": has_user_certs,
        "has_pinning": has_pinning,
        "has_cleartext_traffic_permitted": base_config["cleartext_traffic_permitted"] is True
        or any(cfg.get("cleartext_traffic_permitted") is True for cfg in domain_configs),
    }


def _parse_et_domain_config(elem: ET.Element) -> dict[str, Any]:
    cleartext = elem.attrib.get("cleartextTrafficPermitted")
    domains: list[dict[str, Any]] = []
    trust_anchors: list[str] = []
    pin_set: dict[str, Any] = {"expiration": None, "pins": []}

    for child in elem:
        tag = child.tag.split("}")[-1]
        if tag == "domain":
            subdomains = child.attrib.get("includeSubdomains")
            domain_name = child.text
            if domain_name:
                domains.append(
                    {
                        "domain": domain_name.strip(),
                        "include_subdomains": _to_bool(subdomains)
                        if subdomains is not None
                        else False,
                    }
                )
        elif tag == "trust-anchors":
            for cert in child:
                if cert.tag.split("}")[-1] == "certificates":
                    src = cert.attrib.get("src")
                    if src:
                        trust_anchors.append(src)
        elif tag == "pin-set":
            exp = child.attrib.get("expiration")
            if exp:
                pin_set["expiration"] = exp
            for pin in child:
                if pin.tag.split("}")[-1] == "pin":
                    digest = pin.attrib.get("digest", "SHA-256")
                    val = pin.text
                    if val:
                        pin_set["pins"].append({"digest": digest, "value": val.strip()})

    return {
        "domains": domains,
        "cleartext_traffic_permitted": _to_bool(cleartext) if cleartext is not None else None,
        "trust_anchors": trust_anchors,
        "pin_set": pin_set,
    }


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.lower() in {"true", "1", "yes"}
    return False
