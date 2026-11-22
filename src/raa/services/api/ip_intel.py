"""Backend IP Intelligence Engine.

Enriches extracted APK endpoints and server IP addresses with Autonomous System (ASN) data,
cloud / datacenter infrastructure attribution, bogon validation, and threat risk scoring.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# Known Autonomous System Number (ASN) and Cloud Infrastructure blocks
KNOWN_CLOUD_NETWORKS = [
    ("104.16.0.0/12", 13335, "Cloudflare", "CDN_EDGE", "US", "San Francisco"),
    ("172.64.0.0/13", 13335, "Cloudflare", "CDN_EDGE", "US", "San Francisco"),
    ("1.1.1.0/24", 13335, "Cloudflare DNS", "CDN_EDGE", "AU", "Sydney"),
    ("3.0.0.0/8", 16509, "Amazon AWS", "CLOUD_INFRASTRUCTURE", "US", "Ashburn"),
    ("52.0.0.0/8", 16509, "Amazon AWS", "CLOUD_INFRASTRUCTURE", "US", "Seattle"),
    ("54.0.0.0/8", 16509, "Amazon AWS", "CLOUD_INFRASTRUCTURE", "US", "Seattle"),
    ("18.0.0.0/8", 16509, "Amazon AWS", "CLOUD_INFRASTRUCTURE", "US", "Columbus"),
    ("34.0.0.0/8", 15169, "Google Cloud", "CLOUD_INFRASTRUCTURE", "US", "Mountain View"),
    ("35.0.0.0/8", 15169, "Google Cloud", "CLOUD_INFRASTRUCTURE", "US", "Council Bluffs"),
    ("8.8.8.0/24", 15169, "Google Public DNS", "CLOUD_INFRASTRUCTURE", "US", "Mountain View"),
    ("20.0.0.0/8", 8075, "Microsoft Azure", "CLOUD_INFRASTRUCTURE", "US", "Redmond"),
    ("40.0.0.0/8", 8075, "Microsoft Azure", "CLOUD_INFRASTRUCTURE", "US", "Boydton"),
    ("51.0.0.0/8", 8075, "Microsoft Azure", "CLOUD_INFRASTRUCTURE", "IE", "Dublin"),
    ("159.65.0.0/16", 14061, "DigitalOcean", "DATACENTER_VPS", "US", "New York"),
    ("167.99.0.0/16", 14061, "DigitalOcean", "DATACENTER_VPS", "DE", "Frankfurt"),
    ("88.198.0.0/16", 24940, "Hetzner Online", "DATACENTER_DEDICATED", "DE", "Nuremberg"),
    ("136.243.0.0/16", 24940, "Hetzner Online", "DATACENTER_DEDICATED", "DE", "Falkenstein"),
    ("151.101.0.0/16", 54113, "Fastly", "CDN_EDGE", "US", "San Francisco"),
    ("51.254.0.0/16", 16276, "OVHcloud", "DATACENTER_HOSTING", "FR", "Roubaix"),
]


def analyze_ip_intelligence(
    ip_addresses: list[str] | str,
    threat_threshold: float = 60.0,
) -> dict[str, Any]:
    """Analyze a list of IP addresses for ASN attribution, cloud hosting, and threat scores."""
    if isinstance(ip_addresses, str):
        # Support comma or space separated string
        raw_list = [item.strip() for item in ip_addresses.replace(",", " ").split() if item.strip()]
    else:
        raw_list = [str(ip).strip() for ip in ip_addresses if str(ip).strip()]

    parsed_networks = []
    for cidr, asn, org, p_type, cc, city in KNOWN_CLOUD_NETWORKS:
        with contextlib_suppress():
            parsed_networks.append((ipaddress.ip_network(cidr), asn, org, p_type, cc, city))

    results: list[dict[str, Any]] = []
    cloud_providers_found = set()
    datacenter_count = 0
    high_risk_count = 0

    for ip_str in raw_list:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            results.append(
                {
                    "ip": ip_str,
                    "is_valid": False,
                    "error": "Invalid IP address syntax",
                    "threat_score": 0.0,
                }
            )
            continue

        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        is_bogon = ip_obj.is_reserved or ip_obj.is_unspecified

        asn_num = 0
        asn_org = "Unallocated / Generic ISP"
        provider_type = "RESIDENTIAL_OR_GENERIC"
        country_code = "UNKNOWN"
        city = "Unknown"
        is_datacenter = False

        if is_private:
            provider_type = "PRIVATE_SUBNET"
            asn_org = "RFC 1918 Private Subnet"
        elif is_bogon:
            provider_type = "BOGON_RESERVED"
            asn_org = "IANA Reserved Range"
        else:
            # Check against known cloud prefixes
            for net, k_asn, k_org, k_type, k_cc, k_city in parsed_networks:
                if ip_obj in net:
                    asn_num = k_asn
                    asn_org = k_org
                    provider_type = k_type
                    country_code = k_cc
                    city = k_city
                    is_datacenter = "CLOUD" in k_type or "DATACENTER" in k_type or "CDN" in k_type
                    cloud_providers_found.add(k_org)
                    break

        if is_datacenter:
            datacenter_count += 1

        # Calculate threat score
        threat_score = 0.0
        threat_reasons: list[str] = []

        if is_bogon:
            threat_score += 85.0
            threat_reasons.append("Bogon/reserved IP seen in public application manifest.")
        elif is_private:
            threat_score += 10.0
            threat_reasons.append("Hardcoded private RFC 1918 address (internal testing leak).")
        elif is_datacenter:
            # Datacenter egress is normal for mobile APIs; unauthenticated VPS endpoints carry risk
            if "VPS" in provider_type or "DEDICATED" in provider_type:
                threat_score += 35.0
                threat_reasons.append("Endpoint hosted on generic VPS without CDN fronting.")
            else:
                threat_score += 5.0
        else:
            # Residential or unclassified IP endpoint is unusual for mobile apps
            threat_score += 45.0
            threat_reasons.append("Non-cloud / residential IP used for mobile backend.")

        threat_score = round(min(100.0, threat_score), 1)
        if threat_score >= threat_threshold:
            high_risk_count += 1

        risk_level = (
            "CRITICAL"
            if threat_score >= 80.0
            else ("HIGH" if threat_score >= 60.0 else ("MEDIUM" if threat_score >= 30.0 else "LOW"))
        )

        results.append(
            {
                "ip": ip_str,
                "is_valid": True,
                "version": f"IPv{ip_obj.version}",
                "asn": asn_num,
                "asn_org": asn_org,
                "provider_type": provider_type,
                "is_datacenter": is_datacenter,
                "is_private": is_private,
                "is_bogon": is_bogon,
                "country_code": country_code,
                "city": city,
                "threat_score": threat_score,
                "risk_level": risk_level,
                "threat_reasons": threat_reasons,
            }
        )

    return {
        "total_analyzed": len(results),
        "datacenter_ips_count": datacenter_count,
        "high_risk_ips_count": high_risk_count,
        "cloud_providers_identified": sorted(cloud_providers_found),
        "threat_threshold": threat_threshold,
        "intel_records": results,
    }


def contextlib_suppress():
    """Helper to suppress exceptions when building networks."""
    import contextlib

    return contextlib.suppress(Exception)
