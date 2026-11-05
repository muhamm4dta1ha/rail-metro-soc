"""Lab address space and zones (single source of truth).

Hard constraint HC-18: every simulated asset, attacker host and generated packet stays inside
LAB_CIDR on isolated (internal) Docker networks. Nothing here may ever point at a real,
operational or internet-reachable network.
"""

from __future__ import annotations

import ipaddress

LAB_CIDR = ipaddress.ip_network("10.60.0.0/16")

# Zone name == Docker network name == `asset.zone` value in the event schema.
ZONES: dict[str, ipaddress.IPv4Network] = {
    "corporate_it": ipaddress.IPv4Network("10.60.10.0/24"),
    "dmz_ops": ipaddress.IPv4Network("10.60.20.0/24"),
    "station_field": ipaddress.IPv4Network("10.60.30.0/24"),
    "attacker_lab": ipaddress.IPv4Network("10.60.66.0/24"),
    "soc_mgmt": ipaddress.IPv4Network("10.60.99.0/24"),
}


def in_lab(ip: str) -> bool:
    """True if `ip` is a literal IP address inside the lab address space."""
    try:
        return ipaddress.ip_address(ip) in LAB_CIDR
    except ValueError:
        return False


def zone_of(ip: str) -> str | None:
    """Return the zone that contains `ip`, or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in ZONES.items():
        if addr in net:
            return name
    return None
