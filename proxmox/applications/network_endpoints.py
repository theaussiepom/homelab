"""Resolve reviewed interface endpoints without changing provider allocation."""

import ipaddress
from private_io import require


def interface(nic):
    """DHCP requires a qualified assigned CIDR; static allocation is its endpoint."""
    allocation = nic["ipv4"]
    if allocation == "dhcp":
        require(
            "ipv4_endpoint" in nic and nic.get("gateway") is None,
            "DHCP requires a qualified IPv4 endpoint and no static gateway",
        )
        value = nic["ipv4_endpoint"]
    else:
        require("ipv4_endpoint" not in nic, "Only DHCP declares a separate IPv4 endpoint")
        if allocation == "manual":
            return None
        value = allocation
    require(isinstance(value, str) and "/" in value, "Use an explicit assigned IPv4 endpoint CIDR")
    selected = ipaddress.IPv4Interface(value)
    require(str(selected) == value, "Use a canonical assigned IPv4 endpoint CIDR")
    return selected


def addresses(guest):
    """Validate every interface and return its concrete assigned IPv4 address."""
    return {str(value.ip) for nic in guest["interfaces"] if (value := interface(nic)) is not None}
