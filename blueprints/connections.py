"""Check both guest firewalls against existing service routes and DNS selections.

This models declared IPv4 connections, without probing networks or assuming router
or host enforcement. External resolvers and client policies remain explicit inputs.
"""

from dataclasses import dataclass
import ipaddress
import network_endpoints
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Connection:
    source: str
    target: str
    source_address: str
    target_address: str
    protocol: str
    port: int


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_identities(configurations):
    """Refuse duplicate IP/MAC identities on the same node, bridge and VLAN."""
    selected = {}
    for name, cfg in configurations.items():
        for nic in cfg["guest"]["interfaces"]:
            link = (
                cfg["site"]["api_endpoint"],
                cfg["site"]["node"],
                nic["bridge"],
                nic.get("vlan"),
            )
            identities = [("MAC", nic["mac"].lower())]
            endpoint = network_endpoints.interface(nic)
            if endpoint is not None:
                identities.append(("IPv4", str(endpoint.ip)))
            for kind, value in identities:
                key = (link, kind, value)
                require(
                    key not in selected,
                    f"Duplicate {kind} network identity between {selected.get(key)} and {name}",
                )
                selected[key] = name


def source_address(guest, destination):
    """Use a connected interface, otherwise the declared default IPv4 route."""
    address = ipaddress.IPv4Address(destination)
    nics = [
        (nic, endpoint)
        for nic in guest["interfaces"]
        if (endpoint := network_endpoints.interface(nic)) is not None
    ]
    connected = [(nic, ip) for nic, ip in nics if address in ip.network]
    if connected:
        prefix = max(ip.network.prefixlen for _, ip in connected)
        selected = [
            (nic, ip) for nic, ip in connected if ip.network.prefixlen == prefix
        ]
    else:
        selected = [(nic, ip) for nic, ip in nics if nic.get("gateway") or nic["ipv4"] == "dhcp"]
    require(
        len(selected) == 1,
        "Declare an unambiguous source interface for guest connections",
    )
    return str(selected[0][1].ip)


def connections(configurations, external_routes=None):
    """Project required internal traffic from the existing endpoint authorities."""

    def connection(source, target, address, protocol, port):
        require(
            source in configurations, "Declare the ingress guest for published routes"
        )
        return Connection(
            source,
            target,
            source_address(configurations[source]["guest"], address),
            address,
            protocol,
            port,
        )

    for route in (external_routes or {}).values():
        origin = urlsplit(route["url"])
        yield connection(
            "ingress",
            None,
            origin.hostname,
            "tcp",
            origin.port or (443 if origin.scheme == "https" else 80),
        )
    for name, cfg in configurations.items():
        for route in cfg.get("routes", {}).values():
            origin = urlsplit(route["url"])
            yield connection(
                "ingress",
                name,
                origin.hostname,
                "tcp",
                origin.port or (443 if origin.scheme == "https" else 80),
            )
        for resolver in dict.fromkeys(cfg["guest"]["dns_servers"]):
            address = str(ipaddress.IPv4Address(resolver))
            owners = {
                other
                for other, row in configurations.items()
                if address in network_endpoints.addresses(row["guest"])
            }
            require(
                len(owners) <= 1, "Assign each internal resolver address to one guest"
            )
            if owners and name not in owners:
                target = next(iter(owners))
                for protocol in ("tcp", "udp"):
                    yield connection(name, target, address, protocol, 53)


def permits(rules, direction, connection):
    def includes_network(value, address):
        if value is None:
            return True
        require(isinstance(value, str), "Use a literal IPv4 firewall network")
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(
            value, strict=False
        )

    def includes_port(value):
        if value is None:
            return True
        require(isinstance(value, str), "Use explicit firewall ports")
        ranges = value.split(",")
        require(
            all(
                re.fullmatch(r"[1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?", item)
                for item in ranges
            ),
            "Use literal firewall ports or colon-delimited ranges",
        )
        bounds = [tuple(map(int, item.split(":"))) for item in ranges]
        require(
            all(1 <= row[0] <= row[-1] <= 65535 for row in bounds),
            "Use valid firewall port ranges",
        )
        return any(row[0] <= connection.port <= row[-1] for row in bounds)

    return any(
        rule["direction"] == direction
        and rule["proto"] == connection.protocol
        and includes_network(rule.get("source"), connection.source_address)
        and includes_network(rule.get("destination"), connection.target_address)
        and includes_port(rule.get("port"))
        for rule in rules
    )


def validate(configurations, external_routes=None):
    import service_bindings

    validate_identities(configurations)
    for connection in [
        *connections(configurations, external_routes),
        *service_bindings.connections_for(configurations),
    ]:
        for guest, direction in ((connection.source, "out"), (connection.target, "in")):
            if guest is None:
                continue
            require(
                permits(configurations[guest]["guest"]["rules"], direction, connection),
                f"Permit {connection.source} -> {connection.target} {connection.protocol}/{connection.port} in the {guest} {direction} firewall",
            )
