"""Resolve published application endpoints into consumers, DNS and firewall edges."""

import connections
import dns_records


def bind(resolved, route_records=None):
    endpoints, records = {}, dict(route_records or {})
    for guest, (cfg, _, _) in resolved.items():
        publications = cfg["app"].get("published_services", {})
        connections.require(
            isinstance(publications, dict), "Declare a named service map"
        )
        for application, endpoint in publications.items():
            connections.require(
                isinstance(endpoint, dict)
                and application in cfg["app"]["service_health_checks"]
                and set(endpoint)
                == {"hostname", "addresses", "dns_address", "protocol", "port"}
                and endpoint["protocol"] == "tcp"
                and isinstance(endpoint["addresses"], dict)
                and endpoint["addresses"]
                and endpoint["dns_address"] in endpoint["addresses"]
                and type(endpoint["port"]) is int
                and 1 <= endpoint["port"] <= 65535,
                "Publish a named application with a literal TCP endpoint",
            )
            name = endpoint["hostname"]
            address = endpoint["addresses"][endpoint["dns_address"]]
            for value in endpoint["addresses"].values():
                dns_records.validate({name: value})
            connections.require(
                set(endpoint["addresses"].values())
                <= {nic["ipv4"].split("/")[0] for nic in cfg["guest"]["interfaces"]}
                and name not in records,
                "Publish a unique hostname on its owning guest interface",
            )
            endpoints[guest + "." + application] = endpoint
            records[name] = address
    for guest, (cfg, stack, _) in resolved.items():
        required = cfg["app"].get("service_connections", {})
        connections.require(
            isinstance(required, dict)
            and set(required) <= set(cfg["app"]["service_health_checks"]),
            "Bind consumers to their declared application",
        )
        for application, binding in required.items():
            connections.require(
                isinstance(binding, dict) and set(binding) == {"service", "address"},
                "Select a named service and one of its declared addresses",
            )
            selected = binding["service"]
            connections.require(
                selected in endpoints and selected != guest + "." + application,
                "Select an existing external application endpoint",
            )
            endpoint = endpoints[selected]
            connections.require(
                binding["address"] in endpoint["addresses"],
                "Select a declared service address",
            )
            address = endpoint["addresses"][binding["address"]]
            if stack is not None and stack["kind"] == "zigbee2mqtt":
                connections.require(
                    endpoint["port"] == 1883, "Select the preserved MQTT listener"
                )
                stack["zigbee"]["mqtt_server"] = (
                    "mqtt://" + endpoint["hostname"] + ":" + str(endpoint["port"])
                )
                aliases = stack["services"][application].setdefault("extra_hosts", {})
                connections.require(
                    endpoint["hostname"] not in aliases
                    or aliases[endpoint["hostname"]] == address,
                    "Service bindings must not conflict with explicit host aliases",
                )
                aliases[endpoint["hostname"]] = address
        if stack is not None and stack["kind"] == "dns":
            existing = dns_records.validate(stack.get("dns_records", {}))
            connections.require(
                all(
                    name not in existing or existing[name] == address
                    for name, address in records.items()
                ),
                "Published services must not conflict with explicit DNS records",
            )
            stack["dns_records"] = dict(existing, **records)
            for name, address in sorted(stack["dns_records"].items()):
                check = {
                    "name": "DNS service record " + name,
                    "argv": [
                        "python3",
                        "/opt/homelab-app/dns_records.py",
                        "probe",
                        name,
                        address,
                    ],
                    "expect": '"read_only_dns_check": "passed"',
                }
                cfg["app"]["service_health_checks"]["pihole"].append(check)
                cfg["app"]["health_checks"].append(check)
    return endpoints


def connections_for(configurations):
    endpoints = {
        guest + "." + application: (guest, endpoint)
        for guest, cfg in configurations.items()
        for application, endpoint in cfg["app"].get("published_services", {}).items()
    }
    for source, cfg in configurations.items():
        for binding in cfg["app"].get("service_connections", {}).values():
            guest, endpoint = endpoints[binding["service"]]
            address = endpoint["addresses"][binding["address"]]
            yield connections.Connection(
                source,
                guest,
                connections.source_address(cfg["guest"], address),
                address,
                endpoint["protocol"],
                endpoint["port"],
            )
