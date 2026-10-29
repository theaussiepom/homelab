"""Resolve site routes to app endpoints without coupling routing to app runtimes."""

import copy
import discovery
import network_endpoints


def bind(resolved, routes):
    discovery.require(isinstance(routes, dict), "Declare a named routes map")
    endpoints = {}
    for guest, (cfg, _, _) in resolved.items():
        discovery.require(
            not {"routes", "external_routes"} & cfg.keys(),
            "Declare routes only in the stack routes map",
        )
        cfg["routes"] = {}
        declared = cfg["app"].get("endpoints", {})
        discovery.require(
            isinstance(declared, dict), "Declare named application endpoints"
        )
        for application, named in declared.items():
            discovery.require(
                application in cfg["app"]["service_health_checks"]
                and isinstance(named, dict),
                "Endpoints belong to declared applications",
            )
            for key, url in named.items():
                discovery.name(key)
                discovery.origin(
                    url,
                    network_endpoints.addresses(cfg["guest"]),
                )
                endpoints[guest + "." + application + "." + key] = (guest, url)
    if "ingress" in resolved:
        settings = resolved["ingress"][1].setdefault("routing", {})
        discovery.require(
            "routes" not in settings, "Declare routes only in the stack routes map"
        )
        discovery.validate_ingress(settings)
    if not routes:
        return {}
    discovery.require("ingress" in resolved, "Declare ingress for HTTP routes")
    _, stack, _ = resolved["ingress"]
    settings = stack["routing"]
    all_routes, external = {}, {}
    for key, row in routes.items():
        discovery.require(
            isinstance(row, dict) and "target" in row, "Declare a route target"
        )
        selected = copy.deepcopy(row)
        target = selected.pop("target")
        discovery.require(
            isinstance(target, dict)
            and (set(target) == {"endpoint"} or set(target) == {"url"}),
            "Select exactly one app endpoint or external URL",
        )
        if "endpoint" in target:
            discovery.require(
                isinstance(target["endpoint"], str) and target["endpoint"] in endpoints,
                "Select a declared application endpoint",
            )
            owner, url = endpoints[target["endpoint"]]
            destination = resolved[owner][0]["routes"]
        else:
            url, destination = target["url"], external
            address = discovery.origin(url).hostname
            discovery.require(
                address
                not in {
                    address
                    for cfg, _, _ in resolved.values()
                    for address in network_endpoints.addresses(cfg["guest"])
                },
                "Use an app endpoint for a managed guest backend",
            )
        discovery.require(
            "url" not in selected, "Keep backend selection in the route target"
        )
        selected["url"] = url
        destination[key] = selected
        all_routes[key] = selected
    hosts = discovery.validate_routes(all_routes)
    for route in all_routes.values():
        discovery.references(route, settings)
    settings["routes"] = external
    frontend = stack["foundation"]["bind_address"]
    return {host: frontend for host in hosts}
