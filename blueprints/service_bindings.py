"""Resolve published application endpoints into consumers, DNS and firewall edges."""

import connections
import network_endpoints
import dns_records
import cloudbeaver
import database_admin
import managed_credentials
import mqtt_explorer


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
                <= network_endpoints.addresses(cfg["guest"])
                and name not in records,
                "Publish a unique hostname on its owning guest interface",
            )
            endpoints[guest + "." + application] = endpoint
            records[name] = address
    owners, credential_ids, referenced = {}, set(), set()
    for guest, (cfg, stack, _) in resolved.items():
        for account_id, value in database_admin.accounts(cfg).items():
            source = value['source_guest']
            connections.require(source in resolved and resolved[source][1] is not None
                                and cloudbeaver.selected(resolved[source][1]),
                                'Bind administrator access only to the declared Community client guest')
            endpoint = endpoints.get(guest+'.'+cfg['app']['kind'])
            connections.require(endpoint is not None and endpoint['port'] == database_admin.KINDS[cfg['app']['kind']],
                                'Publish the selected administrator database listener')
            address = endpoint['addresses'][endpoint['dns_address']]
            source_cfg = resolved[source][0]
            connections.require(cfg['paths']['state_root'] == source_cfg['paths']['state_root'],
                                'Keep linked account credentials in the same declared controller state root')
            value['owner'] = {'node': cfg['site']['node'], 'engine': cfg['app']['kind'],
                'database_vmid': cfg['guest']['vmid'], 'source_vmid': source_cfg['guest']['vmid'],
                'server_address': address, 'source_address': connections.source_address(source_cfg['guest'], address),
                'username': value['username'], 'purpose': 'database-administration'}
            connections.require(value['credential_id'] not in credential_ids,
                                'Keep independent credentials for distinct managed accounts')
            credential_ids.add(value['credential_id']); owners[guest+'.'+account_id] = value
        explorer = mqtt_explorer.validate(stack) if stack is not None else None
        broker = explorer.get('broker_connection') if explorer is not None else None
        if broker is not None:
            connections.require(broker['credential_id'] not in credential_ids,
                                'Keep independent credentials for distinct managed accounts')
            credential_ids.add(broker['credential_id'])
    for guest, (cfg, stack, _) in resolved.items():
        required = cfg["app"].get("service_connections", {})
        cloud = stack is not None and cloudbeaver.selected(stack)
        managed = database_admin.connections(stack['cloudbeaver']) if cloud else {}
        allowed = ({'cloudbeaver.' + name for name in {*stack['cloudbeaver']['connections'], *managed}}
                   if cloud else set(cfg['app']['service_health_checks']))
        connections.require(isinstance(required, dict) and set(required) <= allowed,
                            "Bind consumers to their declared application")
        if cloud:
            connections.require(set(required) == allowed,
                                'Bind every metadata-only CloudBeaver database connection')
        explorer = (stack is not None and stack.get('kind') == 'mqtt'
                    and 'broker_connection' in stack.get('mqtt_explorer', {}))
        if explorer:
            connections.require('mqtt_explorer' in required, 'Bind Explorer to the existing broker publication')
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
            if cloud:
                name = application.removeprefix('cloudbeaver.')
                value = managed[name] if name in managed else stack['cloudbeaver']['connections'][name]
                connections.require(selected == value['driver'] + '.' + value['driver']
                                    and endpoint['port'] == cloudbeaver.DRIVERS[value['driver']][2],
                                    'Bind CloudBeaver metadata to its declared database engine')
                value.update(host=address, port=endpoint['port'])
                if name in managed:
                    account_key = selected.rsplit('.', 1)[0]+'.'+value['account_id']
                    account = owners.get(account_key)
                    connections.require(account is not None and account['source_guest'] == guest
                                        and account['owner']['server_address'] == address,
                                        'Bind the exact managed account to its declared client source and listener')
                    value.update(username=account['username'], credential_id=account['credential_id'],
                        credential_file='${inputs}/'+managed_credentials.input_name(account['credential_id']),
                        owner=account['owner'], transport=account['transport'])
                    referenced.add(account_key)
            if explorer and application == 'mqtt_explorer':
                value = stack['mqtt_explorer']['broker_connection']
                connections.require(selected == guest+'.mqtt' and endpoint['port'] == 1883
                                    and value['hostname'] == endpoint['hostname'] and value['port'] == 1883,
                                    'Keep the Explorer account on its owning broker listener')
            if stack is not None and stack["kind"] == "zigbee2mqtt":
                connections.require(
                    endpoint["port"] == 1883, "Select the preserved MQTT listener"
                )
                stack["winet" if application == "winet" else "zigbee"]["mqtt_server"] = (
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
    connections.require(referenced == set(owners), 'Use each declared server-administrator account in its client composition')
    return endpoints


def connections_for(configurations):
    endpoints = {
        guest + "." + application: (guest, endpoint)
        for guest, cfg in configurations.items()
        for application, endpoint in cfg["app"].get("published_services", {}).items()
    }
    for source, cfg in configurations.items():
        for application, binding in cfg["app"].get("service_connections", {}).items():
            guest, endpoint = endpoints[binding["service"]]
            address = endpoint["addresses"][binding["address"]]
            if (guest == source and cfg['app']['kind'] == 'mqtt' and application == 'mqtt_explorer'
                    and binding['service'] == source+'.mqtt' and endpoint['port'] == 1883):
                continue  # This validated co-located application has no external socket edge.
            yield connections.Connection(
                source,
                guest,
                connections.source_address(cfg["guest"], address),
                address,
                endpoint["protocol"],
                endpoint["port"],
            )
