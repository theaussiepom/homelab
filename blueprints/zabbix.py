"""Expand one root Zabbix marker into a closed monitoring composition.

Only declarations are handled here. No credentials, target access or deployment
side effects belong in the blueprint compiler.
"""
import copy
import ipaddress

import connections
from private_io import require

GUEST = "monitoring"


def enabled(overlay):
    if "zabbix" not in overlay:
        return False
    require(overlay["zabbix"] is None,
            "Use an empty root zabbix property; custom monitoring settings are not implemented")
    return True


def selected(spec, overlay):
    active = enabled(overlay)
    require(not active or GUEST in spec["guests"],
            "The selected stack must declare the dedicated Zabbix guest")
    result = copy.deepcopy(spec)
    if not active:
        if GUEST in result["guests"]:
            result["guests"].pop(GUEST)
            result["_inactive_guests"] = [GUEST]
    return result


def rule(direction, source, destination, port):
    return {"direction": direction, "source": source + "/32",
            "destination": destination + "/32", "proto": "tcp",
            "port": str(port), "comment": "Blueprint Zabbix monitoring"}


def database_hba(original, source):
    """Admit only the owned monitoring accounts before existing deny rules."""
    require(ipaddress.IPv4Address(source).is_private,
            "Use the declared private monitoring database source")
    return ('# Root Zabbix: dedicated storage and local statistics only\n'
            'host postgres zbx_monitor 127.0.0.1/32 scram-sha-256\n'
            'host zabbix zabbix 127.0.0.1/32 scram-sha-256\n'
            'host zabbix zabbix ' + source + '/32 scram-sha-256\n' + original)


def bind(resolved, enabled_guests, values):
    """Derive one agent per guest, its workload profiles and exact TCP edges."""
    server_cfg, server_stack, _ = resolved[GUEST]
    address = server_stack["monitoring"]["bind_address"]
    require(str(ipaddress.IPv4Address(address)) == server_cfg["app"]["address"],
            "Expose monitoring only on its declared management interface")
    ingress_cfg = resolved['ingress'][0]
    ingress_cfg['guest']['rules'].append(rule('out',
        connections.source_address(ingress_cfg['guest'], address), address, 8080))
    members = []
    for name, (cfg, _, _) in resolved.items():
        require("monitoring" not in cfg["app"],
                "Monitoring agent settings are derived from the root feature")
        hostname = cfg["site"]["node"] + "-" + str(cfg["guest"]["vmid"])
        profiles = ["linux"]
        if "docker" in cfg["deployment"]["capabilities"]:
            profiles.append("docker")
        if name in {"postgresql", "mariadb", "influxdb"}:
            profiles.append({"mariadb": "mysql"}.get(name, name))
        agent = {"hostname": hostname, "psk_identity": hostname,
                 "server_active": address + ":10051", "profiles": profiles,
                 "server_vmid": server_cfg["guest"]["vmid"],
                 "credential_file": "${inputs}/monitoring-agent.json"}
        cfg["app"]["monitoring"] = agent
        source = connections.source_address(cfg["guest"], address)
        if name != GUEST:
            cfg["guest"]["rules"].append(rule("out", source, address, 10051))
            server_cfg["guest"]["rules"].append(rule("in", source, address, 10051))
        if name in enabled_guests:
            members.append({"guest": name, "vmid": cfg["guest"]["vmid"],
                            "guest_hostname": cfg["guest"]["hostname"],
                            "hostname": hostname, "psk_identity": hostname, "profiles": list(profiles)})
    server_cfg["app"]["monitoring"]["members"] = members
    require(len({m["hostname"] for m in members}) == len(members),
            "Use distinct Zabbix host and PSK identities")
    # Native database plugins run inside their owning guest; they never need
    # remote statistics accounts or general database network access.
    for name in ("postgresql", "mariadb"):
        if name in resolved:
            cfg = resolved[name][0]
            db_address = "127.0.0.1" if name == "postgresql" else values["addresses.mariadb_backend"]
            cfg["app"]["monitoring"]["database_uri"] = "tcp://" + db_address + (":5432" if name == "postgresql" else ":3306")
            cfg["app"]["monitoring"]["database_password_file"] = "${inputs}/monitoring-database-password"
    resolved["postgresql"][0]["app"]["monitoring"]["storage_password_file"] = "${inputs}/monitoring-storage-password"
    server_cfg["app"]["monitoring"]["server_file"] = "${inputs}/monitoring-server.json"
    server_cfg["app"]["monitoring"]["proxmox"] = {
        "hostname": server_cfg["site"]["node"],
        "endpoint": server_cfg["site"]["api_endpoint"],
        "ca_file": server_cfg["paths"]["ca_file"],
    }
    for name, port in [('postgresql', 5432), ('influxdb', 8086)]:
        cfg = resolved[name][0]
        target = values['addresses.' + name + '_backend']
        server_cfg['app']['monitoring'][name + '_address'] = target
        source = connections.source_address(server_cfg['guest'], target)
        server_cfg['guest']['rules'].append(rule('out', source, target, port))
        cfg['guest']['rules'].append(rule('in', source, target, port))
        if name == 'postgresql':
            files = resolved[name][2]
            require('pg_hba.conf' in files, 'Declare PostgreSQL HBA before adding the monitoring database')
            files['pg_hba.conf'] = database_hba(files['pg_hba.conf'], source)
        else:
            for member in members:
                if member['guest'] == name:
                    member['url'] = 'http://' + target + ':8086'


def connections_for(configurations):
    if GUEST not in configurations:
        return
    address = configurations[GUEST]["app"]["address"]
    for name, cfg in configurations.items():
        if name != GUEST:
            yield connections.Connection(name, GUEST,
                connections.source_address(cfg["guest"], address), address, "tcp", 10051)
    server = configurations[GUEST]
    for name, port in [('postgresql', 5432), ('influxdb', 8086)]:
        target = server['app']['monitoring'][name + '_address']
        yield connections.Connection(GUEST, name,
            connections.source_address(server['guest'], target), target, 'tcp', port)
