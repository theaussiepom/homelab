"""Pure rendering of the private database-network contract; no target operations.

Keep this catalogue separate from rollout approval. Reading it never grants
permission to create a bridge, change a running guest, or replay a deployment.
"""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import re

from site_config import read

ROOT = Path(__file__).resolve().parent
SCHEMA = 'homelab-database-networks-v1'
PORTS = {'postgresql': 5432, 'mariadb': 3306, 'influxdb': 8086}
RFC1918 = tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate(value, existing_cidrs=()):
    require(isinstance(value, dict) and set(value) == {'schema', 'networks'}
            and value['schema'] == SCHEMA and isinstance(value['networks'], dict)
            and set(value['networks']) == set(PORTS), 'Use the closed database network catalogue')
    subnets, bridge_names, macs, identities = [], set(), set(), {}
    for name, net in value['networks'].items():
        require(isinstance(net, dict) and set(net) == {'bridge', 'description', 'cidr', 'server', 'clients'},
                'Declare only bridge purpose, subnet and explicit members')
        require(isinstance(net['bridge'], str) and re.fullmatch(r'vmbr[1-9][0-9]{0,3}', net['bridge'])
                and net['bridge'] not in {'vmbr0', 'vmbr1', 'vmbr30'} and net['bridge'] not in bridge_names,
                'Select distinct private database bridges')
        bridge_names.add(net['bridge'])
        require(isinstance(net['description'], str) and 1 <= len(net['description']) <= 200
                and all(32 <= ord(c) < 127 for c in net['description']), 'Use a short printable bridge purpose')
        require(isinstance(net['cidr'], str), 'Use an IPv4 CIDR string')
        subnet = ipaddress.IPv4Network(net['cidr'], strict=True)
        require(subnet.prefixlen == 24 and any(subnet.subnet_of(n) for n in RFC1918)
                and not any(subnet.overlaps(n) for n in subnets)
                and not any(subnet.overlaps(ipaddress.IPv4Network(n)) for n in existing_cidrs),
                'Database subnets must be distinct unused private /24 networks')
        subnets.append(subnet)
        require(isinstance(net['clients'], list) and 1 <= len(net['clients']) <= 32,
                'Declare a finite approved-client inventory')
        members, addresses = set(), set()
        for member in [net['server'], *net['clients']]:
            require(isinstance(member, dict) and set(member) == {'vmid', 'hostname', 'address', 'mac'},
                    'Select exact guest identities and network addresses')
            vmid = member['vmid']
            require(type(vmid) is int and 100 <= vmid <= 999999999
                    and vmid not in {900, 4914, 4915, 4920} and vmid not in members,
                    'Invalid, duplicate or protected database member')
            require(isinstance(member['hostname'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', member['hostname'])
                    and identities.get(vmid, member['hostname']) == member['hostname'],
                    'A guest identity differs across database networks')
            identities[vmid] = member['hostname']; members.add(vmid)
            require(isinstance(member['address'], str), 'Use an IPv4 address string')
            address = ipaddress.IPv4Address(member['address'])
            require(address in subnet and address not in (subnet.network_address, subnet.broadcast_address)
                    and address not in addresses, 'Invalid or duplicate database address')
            addresses.add(address)
            mac = member['mac']
            require(isinstance(mac, str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)
                    and int(mac[:2], 16) & 3 == 2 and mac not in macs,
                    'Use distinct locally administered unicast MACs')
            macs.add(mac)
        require(net['server']['hostname'] == name, 'Database server identity differs from its engine')
    servers = {net['server']['vmid'] for net in value['networks'].values()}
    require(len(servers) == len(PORTS) and not any(g['vmid'] in servers
            for net in value['networks'].values() for g in net['clients']),
            'A database server cannot implicitly join another database network')
    return value


def selected(value, engine, vmid=None):
    validate(value)
    require(engine in PORTS, 'Select a declared database engine')
    net = value['networks'][engine]
    if vmid is None:
        return net
    members = [g for g in [net['server'], *net['clients']] if g['vmid'] == vmid]
    require(len(members) == 1, 'This guest has no declared database-network membership')
    return net, members[0]


def endpoint(value, engine):
    return {'address': selected(value, engine)['server']['address'], 'port': PORTS[engine]}


def interface(value, engine, vmid):
    net, guest = selected(value, engine, vmid)
    return dict(bridge=net['bridge'], vlan=None, mac=guest['mac'], ipv4=guest['address'] + '/24', ipv6='manual')


def rules(value, engine, vmid):
    net, guest = selected(value, engine, vmid)
    server = net['server']
    clients = net['clients'] if guest == server else [guest]
    return [dict(direction='in' if guest == server else 'out', proto='tcp', port=str(PORTS[engine]),
                 source=client['address'] + '/32', destination=server['address'] + '/32',
                 comment=engine + ' approved client ' + client['hostname']) for client in clients]


def bridges(value):
    validate(value)
    return [dict(name=net['bridge'], description=net['description']) for net in value['networks'].values()]


def attach(guest, value, engines):
    """Append selected DB NICs/rules without changing existing interface order.

    This does not remove old listeners/rules, change application credentials or
    rewrite the installed inputs of a commissioned guest. Those are explicit
    steps in a reviewed migration, after both ends have been verified.
    """
    validate(value)
    require(isinstance(engines, list) and len(engines) == len(set(engines)) and engines,
            'Select each required database once')
    result = copy.deepcopy(guest)
    for engine in engines:
        net, member = selected(value, engine, guest['vmid'])
        require(member['hostname'] == guest['hostname'], 'The selected guest hostname differs')
        nic = interface(value, engine, guest['vmid'])
        existing = [n for n in result['interfaces'] if n['bridge'] == net['bridge']]
        require(not existing or existing == [nic], 'An existing database NIC differs; review the change')
        if not existing:
            require(not any(n['mac'].lower() == nic['mac'] for n in result['interfaces']), 'The new database MAC is occupied')
            result['interfaces'].append(nic)
        for rule in rules(value, engine, guest['vmid']):
            if rule not in result['rules']:
                result['rules'].append(rule)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    value = validate(read(args.config))
    print(json.dumps({'status': 'source_validated', 'bridges': bridges(value), 'target_verified': False}))
