"""Render the reviewed foundation profiles from one non-secret site file.

This performs local validation/rendering only. It never contacts a host, grants
access, reads a secret, or changes an existing runner input or state receipt.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parent
KINDS = ('ingress', 'identity', 'db-tools')
SCHEMA = 'homelab-foundation-site-v1'
PATHS = {'api_token': '/var/lib/homelab-inputs/pve-token',
         'backup_directory': '/srv/homelab-backups/applications', 'backup_mount': '/srv/homelab-backups',
         'ca_file': '/usr/local/share/ca-certificates/homelab-pve.crt',
         'known_hosts': '/var/lib/homelab-inputs/known_hosts',
         'private_key': '/home/homelab-runner/.ssh/applications', 'state_root': '/var/lib/homelab-applications'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 131072, 'Expected a bounded site JSON file')
        content = stream.read(131073)
    require(len(content) <= 131072, 'Oversized site file')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate site configuration key')
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=unique)


def shape(value, example):
    require(type(value) is type(example), 'Site field type differs from the public example')
    if isinstance(example, dict):
        require(set(value) == set(example), 'Missing or unknown site configuration field')
        for key in example:
            shape(value[key], example[key])
    elif isinstance(example, list):
        require(1 <= len(value) <= 16, 'Site lists must contain 1 to 16 entries')
        for item in value:
            shape(item, example[0])
    elif isinstance(example, str):
        require(len(value) <= 16384 and not any(char in value for char in '\r\n\x00'), 'Invalid site text field')


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    require(address.is_private and not address.is_loopback and not address.is_unspecified
            and not address.is_multicast and not address.is_link_local, 'Expected a private unicast IPv4 address')
    return address


def validate(cfg):
    shape(cfg, read(ROOT / 'examples/foundation.site.example.json'))
    require(cfg['schema'] == SCHEMA, 'Unknown foundation site schema')
    require(re.fullmatch('[a-z][a-z0-9-]{0,62}', cfg['host']['node']) is not None, 'Invalid Proxmox node name')
    nets = {name: ipaddress.IPv4Network(value['cidr']) for name, value in cfg['networks'].items()}
    for name, network in nets.items():
        require(network.is_private and network.prefixlen == 24, 'Foundation networks must be private /24 subnets')
        require(re.fullmatch(r'vmbr[0-9]{1,4}', cfg['networks'][name]['bridge']) is not None, 'Invalid bridge name')
        for other in nets:
            if other != name:
                require(not network.overlaps(nets[other]), 'Foundation subnets overlap')
    for name in ('management', 'frontend'):
        require(1 <= cfg['networks'][name]['vlan'] <= 4094, 'Invalid VLAN tag')
    require(cfg['networks']['backend']['bridge'] not in
            {cfg['networks'][name]['bridge'] for name in ('management', 'frontend')}, 'Backend bridge must stay isolated')
    ids, addresses, macs = [], [], []
    def target(value):
        require(100 <= value['vmid'] <= 999999999 and value['vmid'] not in {4914, 4915, 4920}, 'Invalid or protected guest ID')
        require(re.fullmatch('[a-z][a-z0-9-]{0,62}', value.get('hostname', 'deploy')) is not None, 'Invalid guest hostname')
        ids.append(value['vmid'])
    def address(value, network):
        parsed = ipv4(value)
        require(parsed in nets[network] and parsed not in (nets[network].network_address, nets[network].broadcast_address),
                'Site address is outside its declared network')
        addresses.append(value)
    def mac(value):
        require(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value) is not None
                and int(value[:2], 16) & 3 == 2, 'Expected a locally administered unicast MAC')
        macs.append(value)
    for value in (cfg['runner'], cfg['dns'], *cfg['databases'].values(), *cfg['guests'].values()):
        target(value)
    address(cfg['host']['address'], 'management'); address(cfg['runner']['address'], 'management')
    address(cfg['networks']['management']['gateway'], 'management'); address(cfg['networks']['frontend']['gateway'], 'frontend'); address(cfg['dns']['address'], 'frontend')
    address(cfg['databases']['postgresql']['address'], 'backend')
    mac(cfg['runner']['mac']); mac(cfg['dns']['mac']); ipv4(cfg['dns']['fallback']); ipv4(cfg['dns']['legacy_proxy'])
    for kind, guest in cfg['guests'].items():
        expected = {'management', 'backend', 'frontend'} if kind == 'ingress' else {'management', 'backend'}
        require(set(guest['interfaces']) == expected, 'Unexpected foundation interface role')
        for role, interface in guest['interfaces'].items():
            address(interface['address'], role); mac(interface['mac'])
        require(re.fullmatch('[0-9a-f]{64}', guest['capture_sha256']) is not None, 'Expected a selected capture hash')
    require(len(ids) == len(set(ids)) and len(addresses) == len(set(addresses)) and len(macs) == len(set(macs)),
            'Guest IDs, addresses or MACs collide')
    require(re.fullmatch(r'[0-9]{1,5}', cfg['smtp']['AUTHENTIK_EMAIL__PORT']) is not None
            and 1 <= int(cfg['smtp']['AUTHENTIK_EMAIL__PORT']) <= 65535, 'Invalid SMTP relay port')
    domains = cfg['domains']
    names = [domains['identity'], domains['db_tools'], *domains['redirect'], *[row['name'] for row in domains['preserve']]]
    for name in names:
        require(len(name) <= 253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', name) is not None,
                'Use lowercase fully qualified DNS names')
    require(len(set(names)) == len(names), 'Selected DNS names or zones collide')
    for name in (domains['identity'], domains['db_tools']):
        require(len('_acme-challenge.' + name) <= 253, 'ACME challenge name exceeds the DNS length limit')
        require(sum(name.endswith('.' + zone) for zone in domains['redirect']) == 1,
                'Each route must belong to exactly one selected redirect zone')
    for row in domains['preserve']:
        ipv4(row['address'])
    for network in cfg['ingress']['client_networks']:
        require(ipaddress.IPv4Network(network).is_private, 'Ingress clients must be explicit private subnets')
    require(re.fullmatch(r'[^\s@:]+:/[^\s]+', cfg['runner']['backup_source']) is not None, 'Expected the selected NAS subdirectory')
    return cfg


def lookup(context, reference):
    value = context
    for part in reference.split('.'):
        require(isinstance(value, dict) and part in value, 'Unknown internal profile reference')
        value = value[part]
    return copy.deepcopy(value)


def expand(value, context):
    # References occur only in pinned public profiles; site strings are data.
    if isinstance(value, dict):
        if set(value) == {'$ref'}:
            return lookup(context, value['$ref'])
        return {key: expand(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [expand(item, context) for item in value]
    if isinstance(value, str):
        def scalar(match):
            item = lookup(context, match.group(1))
            require(type(item) in (str, int), 'A profile string reference must be scalar')
            return str(item)
        return re.sub(r'\$\{([a-zA-Z0-9_.-]+)\}', scalar, value)
    return value


def rule(direction, port, comment, peer, value, proto='tcp', destination=None):
    result = dict(direction=direction, proto=proto, port=port, comment=comment, **{peer: value})
    if destination is not None:
        result['destination'] = destination
    return result


def render(cfg, database_networks=None):
    validate(cfg)
    context = copy.deepcopy(cfg)
    site = {'node': cfg['host']['node'], 'api_endpoint': 'https://' + cfg['host']['address'] + ':8006/'}
    paths = dict(PATHS, backup_source=cfg['runner']['backup_source'])
    interfaces, rules = {}, {}
    proxy = cfg['guests']['ingress']['interfaces']
    pg_address = cfg['databases']['postgresql']['address']
    for kind, guest in cfg['guests'].items():
        interfaces[kind] = []
        for role in ('management', 'backend', 'frontend'):
            if role not in guest['interfaces']:
                continue
            nic = guest['interfaces'][role]
            network = cfg['networks'][role]
            interface = dict(bridge=network['bridge'], vlan=network.get('vlan'), mac=nic['mac'],
                             ipv4=nic['address'] + '/24', ipv6='manual')
            if role == 'management':
                interface['gateway'] = network['gateway']
            interfaces[kind].append(interface)
        selected = [rule('in', '22', 'Deployment runner SSH only', 'source', cfg['runner']['address'] + '/32')]
        for dns in (cfg['dns']['address'], cfg['dns']['fallback']):
            selected += [rule('out', '53', 'Existing internal DNS', 'destination', dns + '/32', proto) for proto in ('udp', 'tcp')]
        selected.append(rule('out', '80,443', 'Signed packages, pinned images, provider and HTTPS', 'destination', '0.0.0.0/0'))
        if kind == 'ingress':
            selected += [rule('in', '80,443', 'Selected internal HTTPS clients', 'source', network,
                              destination=proxy['frontend']['address'] + '/32') for network in cfg['ingress']['client_networks']]
            selected.append(rule('out', '8006', 'Pinned Proxmox discovery API only', 'destination', cfg['host']['address'] + '/32'))
            for backend, port in (('identity', '9000'), ('db-tools', '80')):
                selected.append(rule('out', port, 'Selected discovered backend', 'destination',
                                     cfg['guests'][backend]['interfaces']['backend']['address'] + '/32'))
        else:
            selected.append(rule('in', '9000' if kind == 'identity' else '80', 'Traefik backend only', 'source',
                                 proxy['backend']['address'] + '/32', destination=guest['interfaces']['backend']['address'] + '/32'))
            selected.append(rule('out', '5432', 'Restored Authentik database only' if kind == 'identity' else 'PostgreSQL administration only',
                                 'destination', pg_address + '/32'))
            if kind == 'identity':
                selected.append(rule('out', cfg['smtp']['AUTHENTIK_EMAIL__PORT'], 'Existing Google Workspace SMTP relay', 'destination', '0.0.0.0/0'))
        rules[kind] = selected
    context['derived'] = dict(site=site, paths=paths, interfaces=interfaces, rules=rules,
                              dns_servers=[cfg['dns']['address'], cfg['dns']['fallback']])
    files = {}
    for kind in KINDS:
        for name in ('site', 'stack'):
            files[f'{kind}/{name}.json'] = expand(read(ROOT / f'foundation-profiles/{kind}.{name}.json'), context)
    files['ingress/site.json']['app']['frontend_routing'] = dict(
        address=proxy['frontend']['address'] + '/24', gateway=cfg['networks']['frontend']['gateway'],
        mac=proxy['frontend']['mac'])
    files['rollout.json'] = {'schema': 'homelab-foundation-rollout-v1', 'targets': {
        kind: {'vmid': cfg['guests'][kind]['vmid'], 'policy': 'merge-create-only-v1'} for kind in KINDS}}
    # The bootstrap and guest jobs consume the very same declared identities.
    grants = [{'path': '/nodes/' + cfg['host']['node'], 'role': 'PVEAuditor', 'propagate': 0}]
    for name in ('management', 'frontend'):
        network = cfg['networks'][name]; base = '/sdn/zones/localnetwork/' + network['bridge']
        for path in (base, base + '/' + str(network['vlan'])):
            grants.append(dict(path=path, role='PVESDNUser', propagate=0))
    grants += [dict(path='/storage/local', role='PVEAuditor', propagate=0),
               dict(path='/storage/' + cfg['storage']['id'], role='PVEDatastoreUser', propagate=0)]
    grants += [dict(path='/vms/' + str(cfg[name]['vmid']), role='PVEVMAdmin', propagate=0) for name in ('dns', 'runner')]
    files['bootstrap.json'] = dict(schema='homelab-bootstrap-cd-v1', endpoint=site['api_endpoint'], node=site['node'],
        deploy={name: cfg['runner'][name] for name in ('vmid', 'mac')}, bridge=cfg['networks']['backend']['bridge'],
        applications=[{name: guest[name] for name in ('vmid', 'hostname')} for guest in
                      (*(cfg['databases'][kind] for kind in ('postgresql', 'mariadb', 'influxdb')), *(cfg['guests'][kind] for kind in KINDS))], existing_grants=grants,
        backup_source=paths['backup_source'], service_discovery=dict(vmid=cfg['guests']['ingress']['vmid'],
        address=proxy['management']['address'], guests=sorted(guest['vmid'] for guest in cfg['guests'].values())))
    files['bindings.json'] = dict(site=site, guests={kind: [cfg['guests'][kind]['vmid'], cfg['guests'][kind]['hostname']] for kind in KINDS})
    files['dns-settings.json'] = dict(schema='homelab-foundation-dns-v1', site=site, target={key: cfg['dns'][key] for key in ('vmid','hostname','mac','address')},
        records={domains: proxy['frontend']['address'] for domains in (cfg['domains']['identity'], cfg['domains']['db_tools'])},
        redirects={name: proxy['frontend']['address'] for name in cfg['domains']['redirect']},
        unchanged={row['name']: row['address'] for row in cfg['domains']['preserve']},
        legacy_proxy=cfg['dns']['legacy_proxy'], acme_exceptions=['_acme-challenge.' + name for name in (cfg['domains']['identity'], cfg['domains']['db_tools'])])
    if database_networks is not None:
        import database_networks as dbnets
        dbnets.validate(database_networks, [n['cidr'] for n in cfg['networks'].values()])
        site_bridges = {n['bridge'] for n in cfg['networks'].values()}
        require(not any(net['bridge'] in site_bridges for net in database_networks['networks'].values()),
                'A database bridge must differ from every site network bridge')
        for engine, net in database_networks['networks'].items():
            require(all(net['server'][key] == cfg['databases'][engine][key] for key in ('vmid', 'hostname')),
                    'The database catalogue must select the existing declared database guests')
        # This option extends host-bootstrap only. It must never turn rendering
        # into an implicit reinstallation or input replacement of a live app.
        files['bootstrap.json']['private_bridges'] = dbnets.bridges(database_networks)
    return files


def write_bundle(cfg, output, database_networks=None):
    files = render(cfg, database_networks)  # Validate everything before creating the output.
    output.mkdir(mode=0o700)
    for name, value in files.items():
        path = output / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
    return files


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--database-networks', type=Path,
                        help='Explicit private bridge catalogue for the host bootstrap only')
    args = parser.parse_args()
    write_bundle(read(args.config), args.output,
                 read(args.database_networks) if args.database_networks else None)
