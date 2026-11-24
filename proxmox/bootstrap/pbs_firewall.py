"""Pure input and observed-state checks for one CD-owned PBS INPUT boundary."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'blueprints'))
import authored_config
import bootstrap_ssh

ERROR = 'PBS firewall input, interface or ownership differs; preserve deployment evidence'
TABLE = 'homelab_pbs_apps'
ENDPOINT_TABLE = 'homelab_pbs_endpoint'
DROPIN_PATH = '/etc/systemd/system/nftables.service.d/50-homelab-pbs.conf'
DROPIN = '[Service]\n# Keep enforcement on stop; never flush another policy.\nExecStop=\n'
STOCK_CONFIG = '''#!/usr/sbin/nft -f

flush ruleset

table inet filter {
\tchain input {
\t\ttype filter hook input priority filter;
\t}
\tchain forward {
\t\ttype filter hook forward priority filter;
\t}
\tchain output {
\t\ttype filter hook output priority filter;
\t}
}
'''
STOCK_UNIT = '''[Unit]
Description=nftables
Documentation=man:nft(8) http://wiki.nftables.org
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
StandardInput=null
ProtectSystem=full
ProtectHome=true
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
ExecReload=/usr/sbin/nft -f /etc/nftables.conf
ExecStop=/usr/sbin/nft flush ruleset

[Install]
WantedBy=sysinit.target
'''
HEADER = '# HomeLab PBS interface policy v1; configuration: '
ENDPOINT_HEADER = '# HomeLab PBS endpoint policy v2; configuration: '
INTERFACE_SCHEMA = 'homelab-pbs-firewall-v1'
ENDPOINT_SCHEMA = 'homelab-pbs-firewall-v2'
ENROLLED_CLIENTS = 'enrolled-backup-clients'
# The public update and time rules must never act as a route to local or
# reserved address space. Keep this rule family independent of site CIDRs.
NON_PUBLIC_IPV4 = (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/3',
)


def require(ok):
    """Refuse without including configuration or native diagnostics."""
    if not ok:
        raise ValueError(ERROR)


def closed(value, fields):
    """Require every field and reject extensions, nulls and other containers."""
    require(type(value) is dict and set(value) == set(fields))


def address(value):
    """Accept one canonical unicast IPv4 literal, including synthetic examples."""
    require(type(value) is str)
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(ERROR) from None
    require(str(ip) == value and not (ip.is_multicast or ip.is_unspecified
            or ip.is_loopback or ip.is_link_local or ip.is_reserved))
    return value


def ethernet(value):
    """Require a canonical Ethernet identity without a wildcard or alias."""
    require(type(value['interface']) is str and value['interface'] != 'lo'
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', value['interface']))
    mac = value['mac']
    require(type(mac) is str and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)
            and int(mac[:2], 16) & 1 == 0 and mac != '00:00:00:00:00:00')


def peers(value, *, minimum, maximum):
    """Require a bounded, duplicate-free list of individual IPv4 peers."""
    require(type(value) is list and minimum <= len(value) <= maximum)
    checked = [address(peer) for peer in value]
    require(len(set(checked)) == len(checked))
    return checked


def api_sources(values):
    """Validate explicit callers and narrowly declared administrative networks."""
    require(type(values) is list and 1 <= len(values) <= 16)
    sources = []
    for value in values:
        require(type(value) is str)
        try:
            if '/' in value:
                network = ipaddress.IPv4Network(value)
                require(24 <= network.prefixlen < 32 and str(network) == value)
                address(str(network.network_address))
            else:
                network = ipaddress.IPv4Network(address(value))
        except ValueError:
            raise ValueError(ERROR) from None
        require(not any(network.overlaps(source) for source in sources))
        sources.append(network)
    return sources


def validate(c):
    """Validate the closed authored API without mutation, target or credential I/O."""
    require(type(c) is dict and c.get('schema') in (INTERFACE_SCHEMA, ENDPOINT_SCHEMA))
    endpoint = c['schema'] == ENDPOINT_SCHEMA
    closed(c, ('schema', 'target', 'apps', 'management', 'storage', 'egress')
           if endpoint else ('schema', 'target', 'apps'))
    closed(c['target'], ('address', 'hostname'))
    closed(c['apps'], ('interface', 'mac', 'address', 'proxy'))
    target, apps = c['target'], c['apps']
    require(type(target['hostname']) is str and re.fullmatch(
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', target['hostname']))
    ethernet(apps)
    require(len({address(target['address']), address(apps['address']), address(apps['proxy'])}) == 3)
    if endpoint:
        validate_endpoint(c)
    return c


def validate_endpoint(c):
    management, storage, egress = (c[k] for k in ('management', 'storage', 'egress'))
    closed(management, ('interface', 'mac', 'gateway', 'ssh_clients', 'api_clients'))
    closed(storage, ('interface', 'mac', 'address', 'nfs_server', 'api_clients'))
    closed(egress, ('dns_servers', 'time_servers', 'public_web', 'public_ntp'))
    for plane in (management, storage):
        ethernet(plane)
    for identity in ('interface', 'mac'):
        require(len({c['apps'][identity], management[identity], storage[identity]}) == 3)
    own = {c['target']['address'], c['apps']['address'], address(storage['address'])}
    require(len(own) == 3)
    permitted = [
        address(management['gateway']), address(storage['nfs_server']), c['apps']['proxy'],
        *peers(management['ssh_clients'], minimum=1, maximum=16),
        *peers(storage['api_clients'], minimum=1, maximum=64),
        *peers(egress['dns_servers'], minimum=1, maximum=8),
        *peers(egress['time_servers'], minimum=0, maximum=8),
    ]
    require(not own.intersection(permitted))
    require(not any(ipaddress.IPv4Address(local) in source
                    for source in api_sources(management['api_clients']) for local in own))
    require(storage['nfs_server'] not in storage['api_clients'])
    require(sum(len(plane['api_clients']) for plane in (management, storage))
            + len(management['ssh_clients']) <= 80)
    require(type(egress['public_web']) is bool and type(egress['public_ntp']) is bool)
    require(egress['public_ntp'] or egress['time_servers'])


def endpoint_rules(c):
    """Compile the text and exact observed expressions from one rule definition."""
    def match(text, left, value, op='=='):
        return text, {'match': {'op': op, 'left': left, 'right': value}}

    def interface(side, name):
        key = side + 'ifname'
        return match(f'{key} "{name}"', {'meta': {'key': key}}, name)

    def service(protocol, field, value):
        literal = value
        if protocol == 'ip' and '/' in value:
            network = ipaddress.IPv4Network(value)
            literal = {'prefix': {'addr': str(network.network_address), 'len': network.prefixlen}}
        return match(f'{protocol} {field} {value}',
                     {'payload': {'protocol': protocol, 'field': field}}, literal)

    def states(*values):
        text = 'ct state { ' + ', '.join(values) + ' }'
        return match(text, {'ct': {'key': 'state'}}, {'set': sorted(values)})

    def public():
        return match('ip daddr != { ' + ', '.join(NON_PUBLIC_IPV4) + ' }',
                     {'payload': {'protocol': 'ip', 'field': 'daddr'}},
                     {'set': [{'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}
                              for net in map(ipaddress.IPv4Network, NON_PUBLIC_IPV4)]}, '!=')

    def rule(terms):
        parts = (*terms, ('accept', {'accept': None}))
        return ' '.join(part[0] for part in parts), [part[1] for part in parts]

    family = match('meta nfproto ipv4', {'meta': {'key': 'nfproto'}}, 'ipv4')
    reply = match('ct direction reply', {'ct': {'key': 'direction'}}, 'reply')
    requests = states('new', 'established')
    replies = states('established', 'related')
    apps, management, storage, egress = (c[k] for k in ('apps', 'management', 'storage', 'egress'))
    target = c['target']['address']
    incoming = [rule((interface('i', 'lo'),)), rule((family, reply, replies))]
    outgoing = [rule((interface('o', 'lo'),)), rule((family, reply, replies))]
    for plane, local, callers, port in (
        (apps, apps['address'], (apps['proxy'],), 8007),
        (management, target, management['ssh_clients'], 22),
        (management, target, management['api_clients'], 8007),
        (storage, storage['address'], storage['api_clients'], 8007),
    ):
        incoming.extend(rule((interface('i', plane['interface']), service('ip', 'saddr', peer),
                              service('ip', 'daddr', local), service('tcp', 'dport', port), requests))
                        for peer in callers)
    for plane, local, peers_for_service, protocol, port in (
        (storage, storage['address'], (storage['nfs_server'],), 'tcp', 2049),
        (management, target, egress['dns_servers'], 'udp', 53),
        (management, target, egress['dns_servers'], 'tcp', 53),
        (management, target, egress['time_servers'], 'udp', 123),
    ):
        outgoing.extend(rule((interface('o', plane['interface']), service('ip', 'saddr', local),
                              service('ip', 'daddr', peer), service(protocol, 'dport', port), requests))
                        for peer in peers_for_service)
    for enabled, protocol, ports in ((egress['public_web'], 'tcp', (80, 443)),
                                     (egress['public_ntp'], 'udp', (123,))):
        if enabled:
            outgoing.extend(rule((interface('o', management['interface']), service('ip', 'saddr', target),
                                  public(), service(protocol, 'dport', port), requests))
                            for port in ports)
    return {'input': incoming, 'forward': (), 'output': outgoing}


def render(c):
    """Build one atomic own-table replacement, with no global flush or includes."""
    validate(c)
    if c['schema'] == ENDPOINT_SCHEMA:
        lines = [ENDPOINT_HEADER + json.dumps(c, sort_keys=True, separators=(',', ':')),
                 f'add table inet {ENDPOINT_TABLE}', f'delete table inet {ENDPOINT_TABLE}',
                 f'table inet {ENDPOINT_TABLE} {{']
        for chain, rows in endpoint_rules(c).items():
            lines += [f'    chain {chain} {{', f'        type filter hook {chain} priority 0; policy drop;']
            lines.extend(f'        {text}' for text, _ in rows)
            lines.append('    }')
        return '\n'.join(lines + ['}']) + '\n'
    a = c['apps']
    lines = [HEADER + json.dumps(c, sort_keys=True, separators=(',', ':')),
             f'add table inet {TABLE}', f'delete table inet {TABLE}',
             f'table inet {TABLE} {{', '    chain input {',
             '        type filter hook input priority 0; policy accept;',
             f'        iifname "{a["interface"]}" meta nfproto ipv6 drop',
             f'        iifname "{a["interface"]}" ct state invalid drop',
             f'        iifname "{a["interface"]}" meta nfproto ipv4 ct direction reply ct state {{ established, related }} accept',
             f'        iifname "{a["interface"]}" ip saddr {a["proxy"]} ip daddr {a["address"]} tcp dport 8007 ct state {{ new, established }} accept',
             f'        iifname "{a["interface"]}" drop', '    }', '}']
    return '\n'.join(lines) + '\n'


def previous(text):
    """Recognize an exact generated file; a marker alone never establishes ownership."""
    require(type(text) is str and text.startswith((HEADER, ENDPOINT_HEADER)))
    header = ENDPOINT_HEADER if text.startswith(ENDPOINT_HEADER) else HEADER
    try:
        c = json.loads(text.splitlines()[0][len(header):])
    except (ValueError, IndexError):
        raise ValueError(ERROR) from None
    require(render(c) == text)
    return c


def rules(c):
    """Expected numeric nftables 1.1.3 JSON, excluding only assigned object handles."""
    validate(c)
    if c['schema'] == ENDPOINT_SCHEMA:
        chains = endpoint_rules(c)
        result = [{'table': {'family': 'inet', 'name': ENDPOINT_TABLE}}]
        result.extend({'chain': {'family': 'inet', 'table': ENDPOINT_TABLE, 'name': chain, 'type': 'filter',
                                 'hook': chain, 'prio': 0, 'policy': 'drop'}} for chain in chains)
        result.extend({'rule': {'family': 'inet', 'table': ENDPOINT_TABLE, 'chain': chain, 'expr': expr}}
                      for chain, rows in chains.items() for _, expr in rows)
        return result
    def match(left, right, op='=='):
        return {'match': {'op': op, 'left': left, 'right': right}}
    def meta(key, value):
        return match({'meta': {'key': key}}, value)
    def ct(key, value, op='=='):
        return match({'ct': {'key': key}}, value, op)
    def payload(protocol, field, value):
        return match({'payload': {'protocol': protocol, 'field': field}}, value)
    a = c['apps']
    prefix = meta('iifname', a['interface'])
    expressions = [
        [prefix, meta('nfproto', 'ipv6'), {'drop': None}],
        [prefix, ct('state', 'invalid', 'in'), {'drop': None}],
        [prefix, meta('nfproto', 'ipv4'), ct('direction', 'reply'),
         ct('state', {'set': ['established', 'related']}), {'accept': None}],
        [prefix, payload('ip', 'saddr', a['proxy']), payload('ip', 'daddr', a['address']),
         payload('tcp', 'dport', 8007), ct('state', {'set': ['established', 'new']}), {'accept': None}],
        [prefix, {'drop': None}]]
    return [{'table': {'family': 'inet', 'name': TABLE}},
            {'chain': {'family': 'inet', 'table': TABLE, 'name': 'input', 'type': 'filter',
                       'hook': 'input', 'prio': 0, 'policy': 'accept'}}] + [
        {'rule': {'family': 'inet', 'table': TABLE, 'chain': 'input', 'expr': expr}}
        for expr in expressions]


def kernel(value):
    """Preserve every observed expression/object; ignore only metadata and handles."""
    closed(value, ('nftables',))
    require(type(value['nftables']) is list)
    rows = []
    for row in value['nftables']:
        require(type(row) is dict and len(row) == 1)
        key, body = next(iter(row.items()))
        if key == 'metainfo':
            require(type(body) is dict and body.get('version') == '1.1.3')
        else:
            require(key in ('table', 'chain', 'rule') and type(body) is dict)
            rows.append({key: {k: v for k, v in body.items() if k != 'handle'}})
    return rows


def regular(item, modes):
    """Check fixed root-owned files without following links or accepting hard links."""
    require(type(item) is dict and item.get('isreg') is True and item.get('islnk') is False
            and item.get('uid') == 0 and item.get('gid') == 0 and item.get('nlink') == 1
            and item.get('mode') in modes)


def storage_servers(value):
    """Select literal NFS server addresses for ordinary read-only route queries."""
    closed(value, ('filesystems',))
    require(type(value['filesystems']) is list)
    result = []
    for row in value['filesystems']:
        closed(row, ('source',))
        source = row['source']
        require(type(source) is str)
        host, separator, path = (source.partition(']:') if source.startswith('[')
                                 else source.partition(':'))
        host = host.removeprefix('[')
        try:
            require(separator and path.startswith('/') and str(ipaddress.ip_address(host)) == host)
        except ValueError:
            raise ValueError(ERROR) from None
        if host not in result:
            result.append(host)
    return result


def endpoint_network(c, f, links):
    """Require live Management and Storage plus a positively identified Apps adapter."""
    management, storage = c['management'], c['storage']
    # The shared Apps check allows its identified adapter to remain disconnected
    # and unaddressed while the host receives its first managed firewall.
    for plane, local in ((management, c['target']['address']), (storage, storage['address'])):
        selected = [row for row in links if row.get('ifname') == plane['interface']]
        require(len(selected) == 1 and selected[0].get('address') == plane['mac']
                and selected[0].get('link_type') == 'ether' and not selected[0].get('master')
                and 'SLAVE' not in selected[0].get('flags', [])
                and sum(row.get('address') == plane['mac'] for row in links) == 1)
        addresses = selected[0].get('addr_info', [])
        require([item.get('local') for item in addresses if item.get('family') == 'inet'] == [local]
                and all(item.get('family') == 'inet' or (item.get('family') == 'inet6'
                        and item.get('scope') == 'link') for item in addresses))

    defaults = [row for row in f['routes'] if row.get('dst') in ('default', '0.0.0.0/0', '::/0')]
    require(len(defaults) == 1 and defaults[0].get('dev') == management['interface']
            and defaults[0].get('gateway') == management['gateway'])
    routes = f['storage_routes']
    require(len(routes) == 1 and routes[0][0].get('dst') == storage['nfs_server']
            and routes[0][0].get('dev') == storage['interface']
            and routes[0][0].get('prefsrc') == storage['address']
            and 'gateway' not in routes[0][0])
    require(f.get('forwarding') == ['0', '0'])
    connection = f.get('ssh_connection')
    require(type(connection) is str)
    fields = connection.split()
    require(len(fields) == 4 and fields[0] in management['ssh_clients']
            and fields[2:] == [c['target']['address'], '22']
            and fields[1].isdigit() and 1 <= int(fields[1]) <= 65535)


def network(c, f):
    """Bind the observed Ethernet NIC and exclude existing management/storage/default paths."""
    a, target = c['apps'], c['target']
    require(f['hostname'] == target['hostname'] and f['uid'] == 0
            and f['distribution'] == 'Debian' and f['release'] == '13'
            and f['nft_version'] == '1.1.3-1' and f['pbs_installed'] is True)
    links = f['addresses']
    require(type(links) is list)
    selected = [r for r in links if r.get('ifname') == a['interface']]
    require(len(selected) == 1 and selected[0].get('address') == a['mac']
            and selected[0].get('link_type') == 'ether'
            and not selected[0].get('master') and 'SLAVE' not in selected[0].get('flags', [])
            and sum(r.get('address') == a['mac'] for r in links) == 1)
    management = [r for r in links if any(v.get('local') == target['address'] for v in r.get('addr_info', []))]
    require(len(management) == 1 and management[0]['ifname'] != a['interface'])
    for v in selected[0].get('addr_info', []):
        require((v.get('family') == 'inet' and v.get('local') == a['address'])
                or (v.get('family') == 'inet6' and v.get('scope') == 'link'))
    require(type(f['routes']) is list)
    for route in f['routes']:
        if route.get('dst') in ('default', '0.0.0.0/0', '::/0'):
            require(route.get('dev') and route['dev'] != a['interface']
                    and 'nexthops' not in route and 'nhid' not in route)
    require(type(f['storage_routes']) is list and all(type(r) is list and len(r) == 1
            and r[0].get('dev') and r[0]['dev'] != a['interface'] for r in f['storage_routes']))
    if c['schema'] == ENDPOINT_SCHEMA:
        endpoint_network(c, f, links)
    return [[{'ifname': r['ifname'], 'address': r.get('address'),
              'addr_info': [{k: value for k, value in v.items()
                            if k not in ('valid_life_time', 'preferred_life_time')}
                           for v in r.get('addr_info', [])]} for r in links],
            [{k: value for k, value in route.items() if k != 'expires'} for route in f['routes']]]


def trust(c, options):
    """Retain PBS source validation and share the unchanged SSH custody check."""
    validate(c)
    try:
        bootstrap_ssh.trust(c['target'], options)
    except ValueError:
        raise ValueError(ERROR) from None

def inspect(c, f, final=False):
    """Admit pristine first use or exact owned repeat; validate final actual readback."""
    validate(c)
    net = network(c, f)
    regular(f['unit_stat'], ('0644',))
    require(f['unit'] == STOCK_UNIT and f['fragment'] == '/usr/lib/systemd/system/nftables.service'
            and f['reload_needed'] == 'no')
    regular(f['config_stat'], ('0600', '0644', '0755'))
    active = kernel(f['ruleset'])
    if f['config'].startswith((HEADER, ENDPOINT_HEADER)):
        old = previous(f['config'])
        require(old['schema'] == c['schema']
                and old['target'] == c['target'] and {k: v for k, v in old['apps'].items() if k != 'proxy'}
                == {k: v for k, v in c['apps'].items() if k != 'proxy'})
        if old['schema'] == ENDPOINT_SCHEMA:
            require(all(
                old[plane][key] == c[plane][key]
                for plane, keys in (('management', ('interface', 'mac', 'gateway')),
                                    ('storage', ('interface', 'mac', 'address', 'nfs_server')))
                for key in keys))
        regular(f['dropin_stat'], ('0644',))
        require(f['config_stat']['mode'] == '0600' and f['dropin'] == DROPIN
                and f['dropins'] == DROPIN_PATH and f['active'] == 'active'
                and f['enabled'] == 'enabled' and active == rules(old))
    else:
        require(not final and f['config'] == STOCK_CONFIG and not active
                and f['dropin_stat'] == {'exists': False} and f['dropins'] == ''
                and f['active'] == 'inactive' and f['enabled'] == 'disabled')
    if final:
        require(f['config'] == render(c) and active == rules(c))
    desired = render(c)
    return {'policy': desired, 'dropin': DROPIN, 'changed': f['config'] != desired,
            'active': f['active'], 'network': net,
            'baseline': 'clean' if f['config'] == STOCK_CONFIG else 'owned',
            'previous_sha256': hashlib.sha256(f['config'].encode()).hexdigest(),
            'desired_sha256': hashlib.sha256(desired.encode()).hexdigest()}


def inspect_trial(c, f, baseline):
    """Verify a trial installed in the kernel while the trusted boot file stays in place."""
    require(c['schema'] == ENDPOINT_SCHEMA
            and hashlib.sha256(f['config'].encode()).hexdigest() == baseline['previous_sha256']
            and kernel(f['ruleset']) == rules(c))
    prior_rules = [] if f['config'] == STOCK_CONFIG else rules(previous(f['config']))
    inspected = inspect(c, {**f, 'ruleset': {'nftables': prior_rules}})
    require(inspected['network'] == baseline['network'] and inspected['baseline'] == baseline['baseline'])


def enrolled_clients(resolved, server):
    """Use the scheduled jobs' bound Storage sources, with no second address list."""
    schedule = resolved['backup']['group']['group']
    members = set(schedule['members'])
    clients = {}
    for guest in resolved['guests'].values():
        if not guest.get('backup'):
            continue
        job = guest['backup']['job']
        owner = job.get('group') or {}
        if owner.get('name') != schedule['name'] or owner.get('member') not in members:
            continue
        member = owner['member']
        destination = job['destination']
        require(member not in clients and destination['server'] == server
                and destination['port'] == 8007 and destination['backup_id'] == member)
        source = address(job['transport']['address'])
        matches = [device for name, device in guest['interfaces'].items()
                   if guest['interface_addresses'].get(name) == source]
        require(len(matches) == 1 and matches[0]['address']['mode'] == 'static'
                and job['transport']['device'] == 'eth' + str(matches[0]['slot']))
        clients[member] = source
    require(set(clients) == members)
    selected = sorted(clients.values(), key=ipaddress.IPv4Address)
    return peers(selected, minimum=1, maximum=64)


def load_policy(path, site_root=None, stack_root=None):
    authored = authored_config.read(path)
    storage = authored.get('storage') if type(authored) is dict else None
    management = authored.get('management') if type(authored) is dict else None
    management_sources = management.get('api_clients') if type(management) is dict else None
    uses_enrolment = (type(storage) is dict and storage.get('api_clients') == ENROLLED_CLIENTS)
    uses_address_groups = type(management_sources) is list and any(
        type(peer) is dict for peer in management_sources)
    if not (uses_enrolment or uses_address_groups):
        require((site_root is None) == (stack_root is None))
        return validate(authored)
    require(authored.get('schema') == ENDPOINT_SCHEMA and site_root is not None and stack_root is not None)
    import compile as site_compiler
    try:
        plan = site_compiler.resolve_plan(Path(stack_root).resolve(),
                                          site_compiler.site_path(Path(site_root).resolve()), [], admit=True)
        if uses_enrolment:
            clients = enrolled_clients(plan.resolved, address(storage['address']))
            authored = {**authored, 'storage': {**storage, 'api_clients': clients}}
        if uses_address_groups:
            authored = {**authored, 'management': {
                **management, 'api_clients': resolve_api_sources(plan.resolved, management_sources)}}
    except (KeyError, TypeError, ValueError):
        raise ValueError(ERROR) from None
    return validate(authored)


def resolve_api_sources(resolved, declarations):
    """Resolve named site groups without copying their members into the PBS binding."""
    members = []
    for item in declarations:
        if type(item) is dict:
            closed(item, ('address_group',))
            group = resolved['address_groups'][item['address_group']]
            for member in group:
                network = ipaddress.IPv4Network(member)
                members.append(str(network.network_address) if network.prefixlen == 32 else str(network))
        else:
            members.append(item)
    return members


def main(argv=None):
    """Only pure explicit-file check/emit are public CLI operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--site-root')
    parser.add_argument('--stack-root')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--emit', action='store_true')
    args = parser.parse_args(argv)
    try:
        c = load_policy(args.config, args.site_root, args.stack_root)
    except ValueError:
        parser.exit(1, ERROR + '\n')
    print(json.dumps(c, sort_keys=True) if args.emit else 'PBS firewall configuration accepted')


if __name__ == '__main__':
    main()
