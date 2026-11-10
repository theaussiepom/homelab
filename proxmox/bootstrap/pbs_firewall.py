"""Pure input and observed-state checks for one CD-owned PBS INPUT boundary."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'blueprints'))
import authored_config

ERROR = 'PBS firewall input, interface or ownership differs; preserve deployment evidence'
TABLE = 'homelab_pbs_apps'
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


def validate(c):
    """Validate the closed authored API without mutation, target or credential I/O."""
    closed(c, ('schema', 'target', 'apps'))
    require(c['schema'] == 'homelab-pbs-firewall-v1')
    closed(c['target'], ('address', 'hostname'))
    closed(c['apps'], ('interface', 'mac', 'address', 'proxy'))
    target, apps = c['target'], c['apps']
    require(type(target['hostname']) is str and re.fullmatch(
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', target['hostname']))
    require(type(apps['interface']) is str and apps['interface'] != 'lo'
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', apps['interface']))
    require(type(apps['mac']) is str and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', apps['mac'])
            and int(apps['mac'][:2], 16) & 1 == 0 and apps['mac'] != '00:00:00:00:00:00')
    require(len({address(target['address']), address(apps['address']), address(apps['proxy'])}) == 3)
    return c


def render(c):
    """Build one atomic own-table replacement, with no global flush or includes."""
    validate(c)
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
    require(type(text) is str and text.startswith(HEADER))
    try:
        c = json.loads(text.splitlines()[0][len(HEADER):])
    except (ValueError, IndexError):
        raise ValueError(ERROR) from None
    require(render(c) == text)
    return c


def rules(c):
    """Expected numeric nftables 1.1.3 JSON, excluding only assigned object handles."""
    validate(c)
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
    return [[{'ifname': r['ifname'], 'address': r.get('address'), 'addr_info': r.get('addr_info', [])}
             for r in links], f['routes']]


def trust(c, options):
    """Check actual SSH option resolution and explicit files before any target contact."""
    validate(c)
    closed(options, ('host_key_checking', 'ssh_executable', 'ssh_extra_args', 'sftp_extra_args',
                     'scp_extra_args', 'ssh_args', 'ssh_common_args', 'private_key_file', 'inline_key_absent', 'password_absent'))
    require(options['host_key_checking'] is True
            and options['inline_key_absent'] is True and options['password_absent'] is True
            and options['ssh_executable'] in ('ssh', '/usr/bin/ssh')
            and not options['ssh_extra_args'] and not options['sftp_extra_args']
            and not options['scp_extra_args'])
    try:
        tokens = shlex.split(options['ssh_args']) + shlex.split(options['ssh_common_args'])
        settings = {}
        config_disabled = False
        while tokens:
            flag = tokens.pop(0)
            if flag == '-C':
                continue
            require(flag in ('-o', '-F') and tokens)
            value = tokens.pop(0)
            if flag == '-F':
                require(value == '/dev/null')
                config_disabled = True
            else:
                name, separator, selected = value.partition('=')
                require(separator and name in ('StrictHostKeyChecking', 'ControlMaster', 'BatchMode',
                        'IdentitiesOnly', 'UserKnownHostsFile', 'GlobalKnownHostsFile', 'VerifyHostKeyDNS', 'UpdateHostKeys')
                        and settings.get(name, selected) == selected)
                settings[name] = selected
        require(config_disabled and settings.get('StrictHostKeyChecking') == 'yes'
                and settings.get('ControlMaster') == 'no' and settings.get('BatchMode') == 'yes'
                and settings.get('IdentitiesOnly') == 'yes'
                and settings.get('GlobalKnownHostsFile') == '/dev/null'
                and settings.get('VerifyHostKeyDNS') == 'no' and settings.get('UpdateHostKeys') == 'no')
        key, known = Path(options['private_key_file']), Path(settings['UserKnownHostsFile'])
        require(key.is_absolute() and known.is_absolute())
        k, before = key.lstat(), known.lstat()
        require(stat.S_ISREG(k.st_mode) and k.st_uid == os.geteuid() and k.st_nlink == 1
                and stat.S_IMODE(k.st_mode) == 0o600
                and stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in (0o600, 0o644)
                and before.st_size <= 65536)
        with os.fdopen(os.open(known, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(65537)
            require(authored_config._identity(opened) == authored_config._identity(before)
                    and authored_config._identity(os.fstat(stream.fileno())) == authored_config._identity(before)
                    and authored_config._identity(known.lstat()) == authored_config._identity(before)
                    and len(raw) <= 65536)
        rows = [line.split() for line in raw.decode('ascii').splitlines() if line and not line.startswith('#')]
        require(rows and all(len(row) == 3 and c['target']['address'] in row[0].split(',')
                and all(host in (c['target']['address'], c['target']['hostname']) for host in row[0].split(','))
                and row[1] in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa')
                and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', row[2]) for row in rows))
    except (OSError, ValueError, KeyError, TypeError):
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
    if f['config'].startswith(HEADER):
        old = previous(f['config'])
        require(old['target'] == c['target'] and {k: v for k, v in old['apps'].items() if k != 'proxy'}
                == {k: v for k, v in c['apps'].items() if k != 'proxy'})
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
    return {'policy': render(c), 'dropin': DROPIN, 'changed': f['config'] != render(c),
            'active': f['active'], 'network': net}


def main(argv=None):
    """Only pure explicit-file check/emit are public CLI operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--emit', action='store_true')
    args = parser.parse_args(argv)
    try:
        c = validate(authored_config.read(args.config))
    except ValueError:
        parser.exit(1, ERROR + '\n')
    print(json.dumps(c, sort_keys=True) if args.emit else 'PBS firewall configuration accepted')


if __name__ == '__main__':
    main()
