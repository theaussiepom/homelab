"""Admit one additive IPv4 web-listener boundary without owning other traffic."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'blueprints'))
import authored_config
import bootstrap_ssh

ERROR = 'Device web firewall input, target or existing ownership differs; preserve the attempt'
TABLE = 'homelab_device_web'
DIRECTORY = '/etc/homelab-device-web'
CONFIG = DIRECTORY + '/web.nft'
UNIT_PATH = '/etc/systemd/system/homelab-device-web-firewall.service'
HEADER = '# HomeLab device web boundary v1: '
UNIT = '''[Unit]
Description=HomeLab device web listener boundary
After=nftables.service
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/homelab-device-web/web.nft
ExecReload=/usr/sbin/nft -f /etc/homelab-device-web/web.nft
TimeoutStartSec=15

[Install]
WantedBy=multi-user.target
'''


def require(ok):
    """Reject observations and source without echoing private input."""
    if not ok:
        raise ValueError(ERROR)


def closed(value, fields):
    """Reject omitted and unknown fields in the authored capability."""
    require(type(value) is dict and set(value) == set(fields))


def address(value):
    """Accept only one canonical unicast IPv4 literal."""
    require(type(value) is str)
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(ERROR) from None
    require(str(ip) == value and not (ip.is_unspecified or ip.is_loopback
            or ip.is_link_local or ip.is_multicast or ip.is_reserved))
    return value


def validate(c):
    """Validate an explicit management identity and one web listener."""
    closed(c, ('schema', 'target', 'web'))
    require(c['schema'] == 'homelab-device-web-firewall-v1')
    closed(c['target'], ('address', 'hostname', 'user'))
    closed(c['web'], ('interface', 'mac', 'address', 'proxy', 'port'))
    target, web = c['target'], c['web']
    require(type(target['hostname']) is str and re.fullmatch(
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', target['hostname']))
    require(type(target['user']) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', target['user']))
    require(type(web['interface']) is str and web['interface'] != 'lo'
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', web['interface']))
    require(type(web['mac']) is str and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', web['mac'])
            and int(web['mac'][:2], 16) & 1 == 0 and web['mac'] != '00:00:00:00:00:00')
    require(type(web['port']) is int and 1 <= web['port'] <= 65535)
    require(len({address(target['address']), address(web['address']), address(web['proxy'])}) == 3)
    return c


def render(c):
    """Replace only the owned table in one atomic batch; never flush rulesets."""
    validate(c)
    w = c['web']
    selected = f'ip daddr {w["address"]} tcp dport {w["port"]}'
    return '\n'.join([
        HEADER + json.dumps(c, sort_keys=True, separators=(',', ':')),
        f'add table inet {TABLE}', f'delete table inet {TABLE}',
        f'table inet {TABLE} {{', '    chain input {',
        '        type filter hook input priority -10; policy accept;',
        f'        iifname "{w["interface"]}" ip saddr {w["proxy"]} {selected} accept',
        f'        iifname "lo" {selected} accept',
        f'        {selected} drop', '    }', '}', ''])


def previous(text):
    """Accept an exact previously generated document, never a marker alone."""
    require(type(text) is str and text.startswith(HEADER))
    try:
        c = json.loads(text.splitlines()[0][len(HEADER):])
    except (ValueError, IndexError):
        raise ValueError(ERROR) from None
    require(render(c) == text)
    return c


def rules(c):
    """Describe exactly the owned numeric nftables table, excluding handles."""
    validate(c)
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    def meta(key, right):
        return match({'meta': {'key': key}}, right)
    def payload(protocol, field, right):
        return match({'payload': {'protocol': protocol, 'field': field}}, right)
    w = c['web']
    selected = [payload('ip', 'daddr', w['address']), payload('tcp', 'dport', w['port'])]
    expressions = [
        [meta('iifname', w['interface']), payload('ip', 'saddr', w['proxy']), *selected, {'accept': None}],
        [meta('iifname', 'lo'), *selected, {'accept': None}],
        [*selected, {'drop': None}]]
    return [{'table': {'family': 'inet', 'name': TABLE}},
            {'chain': {'family': 'inet', 'table': TABLE, 'name': 'input',
                       'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}}] + [
        {'rule': {'family': 'inet', 'table': TABLE, 'chain': 'input', 'expr': expr}}
        for expr in expressions]


def kernel(value):
    """Keep all observed policy data except native handles and metadata."""
    closed(value, ('nftables',))
    require(type(value['nftables']) is list)
    result = []
    for row in value['nftables']:
        require(type(row) is dict and len(row) == 1)
        key, body = next(iter(row.items()))
        require(type(body) is dict)
        if key != 'metainfo':
            require(key in ('table', 'chain', 'rule'))
            result.append({key: {k: v for k, v in body.items() if k != 'handle'}})
    return result


def regular(item, mode):
    """Require the exact root-owned regular-file metadata before reading it."""
    require(type(item) is dict and item.get('isreg') is True and item.get('islnk') is False
            and item.get('uid') == 0 and item.get('gid') == 0 and item.get('nlink') == 1
            and item.get('mode') == mode)


def trust(c, options):
    """Reuse the same precontact custody validation as the PBS capability."""
    validate(c)
    try:
        bootstrap_ssh.trust({k: c['target'][k] for k in ('address', 'hostname')}, options)
    except ValueError:
        raise ValueError(ERROR) from None


def inspect(c, f, final=False):
    """Admit an unused namespace or an exact owned repeat and actual readback."""
    validate(c)
    closed(f, ('uid', 'hostname', 'addresses', 'parent_stat', 'config_stat', 'config',
               'unit_stat', 'unit', 'ruleset', 'fragment', 'dropins', 'active', 'enabled'))
    require(type(f['uid']) is int and f['uid'] == 0 and f['hostname'] == c['target']['hostname']
            and type(f['addresses']) is list)
    require(all(type(r) is dict and type(r.get('addr_info', [])) is list
            and all(type(a) is dict for a in r.get('addr_info', [])) for r in f['addresses']))
    w = c['web']
    links = [r for r in f['addresses'] if r.get('ifname') == w['interface']]
    require(len(links) == 1 and links[0].get('address') == w['mac']
            and not links[0].get('master') and 'SLAVE' not in links[0].get('flags', []))
    addresses = [(r.get('ifname'), a.get('local')) for r in f['addresses']
                 for a in r.get('addr_info', []) if a.get('family') == 'inet']
    require(addresses.count((w['interface'], w['address'])) == 1
            and sum(a == w['address'] for _, a in addresses) == 1
            and sum(a == c['target']['address'] and name != w['interface'] for name, a in addresses) == 1)
    parent = f['parent_stat']
    require(type(parent) is dict and type(f['config_stat']) is dict and type(f['unit_stat']) is dict)
    require(parent == {'exists': False} or (parent.get('isdir') is True
            and parent.get('islnk') is False and parent.get('uid') == 0
            and parent.get('gid') == 0 and parent.get('mode') == '0755'))
    active = kernel(f['ruleset'])
    require(f['dropins'] == '')
    if f['config_stat'] == {'exists': False}:
        require(not final and f['unit_stat'] == {'exists': False} and f['config'] is None
                and f['unit'] is None and not active and f['fragment'] == ''
                and f['active'] == 'inactive' and f['enabled'] in ('', 'not-found'))
    else:
        regular(f['config_stat'], '0600')
        regular(f['unit_stat'], '0644')
        old = previous(f['config'])
        require(old['target'] == c['target'] and {k: v for k, v in old['web'].items() if k != 'proxy'}
                == {k: v for k, v in w.items() if k != 'proxy'})
        require(f['unit'] == UNIT and f['fragment'] == UNIT_PATH
                and f['active'] == 'active' and f['enabled'] == 'enabled' and active == rules(old))
    if final:
        require(f['config'] == render(c) and active == rules(c))
    return {'policy': render(c), 'unit': UNIT, 'changed': f['config'] != render(c)}


def main(argv=None):
    """Validate one authored input; optionally admit supplied observation data."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--emit', action='store_true')
    mode.add_argument('--observe', action='store_true')
    parser.add_argument('--final', action='store_true')
    args = parser.parse_args(argv)
    try:
        require(not args.final or args.observe)
        c = validate(authored_config.read(args.config))
        result = inspect(c, json.load(sys.stdin), final=args.final) if args.observe else c
    except (ValueError, KeyError, TypeError):
        parser.exit(1, ERROR + '\n')
    print('Device web firewall configuration accepted' if args.check else json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
