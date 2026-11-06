"""Closed desired host TCP allowances and cluster options; no import/recovery path."""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'blueprints'))
import authored_config

HOST = 'proxmox_virtual_environment_firewall_rules.host'
CLUSTER = 'proxmox_virtual_environment_cluster_firewall.cluster'
DEFAULTS = {'enabled': False, 'ebtables': True, 'input_policy': 'DROP',
            'output_policy': 'ACCEPT', 'forward_policy': 'ACCEPT',
            'log_ratelimit': {'enabled': True, 'rate': '1/second', 'burst': 5}}
RULE_FIELDS = {'action', 'comment', 'dest', 'dport', 'enabled', 'iface', 'log',
               'macro', 'pos', 'proto', 'security_group', 'source', 'sport', 'type'}
ERROR = 'Host firewall configuration or ownership differs; preserve private evidence'


def require(ok):
    if not ok:
        raise ValueError(ERROR)


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def address(value, network=False):
    require(type(value) is str)
    try:
        result = ipaddress.IPv4Network(value, strict=True) if network else ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(ERROR) from None
    first = result.network_address if network else result
    require(str(result) == value and not (first.is_multicast or first.is_loopback
            or first.is_link_local or first.is_unspecified or first.is_reserved)
            and (not network or result.prefixlen > 0))
    return value


def validate(c):
    closed(c, ('schema', 'endpoint', 'node', 'host_address', 'allowances', 'cluster'))
    require(c['schema'] == 'homelab-host-firewall-v1' and type(c['endpoint']) is str)
    try:
        e = urlsplit(c['endpoint'])
        require(e.scheme == 'https' and e.hostname and e.port == 8006 and e.username is None
                and e.password is None and '?' not in c['endpoint'] and '#' not in c['endpoint'] and e.path in ('', '/')
                and not any(char.isspace() for char in c['endpoint']))
    except ValueError:
        raise ValueError(ERROR) from None
    require(type(c['node']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', c['node']))
    address(c['host_address'])
    rows = c['allowances']
    require(type(rows) is list and 1 <= len(rows) <= 32)
    tuples, comments = set(), set()
    for row in rows:
        closed(row, ('source', 'port', 'comment'))
        address(row['source'], network=True)
        require(type(row['port']) is int and 1 <= row['port'] <= 65535
                and type(row['comment']) is str and 1 <= len(row['comment']) <= 200
                and row['comment'].strip() == row['comment']
                and all(32 <= ord(char) < 127 for char in row['comment']))
        key = row['source'], row['port']
        require(key not in tuples and row['comment'] not in comments)
        tuples.add(key)
        comments.add(row['comment'])
    validate_cluster(c['cluster'])
    return c


def validate_cluster(cluster):
    closed(cluster, DEFAULTS)
    require(type(cluster['enabled']) is bool and type(cluster['ebtables']) is bool)
    require(cluster['input_policy'] in ('ACCEPT', 'DROP', 'REJECT')
            and cluster['output_policy'] in ('ACCEPT', 'DROP', 'REJECT')
            and cluster['forward_policy'] in ('ACCEPT', 'DROP'))
    log = cluster['log_ratelimit']
    closed(log, ('enabled', 'rate', 'burst'))
    require(type(log['enabled']) is bool and type(log['burst']) is int and 1 <= log['burst'] <= 2147483647
            and type(log['rate']) is str and re.fullmatch(r'[1-9][0-9]{0,8}/(?:second|minute|hour|day)', log['rate']))


def rules(c):
    validate(c)
    return [dict(action='ACCEPT', type='in', proto='tcp', enabled=True, comment=r['comment'],
                 source=r['source'], dest=c['host_address'] + '/32', dport=str(r['port']),
                 iface='', log='', macro='', sport='', security_group='', pos=i)
            for i, r in enumerate(c['allowances'])]


def cluster_values(value):
    """Normalize provider null/omission only; an explicit false remains false."""
    require(type(value) is dict and set(value) <= set(DEFAULTS) | {'id'})
    result = copy.deepcopy(DEFAULTS)
    for key in DEFAULTS:
        if value.get(key) is not None:
            result[key] = copy.deepcopy(value[key])
    log = result['log_ratelimit']
    if log == []:
        result['log_ratelimit'] = copy.deepcopy(DEFAULTS['log_ratelimit'])
    elif type(log) is list:
        require(len(log) == 1)
        result['log_ratelimit'] = log[0]
    validate_cluster(result)
    return result


def native_cluster(value):
    require(type(value) is dict and set(value) <= {'digest', 'enable', 'ebtables', 'policy_in',
            'policy_out', 'policy_forward', 'log_ratelimit'})
    result = copy.deepcopy(DEFAULTS)
    for source, target in [('enable', 'enabled'), ('ebtables', 'ebtables')]:
        if source in value:
            require(type(value[source]) in (bool, int) and value[source] in (0, 1))
            result[target] = bool(value[source])
    for source, target in [('policy_in', 'input_policy'), ('policy_out', 'output_policy'), ('policy_forward', 'forward_policy')]:
        if source in value:
            result[target] = value[source]
    if 'log_ratelimit' in value:
        raw = value['log_ratelimit']
        require(type(raw) is str)
        pairs = [part.split('=', 1) for part in raw.split(',')]
        require(len(pairs) == 3 and all(len(p) == 2 for p in pairs))
        parts = dict(pairs)
        closed(parts, ('enable', 'rate', 'burst'))
        require(parts['enable'] in ('0', '1') and re.fullmatch(r'[1-9][0-9]*', parts['burst']))
        result['log_ratelimit'] = {'enabled': parts['enable'] == '1', 'rate': parts['rate'], 'burst': int(parts['burst'])}
    validate_cluster(result)
    return result


def native_rules(value):
    require(type(value) is list and len(value) <= 32)
    result = []
    for i, row in enumerate(value):
        require(type(row) is dict and set(row) <= (RULE_FIELDS - {'enabled', 'security_group'}) | {'enable', 'digest', 'ipversion'}
                and row.get('pos') == i and type(row['pos']) is int and not row.get('errors')
                and row.get('ipversion', 4) == 4 and type(row.get('enable', 0)) in (int, bool)
                and row.get('enable', 0) in (0, 1))
        record = {k: row.get(k, '') for k in RULE_FIELDS - {'pos', 'enabled'}}
        require(all(type(v) is str for v in record.values()))
        record.update(pos=i, enabled=bool(row.get('enable', 0)))
        result.append(record)
    return result


def no_true(value):
    if type(value) is dict:
        return all(no_true(v) for v in value.values())
    if type(value) is list:
        return all(no_true(v) for v in value)
    return value is False


def plan_rules(value, planned=False):
    require(type(value) is list)
    result = []
    for i, row in enumerate(value):
        closed(row, RULE_FIELDS)
        row = dict(row)
        require(type(row['enabled']) is bool)
        if not planned:
            require(type(row['pos']) is int and row['pos'] == i)
        if planned:
            require(row['pos'] is None or type(row['pos']) is int and row['pos'] == i)
            row['pos'] = i
            for key in ('iface', 'log', 'macro', 'sport', 'security_group'):
                if row[key] is None:
                    row[key] = ''
        require(all(type(row[k]) is str for k in RULE_FIELDS - {'pos', 'enabled'}))
        result.append(row)
    return result


def check_plan(plan, c, before):
    validate(c)
    closed(before, ('rules', 'cluster'))
    validate_cluster(before['cluster'])
    plan_rules(before['rules'])
    require(type(plan) is dict and plan.get('errored') is not True and not plan.get('resource_drift'))
    changes = plan.get('resource_changes')
    require(type(changes) is list and len(changes) == 2 and {r.get('address') for r in changes} == {HOST, CLUSTER})
    configured = plan.get('configuration', {}).get('root_module', {}).get('resources', [])
    require({r.get('address') for r in configured} == {HOST, CLUSTER})
    for resource in changes:
        require(resource.get('mode') == 'managed' and resource.get('provider_name') == 'registry.opentofu.org/bpg/proxmox')
        change = resource['change']
        require(change['actions'] in (['update'], ['no-op']) and not change.get('importing')
                and no_true(change.get('after_unknown', {})) and no_true(change.get('after_sensitive', {})))
        old, new = change['before'], change['after']
        require(type(old) is dict and type(new) is dict and old.get('id') and old['id'] == new.get('id'))
        if resource['address'] == HOST:
            for attrs in (old, new):
                closed(attrs, ('id', 'node_name', 'vm_id', 'container_id', 'rule'))
                require(attrs['node_name'] == c['node'] and attrs['vm_id'] is None and attrs['container_id'] is None)
            require(plan_rules(old['rule']) == before['rules'] and plan_rules(new['rule'], True) == rules(c))
        else:
            require(cluster_values(old) == before['cluster'] and cluster_values(new) == c['cluster'])
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--work', type=Path)
    args = parser.parse_args()
    try:
        require(args.check != (args.work is not None))
        c = validate(authored_config.read(args.config))
        if args.check:
            result = {'status': 'valid'}
        else:
            from host_firewall_run import run
            result = run(c, args.work, args.config)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print('Host firewall held; preserve private state and attempt evidence', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
