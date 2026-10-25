"""Run over the existing pinned host SSH connection; add one API allowance."""
import ipaddress
import json
import re
import socket
import subprocess
import sys
from urllib.parse import urlparse


def command(args):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if proc.returncode:
        raise RuntimeError('Host command failed: ' + proc.stderr.strip())
    return proc.stdout


def normalized(rows):
    return [{k: v for k, v in row.items() if k not in ('pos', 'digest')} for row in rows]


def same_allowance(row, desired):
    fields = set(desired) - {'comment'}
    return (all(str(row.get(k)) == str(desired[k]) for k in fields)
            and not (set(row) - fields - {'comment', 'pos', 'digest', 'ipversion', 'log'})
            and row.get('ipversion', 4) == 4)


def ensure_rule(request, execute=command, emit=lambda value: None):
    node, vmid = request['node'], request['vmid']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', node) or socket.gethostname().split('.')[0] != node:
        raise RuntimeError('SSH host must be the selected Proxmox node')
    if type(vmid) is not int or not 100 <= vmid <= 999999999 or vmid in (4914, 4915, 4920):
        raise RuntimeError('Select the bootstrap guest, never a protected ID')
    source = ipaddress.IPv4Address(request['guest_address'])
    if source.is_loopback or source.is_link_local or source.is_multicast or source.is_unspecified:
        raise RuntimeError('A usable individual guest IPv4 address is required')
    endpoint = urlparse(request['api_endpoint'])
    if (endpoint.scheme != 'https' or endpoint.port != 8006 or not endpoint.hostname
            or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
            or endpoint.path not in ('', '/')):
        raise RuntimeError('Use the selected host HTTPS API endpoint on port 8006')
    local = {a['local'] for interface in json.loads(execute(['ip', '-j', '-4', 'addr', 'show']))
             for a in interface.get('addr_info', []) if a.get('family') == 'inet'}
    resolved = {row[4][0] for row in socket.getaddrinfo(endpoint.hostname, 8006, socket.AF_INET, socket.SOCK_STREAM)}
    if len(resolved) != 1 or not resolved <= local:
        raise RuntimeError('API hostname must resolve to one local address on the selected host')
    destination = ipaddress.IPv4Address(next(iter(resolved)))
    if (destination == source or destination.is_loopback or destination.is_link_local
            or destination.is_multicast or destination.is_unspecified):
        raise RuntimeError('API destination must be a usable local host address')
    actual = execute(['pct', 'exec', str(vmid), '--', 'hostname', '-I']).split()
    if str(source) not in actual:
        raise RuntimeError('The selected source is not an address of the bootstrap guest')
    api = '/nodes/' + node + '/firewall'
    options = lambda: {k: v for k, v in json.loads(execute([
        'pvesh', 'get', api + '/options', '--output-format', 'json'])).items() if k != 'digest'}
    rules = lambda: json.loads(execute(['pvesh', 'get', api + '/rules', '--output-format', 'json']))
    desired = {'type': 'in', 'action': 'ACCEPT', 'enable': 1,
               'source': str(source) + '/32', 'dest': str(destination) + '/32',
               'proto': 'tcp', 'dport': '8006', 'comment': 'Homelab bootstrap API for deploy ' + str(vmid)}
    before_options, before = options(), rules()
    emit({'phase': 'before', 'rule': desired, 'options': before_options, 'rules': before})
    owned = [row for row in before if row.get('comment') == desired['comment']]
    if owned and (len(owned) != 1 or not same_allowance(owned[0], desired) or owned[0] != before[0]):
        raise RuntimeError('Existing bootstrap API rule conflict; no rewrite or automatic retry')
    changed = not (before and same_allowance(before[0], desired))
    if changed:
        args = ['pvesh', 'create', api + '/rules']
        for key, value in desired.items():
            args += ['--' + key, str(value)]
        # Proxmox validates and prepends a single rule under its own config lock.
        execute(args)
    after = rules()
    remainder = after[1:] if changed else after
    if (not after or not same_allowance(after[0], desired)
            or normalized(remainder) != normalized(before) or options() != before_options):
        raise RuntimeError('Host rule readback did not preserve the existing rules/options; no retry or cleanup')
    return {'phase': 'result', 'status': 'stored', 'changed': changed,
            'rule': desired, 'existing_rules_preserved': True, 'host_options_unchanged': True}


if __name__ == '__main__':
    try:
        result = ensure_rule(json.loads(sys.argv[1]), emit=lambda value: print(json.dumps(value), flush=True))
        print(json.dumps(result), flush=True)
    except (RuntimeError, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'phase': 'result', 'status': 'held', 'reason': str(exc), 'automatic_retry': False}), flush=True)
        raise SystemExit(1)
