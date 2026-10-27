"""Keep replies from the HTTPS frontend on its own gateway, inside one guest.

Only the reserved table/rule10040 is managed. No main-route, forwarding,
firewall, NAT or host setting is changed; unexpected policy is a hold.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TABLE = 10040


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate(value):
    require(isinstance(value, dict) and set(value) == {'address', 'gateway', 'mac'}, 'Use the closed ingress routing settings')
    require(all(isinstance(item, str) for item in value.values()), 'Routing settings must be literal strings')
    interface = ipaddress.IPv4Interface(value['address'])
    gateway = ipaddress.IPv4Address(value['gateway'])
    network = interface.network
    require(interface.ip.is_private and not interface.ip.is_loopback and not interface.ip.is_link_local
            and network.prefixlen == 24 and gateway in network
            and gateway not in (network.network_address, network.broadcast_address, interface.ip)
            and interface.ip not in (network.network_address, network.broadcast_address), 'Use the selected frontend subnet and gateway')
    require(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value['mac']) is not None
            and int(value['mac'][:2], 16) & 3 == 2, 'Use the selected locally administered frontend MAC')
    return str(interface.ip), str(network), str(gateway), value['mac']


def command(argv):
    result = subprocess.run(['ip', '-4', *argv], capture_output=True, text=True, check=False, timeout=10)
    require(result.returncode == 0, 'Ingress routing command failed; preserve the deployment hold')
    return result.stdout


def state(settings):
    address, network, gateway, mac = validate(settings)
    links = json.loads(command(['-j', 'address', 'show']))
    found = [(link, item) for link in links for item in link.get('addr_info', []) if item.get('local') == address]
    require(len(found) == 1, 'The exact frontend address must exist once before routing is configured')
    link, assigned = found[0]
    device = link['ifname']
    require(isinstance(device, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', device) is not None,
            'Unexpected frontend interface name')
    # `ip -4 address` deliberately omits link-layer addresses. Bind the MAC
    # through the link query instead of guessing or weakening the identity check.
    hardware = [row for row in json.loads(command(['-j', 'link', 'show'])) if row.get('ifname') == device]
    require(len(hardware) == 1 and hardware[0].get('address', '').lower() == mac
            and 'UP' in hardware[0].get('flags', []) and assigned.get('prefixlen') == 24,
            'Frontend interface identity, prefix or link state differs')
    rules = json.loads(command(['-j', 'rule', 'show']))
    require(all(row.get('priority') in (0, TABLE, 32766, 32767) for row in rules),
            'Existing non-default routing policy needs review')
    own_rules = [row for row in rules if row.get('priority') == TABLE or str(row.get('table')) == str(TABLE)]
    for row in own_rules:
        source = row.get('src', '')
        require(row.get('priority') == TABLE and str(row.get('table')) == str(TABLE)
                and source in (address, address + '/32') and row.get('dst', 'all') == 'all'
                and set(row) <= {'priority', 'src', 'dst', 'table', 'protocol'}, 'Reserved ingress rule differs; no replacement')
    require(len(own_rules) <= 1, 'Duplicate ingress rules need review')
    routes = [row for row in json.loads(command(['-j', 'route', 'show', 'table', 'all']))
              if str(row.get('table')) == str(TABLE)]
    expected = {(network, None, 'link'), ('default', gateway, 'global')}
    actual = []
    for row in routes:
        signature = (row.get('dst'), row.get('gateway'), row.get('scope', 'global'))
        require(signature in expected and row.get('dev') == device and row.get('prefsrc') == address
                and row.get('type', 'unicast') == 'unicast' and not row.get('flags')
                and not row.get('metric') and 'multipath' not in row, 'Reserved ingress routes differ; no replacement')
        actual.append(signature)
    require(len(actual) == len(set(actual)), 'Duplicate ingress routes need review')
    return address, network, gateway, device, set(actual), bool(own_rules)


def run(settings, apply=False):
    address, network, gateway, device, routes, rule = state(settings)
    missing = {(network, None, 'link'), ('default', gateway, 'global')} - routes
    require(apply or not missing and rule, 'The selected ingress routing policy is not complete')
    changed = False
    if apply:
        if (network, None, 'link') in missing:
            command(['route', 'add', network, 'dev', device, 'scope', 'link', 'src', address, 'table', str(TABLE)])
            changed = True
        if ('default', gateway, 'global') in missing:
            command(['route', 'add', 'default', 'via', gateway, 'dev', device, 'src', address, 'table', str(TABLE)])
            changed = True
        if not rule:
            command(['rule', 'add', 'priority', str(TABLE), 'from', address + '/32', 'table', str(TABLE)])
            changed = True
        # Read back the completed policy; a partial failure never reports success.
        run(settings, apply=False)
    return {'status': 'passed', 'table': TABLE, 'frontend': address, 'device': device, 'changed': changed}


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'r') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096, 'Expected an owned private routing file')
        return json.loads(stream.read(4097))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run(read(args.config), apply=args.apply)))
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Ingress routing held; inspect the selected guest and retained deployment evidence.') from None
