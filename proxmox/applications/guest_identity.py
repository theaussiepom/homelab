"""Verify a new guest's SSH key against its trusted Proxmox creation log."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
from urllib.parse import quote, urlencode
from private_io import private_writer
import network_endpoints


def fingerprint(key):
    raw = base64.b64decode(key, validate=True)
    # An Ed25519 SSH public-key blob has two length-prefixed fields.
    if len(raw) != 51 or raw[:15] != struct.pack('!I', 11) + b'ssh-ed25519' or raw[15:19] != struct.pack('!I', 32):
        raise ValueError('Expected one valid Ed25519 guest host key')
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


def creation_fingerprint(rows):
    found = []
    ordered = sorted(rows, key=lambda row: row['n'])
    for previous, current in zip(ordered, ordered[1:]):
        if "Creating SSH host key 'ssh_host_ed25519_key'" in previous.get('t', ''):
            match = re.fullmatch(r'done: (SHA256:[A-Za-z0-9+/]{43})\s+\S+', current.get('t', ''))
            if current['n'] != previous['n'] + 1 or not match:
                raise ValueError('The creation task has incomplete SSH identity evidence')
            found.append(match.group(1))
    if len(found) != 1:
        raise ValueError('The creation task needs exactly one Ed25519 fingerprint')
    return found[0]


def verify_network(cfg, address, get_json):
    """Read trusted PVE identity and refuse changed DHCP leases before any SSH."""
    if ipaddress.ip_address(address).version != 4:
        raise ValueError('Select the verified guest IPv4 address')
    guest = cfg['guest']
    network_endpoints.addresses(guest)
    prefix = '/nodes/' + quote(cfg['site']['node'], safe='')
    config = get_json(prefix + '/lxc/' + str(guest['vmid']) + '/config')
    if config.get('hostname') != guest['hostname'] or config.get('protection') != 1 or config.get('unprivileged') != 1:
        raise ValueError('Proxmox returned a different or unprotected application guest')
    selected = [nic for nic in guest['interfaces'] if nic['mac'].lower() == cfg['app']['mac'].lower()]
    if len(selected) != 1 or network_endpoints.interface(selected[0]) is None or str(network_endpoints.interface(selected[0]).ip) != address:
        raise ValueError('Select exactly one application interface')
    interfaces = get_json(prefix + '/lxc/' + str(guest['vmid']) + '/interfaces')
    for nic in guest['interfaces']:
        if nic not in selected and nic['ipv4'] != 'dhcp':
            continue
        networks = []
        for key, value in config.items():
            if re.fullmatch(r'net[0-9]+', key):
                pairs = [part.split('=', 1) for part in value.split(',')]
                if any(len(pair) != 2 for pair in pairs) or len({pair[0] for pair in pairs}) != len(pairs):
                    raise ValueError('Require unambiguous Proxmox network fields')
                fields = dict(pairs)
                if fields.get('hwaddr', '').lower() == nic['mac'].lower():
                    networks.append(fields)
        vlan = str(nic['vlan']) if nic['vlan'] is not None else None
        if len(networks) != 1 or networks[0].get('bridge') != nic['bridge'] or networks[0].get('tag') != vlan:
            raise ValueError('The guest network does not match its reviewed identity')
        if nic['ipv4'] == 'dhcp' and (networks[0].get('ip') != 'dhcp' or networks[0].get('gw')):
            raise ValueError('Preserve the reviewed DHCP allocation without a static gateway')
        active = [row for row in interfaces if row.get('hwaddr', '').lower() == nic['mac'].lower()]
        expected = network_endpoints.interface(nic)
        if len(active) != 1:
            raise ValueError('Require one observed interface for each reviewed MAC')
        observed_value = active[0].get('inet', '')
        if not isinstance(observed_value, str) or '/' not in observed_value:
            raise ValueError('Require an observed assigned IPv4 address and prefix')
        observed = ipaddress.IPv4Interface(observed_value)
        if observed.ip != expected.ip or (nic['ipv4'] == 'dhcp' and observed != expected):
            raise ValueError('The observed guest endpoint differs from its reviewed address or prefix')


def pin(cfg, work, address, get_json, persist):
    """No credential is sent to the guest before its public key is verified."""
    verify_network(cfg, address, get_json)
    guest = cfg['guest']
    prefix = '/nodes/' + quote(cfg['site']['node'], safe='')
    hosts = Path(cfg['paths']['known_hosts'])
    info = hosts.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('Use the deployment account private known_hosts file')
    lookup = subprocess.run(['ssh-keygen', '-F', address, '-f', str(hosts)], capture_output=True, text=True, timeout=10)
    if lookup.returncode not in (0, 1):
        raise ValueError('Existing guest host-key lookup failed')
    existing = [line.split()[2] for line in lookup.stdout.splitlines()
                if line and not line.startswith('#') and len(line.split()) >= 3 and line.split()[1] == 'ssh-ed25519']
    if lookup.returncode == 0:
        if len(existing) != 1:
            raise ValueError('Existing guest trust must have one exact Ed25519 key')
        expected = fingerprint(existing[0])
        source = 'existing-pinned-key'
    else:
        window = json.loads((work / 'apply-window.json').read_text())
        plan = json.loads((work / 'plan.json').read_text())
        if window['plan_sha256'] != plan['plan_sha256'] or not window.get('finished_at_ns'):
            raise ValueError('Guest creation has no completed reviewed apply window')
        actor = Path(cfg['paths']['api_token']).read_text().strip().partition('=')[0]
        if '!' not in actor:
            raise ValueError('Guest identity verification requires the existing scoped API token')
        user, token = actor.split('!', 1)
        query = urlencode({'vmid': guest['vmid'], 'typefilter': 'vzcreate', 'limit': 10})
        tasks = get_json(prefix + '/tasks?' + query)
        matches = [row for row in tasks if row.get('node') == cfg['site']['node']
                   and str(row.get('id')) == str(guest['vmid']) and row.get('type') == 'vzcreate'
                   and row.get('user') == user and row.get('tokenid') == token and row.get('status') == 'OK'
                   and window['started_at_ns'] // 1_000_000_000 - 1 <= row.get('starttime', -1)
                   <= row.get('endtime', -1) <= window['finished_at_ns'] // 1_000_000_000 + 1]
        if len(matches) != 1:
            raise ValueError('No unambiguous successful creation task from this reviewed apply')
        source = matches[0]['upid']
        expected = creation_fingerprint(get_json(prefix + '/tasks/' + quote(source, safe='') + '/log?limit=200'))

    scan = subprocess.run(['ssh-keyscan', '-T', '5', '-t', 'ed25519', address], capture_output=True, text=True, timeout=15)
    keys = [line.split() for line in scan.stdout.splitlines() if line and not line.startswith('#')]
    if scan.returncode or len(keys) != 1 or len(keys[0]) != 3 or keys[0][:2] != [address, 'ssh-ed25519']:
        raise ValueError('Could not obtain exactly the selected guest public host key')
    if fingerprint(keys[0][2]) != expected:
        raise ValueError('Guest SSH identity differs from the trusted Proxmox evidence; preserve it for review')
    if not existing:
        with private_writer(hosts, append=True, readable=True, create=False) as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError('Guest host-trust file changed during verification')
            if stream.seek(0, os.SEEK_END):
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b'\n':
                    raise ValueError('Existing known_hosts must end with a newline before appending a guest')
            stream.write((' '.join(keys[0]) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
    result = {'address': address, 'fingerprint': expected, 'source': source}
    persist(work / 'host-key-evidence.json', result)
    return result
