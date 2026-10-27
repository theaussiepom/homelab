#!/usr/bin/env python3
"""Restricted native SSH configuration for the existing single-guest CD path."""
import argparse
import base64
import grp
import ipaddress
import json
from pathlib import Path
import pwd
import re
import subprocess
import sys

SYSCTLS = {'net.ipv4.ip_forward': '0', 'net.ipv4.conf.all.forwarding': '0',
           'net.ipv4.conf.default.forwarding': '0', 'net.ipv6.conf.all.forwarding': '0',
           'net.ipv6.conf.default.forwarding': '0'}


def ipv4(value):
    """Accept a literal unicast IPv4 address, without configuration syntax."""
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or str(ip) != value:
        raise ValueError('Select a literal unicast IPv4 address')
    return value


def source(value):
    network = ipaddress.IPv4Network(value, strict=True)
    if network.prefixlen != 32 or str(network) != value:
        raise ValueError('Bind each existing VPN or runner identity to an exact IPv4 /32')
    ipv4(str(network.network_address))
    return value


def validate_policy(policy):
    """Finite roles, exact endpoints and explicit public-key references only."""
    if set(policy) != {'entry_address', 'management_address', 'runner_source', 'roles', 'maintenance'}:
        raise ValueError('Bind the two listeners, existing runner, roles and finite maintenance endpoints')
    entry, management = ipv4(policy['entry_address']), ipv4(policy['management_address'])
    if entry == management:
        raise ValueError('Entry and management must be separate interfaces')
    source(policy['runner_source'])
    roles = policy['roles']
    if not isinstance(roles, list) or not 1 <= len(roles) <= 8:
        raise ValueError('Supply one to eight explicitly selected tunnel roles')
    names, uids, gids = set(), set(), set()
    for role in roles:
        if set(role) != {'name', 'uid', 'gid', 'sources', 'public_key_file', 'permit_open'}:
            raise ValueError('Bind role identity, existing public key, source peers and PermitOpen')
        name = role['name']
        if not isinstance(name, str) or not re.fullmatch('[a-z][a-z0-9_-]{0,30}', name) or name == 'root' or name in names:
            raise ValueError('Use distinct non-root role names')
        names.add(name)
        for key, used in [('uid', uids), ('gid', gids)]:
            value = role[key]
            if type(value) is not int or not 1000 <= value <= 59999 or value in used:
                raise ValueError('Bind distinct preserved role UID/GID values')
            used.add(value)
        if not isinstance(role['sources'], list) or not 1 <= len(role['sources']) <= 16 or len(set(role['sources'])) != len(role['sources']):
            raise ValueError('Bind finite distinct existing VPN peers')
        for peer in role['sources']:
            source(peer)
        if not Path(role['public_key_file']).is_absolute():
            raise ValueError('Select an existing operator public-key file on the private runner')
        opens = role['permit_open']
        if not isinstance(opens, list) or not 1 <= len(opens) <= 16 or len(set(opens)) != len(opens):
            raise ValueError('Bind finite distinct PermitOpen destinations')
        for endpoint in opens:
            match = re.fullmatch(r'([0-9.]+):([1-9][0-9]{0,4})', endpoint)
            if not match or int(match[2]) > 65535:
                raise ValueError('PermitOpen needs exact IPv4 and TCP port')
            ipv4(match[1])
    if not isinstance(policy['maintenance'], list) or len(policy['maintenance']) > 16:
        raise ValueError('Bind finite package/DNS maintenance endpoints')
    for endpoint in policy['maintenance']:
        if set(endpoint) != {'address', 'port', 'proto', 'source_address'}:
            raise ValueError('Maintenance needs exact address, port and protocol')
        ipv4(endpoint['address'])
        if endpoint['source_address'] not in (entry, management):
            raise ValueError('Maintenance must select an assigned source address')
        if type(endpoint['port']) is not int or not 1 <= endpoint['port'] <= 65535 or endpoint['proto'] not in ('tcp', 'udp'):
            raise ValueError('Maintenance needs exact address, port and protocol')
    return policy


def access_rules(policy):
    """No subnet-wide grant: selected packets use PVE's existing DROP policies."""
    validate_policy(policy)
    entry, management = policy['entry_address'], policy['management_address']
    rules = [{'direction': 'in', 'proto': 'tcp', 'port': '22', 'source': policy['runner_source'],
              'destination': management + '/32', 'comment': 'Existing deployment SSH'}]
    peers = sorted({peer for role in policy['roles'] for peer in role['sources']})
    for peer in peers:
        rules.append({'direction': 'in', 'proto': 'tcp', 'port': '22', 'source': peer,
                      'destination': entry + '/32', 'comment': 'Selected admin VPN peer'})
    endpoints = {(endpoint.split(':')[0], int(endpoint.split(':')[1]), 'tcp')
                 for role in policy['roles'] for endpoint in role['permit_open']}
    for address, port, proto in sorted(endpoints):
        rules.append({'direction': 'out', 'proto': proto, 'port': str(port), 'source': management + '/32',
                      'destination': address + '/32', 'comment': 'Selected bastion destination'})
    for row in policy['maintenance']:
        rules.append({'direction': 'out', 'proto': row['proto'], 'port': str(row['port']),
                      'source': row['source_address'] + '/32', 'destination': row['address'] + '/32',
                      'comment': 'Selected package or DNS maintenance'})
    return rules


def validate(cfg):
    app, guest = cfg['app'], cfg['guest']
    policy = validate_policy(app['bastion'])
    if any(key in app for key in ('capture', 'stack_config', 'database', 'discovery_routes')):
        raise ValueError('A bastion has no application restore, container stack or public discovery route')
    nics = guest['interfaces']
    if len(nics) != 2 or any(nic.get('ipv6', 'manual') not in (None, 'manual') for nic in nics):
        raise ValueError('Select exactly two static IPv4 interfaces; IPv6 needs separate admission')
    assigned = {str(ipaddress.IPv4Interface(nic['ipv4']).ip): ipaddress.IPv4Interface(nic['ipv4']).network for nic in nics}
    if any(network.prefixlen < 24 for network in assigned.values()):
        raise ValueError('Select narrow, non-overlapping guest networks')
    networks = list(assigned.values())
    if len(networks) != 2 or networks[0].overlaps(networks[1]):
        raise ValueError('Select two non-overlapping guest networks')
    if (set(assigned) != {policy['entry_address'], policy['management_address']}
            or assigned[policy['entry_address']] == assigned[policy['management_address']]
            or app['address'] != policy['management_address']):
        raise ValueError('Bind the entry and management interfaces; CD uses only management')
    gateways = [nic for nic in nics if nic.get('gateway')]
    if len(gateways) != 1 or str(ipaddress.IPv4Interface(gateways[0]['ipv4']).ip) != policy['entry_address']:
        raise ValueError('Use the entry default gateway for VPN replies; management destinations stay on-link')
    if ipaddress.IPv4Address(gateways[0]['gateway']) not in assigned[policy['entry_address']]:
        raise ValueError('The entry gateway must be on its selected network')
    management_network = assigned[policy['management_address']]
    for endpoint in policy['maintenance']:
        expected_source = policy['management_address'] if ipaddress.IPv4Address(endpoint['address']) in management_network else policy['entry_address']
        if endpoint['source_address'] != expected_source:
            raise ValueError('Maintenance source must match the selected direct or default route')
    for role in policy['roles']:
        for endpoint in role['permit_open']:
            address = endpoint.split(':')[0]
            if ipaddress.IPv4Address(address) not in management_network or address in assigned:
                raise ValueError('Tunnel destinations must be exact other management-interface endpoints')
    if guest.get('nesting') is not False or guest.get('keyctl') is not False or guest.get('volumes') != {}:
        raise ValueError('A native bastion needs no nesting, keyctl or application data mounts')
    if guest['rules'] != access_rules(policy):
        raise ValueError('The guest firewall must exactly match the selected SSH and maintenance endpoints')
    names = {value.split('=')[0] for value in app['packages']}
    if not {'openssh-server', 'nftables'} <= names or any(name.startswith(('docker', 'podman')) for name in names):
        raise ValueError('Pin native OpenSSH and nftables packages, without a container engine')
    render(policy)  # Reject invalid/missing public key material before any native step.


def source_files(policy):
    validate_policy(policy)
    return [role['public_key_file'] for role in policy['roles']]


def public_key(path):
    """Read only the explicitly selected public key; never generate credentials."""
    value = Path(path).read_text().strip()
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', value):
        raise ValueError('Supply one existing comment-free Ed25519 public key')
    try:
        decoded = base64.b64decode(value.split()[1], validate=True)
    except ValueError:
        raise ValueError('Invalid Ed25519 public key') from None
    if len(decoded) != 51 or decoded[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('Invalid Ed25519 public key')
    return value + '\n'


def render(policy):
    validate_policy(policy)
    entry, management = policy['entry_address'], policy['management_address']
    roles = policy['roles']
    lines = ['# Managed only for the selected new bastion guest.', 'Port 22', 'AddressFamily inet',
             f'ListenAddress {entry}:22', f'ListenAddress {management}:22',
             'HostKey /etc/ssh/ssh_host_ed25519_key', 'UsePAM yes',
             'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
             'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
             'PermitRootLogin prohibit-password', 'StrictModes yes',
             'AuthorizedKeysFile /root/.ssh/authorized_keys', 'AuthorizedKeysCommand none',
             'TrustedUserCAKeys none', 'AllowAgentForwarding no', 'AllowTcpForwarding no',
             'AllowStreamLocalForwarding no', 'GatewayPorts no', 'PermitListen none',
             'PermitOpen none', 'PermitTunnel no', 'PermitTTY no', 'X11Forwarding no',
             'PermitUserRC no', 'PermitUserEnvironment no', 'LogLevel VERBOSE',
             'LoginGraceTime 30', 'MaxAuthTries 3',
             f'Match LocalAddress {management}', f'    AllowUsers root@{policy["runner_source"]}',
             f'Match LocalAddress {entry}',
             '    AllowUsers ' + ' '.join(role['name'] + '@' + peer for role in roles for peer in role['sources']),
             '    PermitRootLogin no', '    MaxSessions 0', '    ForceCommand /usr/sbin/nologin',
             '    AllowTcpForwarding local', '    AuthorizedKeysFile /etc/ssh/bastion-keys/%u']
    for role in roles:
        lines += [f'Match LocalAddress {entry} User {role["name"]}',
                  '    PermitOpen ' + ' '.join(role['permit_open'])]
    return {'sshd_config': '\n'.join(lines) + '\n',
            'sysctl': ''.join(f'{key}={value}\n' for key, value in SYSCTLS.items()),
            'keys': {role['name']: public_key(role['public_key_file']) for role in roles}}


def account_preflight(policy, receipt=None):
    """Refuse account adoption or numeric collisions; never normalize an identity."""
    expected = [{key: role[key] for key in ('name', 'uid', 'gid')} for role in policy['roles']]
    if receipt is not None and receipt != expected:
        raise ValueError('Existing bastion account receipt differs')
    users, groups = pwd.getpwall(), grp.getgrall()
    for role in expected:
        selected_users = [row for row in users if row.pw_name == role['name'] or row.pw_uid == role['uid'] or row.pw_gid == role['gid']]
        selected_groups = [row for row in groups if row.gr_name == role['name'] or row.gr_gid == role['gid']]
        if not selected_users and not selected_groups and receipt is None:
            continue
        if (receipt is None or len(selected_users) != 1 or len(selected_groups) != 1
                or selected_users[0].pw_name != role['name'] or selected_users[0].pw_uid != role['uid']
                or selected_users[0].pw_gid != role['gid'] or selected_users[0].pw_dir != '/nonexistent'
                or selected_users[0].pw_shell != '/usr/sbin/nologin'
                or selected_groups[0].gr_name != role['name'] or selected_groups[0].gr_gid != role['gid']
                or selected_groups[0].gr_mem or any(role['name'] in row.gr_mem for row in groups)):
            raise ValueError('Preserve existing accounts and UID/GID membership; account collision or drift')


def daemon_preflight(defaults=Path('/etc/default/ssh')):
    """Do not let a vendor environment file override the selected daemon policy."""
    if defaults.exists():
        for line in defaults.read_text().splitlines():
            value = line.strip()
            if value and not value.startswith('#') and value not in ('SSHD_OPTS=', 'SSHD_OPTS=""', "SSHD_OPTS=''" ):
                raise ValueError('Unreviewed SSH service environment; preserve the original')


def check_transit(sysctls, links, rules):
    if any(sysctls.get(key) != value for key, value in SYSCTLS.items()):
        raise ValueError('Forwarding must be disabled for IPv4 and IPv6')
    if {row.get('ifname') for row in links} != {'lo', 'eth0', 'eth1'}:
        raise ValueError('Unexpected guest interface identity')
    if any(row.get('linkinfo', {}).get('info_kind') in ('bridge', 'vxlan', 'tun', 'wireguard')
           or row.get('linkinfo', {}).get('info_kind') == 'veth' and row.get('ifname') not in ('eth0', 'eth1')
           for row in links):
        # Only the two selected LXC interfaces may be veth devices.
        raise ValueError('Unexpected bridge or tunnel interface')
    if any(row.get('chain', {}).get('type') == 'nat' for row in rules['nftables']):
        raise ValueError('No NAT chains are admitted')


def run(argv):
    return subprocess.check_output(argv, text=True)


def verify(policy, expected):
    """Read back source restrictions; real client/authentication acceptance is separate."""
    validate_policy(policy)
    actual = Path('/etc/ssh/sshd_config').read_text()
    if actual != expected['sshd_config'] or Path('/etc/sysctl.d/90-homelab-bastion.conf').read_text() != expected['sysctl']:
        raise ValueError('Installed bastion policy drift')
    for name, value in expected['keys'].items():
        path = Path('/etc/ssh/bastion-keys') / name
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 or path.read_text() != value:
            raise ValueError('Installed public key or custody differs')
    daemon_preflight()
    account_preflight(policy, json.loads(Path('/etc/homelab-bastion-accounts.json').read_text()))
    sysctls = {key: run(['sysctl', '-n', key]).strip() for key in SYSCTLS}
    for family in ('ipv4', 'ipv6'):
        for path in Path('/proc/sys/net/' + family + '/conf').glob('*/forwarding'):
            if path.read_text().strip() != '0':
                raise ValueError('Per-interface forwarding drift')
    check_transit(sysctls, json.loads(run(['ip', '-d', '-j', 'link'])), json.loads(run(['nft', '-j', 'list', 'ruleset'])))
    # Check effective Match precedence with the installed OpenSSH binary.
    for role in policy['roles']:
        options = run(['/usr/sbin/sshd', '-T', '-C', f'user={role["name"]},addr={role["sources"][0].split("/")[0]},laddr={policy["entry_address"]},lport=22,host=client.invalid'])
        for line in ['allowtcpforwarding local', 'maxsessions 0', 'allowagentforwarding no',
                     'permitlisten none', 'permitopen ' + ' '.join(role['permit_open'])]:
            if line not in options.splitlines():
                raise ValueError('Effective OpenSSH restrictions differ')
    for role in policy['roles']:
        for endpoint in role['permit_open']:
            route = json.loads(run(['ip', '-j', 'route', 'get', endpoint.split(':')[0]]))
            if len(route) != 1 or route[0].get('prefsrc') != policy['management_address']:
                raise ValueError('A management connection would use an unselected source address')
    listeners = run(['ss', '-H', '-lnt']).splitlines()
    ssh_addresses = {line.split()[3] for line in listeners if line.split()[3].endswith(':22')}
    if ssh_addresses != {policy['entry_address'] + ':22', policy['management_address'] + ':22'}:
        raise ValueError('SSH listener addresses differ')
    run(['systemctl', 'is-active', 'ssh'])
    return {'status': 'passed', 'scope': 'installed restrictions; native client/MFA acceptance remains separate'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('accounts', 'verify'))
    parser.add_argument('--policy', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    validate_policy(policy)
    if args.action == 'accounts':
        daemon_preflight()
        receipt = Path('/etc/homelab-bastion-accounts.json')
        account_preflight(policy, json.loads(receipt.read_text()) if receipt.exists() else None)
        print('accounts admitted without adoption')
    else:
        bound = json.load(sys.stdin)
        if policy != bound['policy']:
            raise ValueError('Installed policy differs from selected private input')
        print(json.dumps(verify(policy, bound['files'])))


if __name__ == '__main__': main()
