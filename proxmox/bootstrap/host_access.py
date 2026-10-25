"""Create one separated bootstrap token through the ISO-installed SSH key."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


def node_ready(node):
    """Confirm the local Proxmox cluster filesystem belongs to the selected node."""
    return (os.path.ismount('/etc/pve') and Path('/etc/pve/nodes/' + node).is_dir()
            and Path('/etc/pve/local').resolve() == Path('/etc/pve/nodes/' + node))


def command(args):
    """Run one bounded Proxmox command and decode its JSON response."""
    proc = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if proc.returncode:
        raise RuntimeError('Proxmox access setup failed; ' + proc.stderr.strip())
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def grant(request, execute=command, emit=lambda value: None, ca_pem=None):
    """Mint one separated token and verify its exact resource grants without retry."""
    node, vmid = request['node'], request['vmid']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', node) or socket.gethostname().split('.')[0] != node:
        raise RuntimeError('SSH host must be the selected Proxmox node')
    if type(vmid) is not int or not 100 <= vmid <= 999999999 or vmid in (4914, 4915, 4920):
        raise RuntimeError('Select one unused bootstrap guest ID')
    for name in ('storage_id', 'template_storage', 'bridge'):
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*', request[name]):
            raise RuntimeError('Use an individual existing storage or bridge name')
    seconds = request['expires_in']
    if type(seconds) is not int or (seconds != 0 and not 3600 <= seconds <= 31536000):
        raise RuntimeError('Token lifetime must be zero or between one hour and one year')
    if type(request['download_template']) is not bool:
        raise RuntimeError('Template download selection must be explicit')
    if request['download_template']:
        raise RuntimeError('Use a cached template over pinned SSH; API template downloads are outside this MVP')
    if not node_ready(node):
        raise RuntimeError('Proxmox cluster filesystem/local node is not ready')
    guests = execute(['pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'])
    if any(int(row['vmid']) == vmid for row in guests):
        raise RuntimeError('Guest ID already exists; no replacement')
    token_name = 'homelab-deploy-' + str(vmid)
    token_id = 'root@pam!' + token_name
    def token_acls():
        """Read ACL rows assigned to this exact token identity."""
        return [row for row in execute(['pveum', 'acl', 'list', '--output-format', 'json'])
                if row.get('ugid') == token_id]
    tokens = execute(['pveum', 'user', 'token', 'list', 'root@pam', '--output-format', 'json'])
    if any(row.get('tokenid') == token_name for row in tokens):
        raise RuntimeError('Bootstrap token already exists; preserve it, no replacement')
    if token_acls():
        raise RuntimeError('Selected token has preexisting ACL rows; no adoption')
    grants = {}
    def add(path, role):
        """Combine selected roles at one nonpropagating resource path."""
        grants.setdefault(path, set()).add(role)
    add('/vms/' + str(vmid), 'PVEVMAdmin')
    add('/storage/' + request['storage_id'], 'PVEDatastoreUser')
    add('/storage/' + request['template_storage'], 'PVEAuditor')
    add('/sdn/zones/localnetwork/' + request['bridge'], 'PVESDNUser')
    add('/nodes/' + node, 'PVEAuditor')
    roles = {row['roleid'] for row in execute(['pveum', 'role', 'list', '--output-format', 'json'])}
    if not set().union(*grants.values()) <= roles:
        raise RuntimeError('A required built-in Proxmox role is missing')
    if ca_pem is None:
        ca_pem = Path('/etc/pve/pve-root-ca.pem').read_text()
    expires = int(time.time()) + seconds if seconds else 0
    minted = execute(['pveum', 'user', 'token', 'add', 'root@pam', token_name,
                      '--privsep', '1', '--expire', str(expires),
                      '--comment', 'Homelab bootstrap deploy ' + str(vmid), '--output-format', 'json'])
    result = {'status': 'token_created_grants_pending', 'token_id': token_id,
              'expires_at': expires, 'privsep': True, 'ca_pem': ca_pem,
              'PROXMOX_VE_API_TOKEN': token_id + '=' + minted['value'], 'grants': []}
    # The caller saves stdout privately, including this receipt before any ACL write.
    emit(dict(result))
    for path, assigned in grants.items():
        role = ','.join(sorted(assigned))
        execute(['pveum', 'acl', 'modify', path, '--tokens', token_id,
                 '--roles', role, '--propagate', '0'])
        result['grants'].append({'path': path, 'roles': role, 'propagate': False})
    result['effective_permissions'] = execute(['pveum', 'user', 'token', 'permissions',
                                             'root@pam', token_name, '--output-format', 'json'])
    actual = token_acls()
    expected = {(path, role, 0) for path, roles in grants.items() for role in roles}
    if (len(actual) != len(expected) or any(row.get('type') != 'token' for row in actual)
            or {(row['path'], row['roleid'], int(row['propagate'])) for row in actual} != expected):
        raise RuntimeError('Exact token ACL readback differs from the selected grants')
    metadata = [row for row in execute(['pveum', 'user', 'token', 'list', 'root@pam', '--output-format', 'json'])
                if row.get('tokenid') == token_name]
    if len(metadata) != 1 or metadata[0].get('privsep') not in (1, True) or metadata[0].get('expire') != expires:
        raise RuntimeError('Token expiry/privsep readback mismatch')
    effective = {path: perms for path, perms in result['effective_permissions'].items() if perms}
    if set(effective) != set(grants) or any(flag not in (0, False) for perms in effective.values() for flag in perms.values()):
        raise RuntimeError('Effective permission paths/propagation differ from the selected grants')
    required = {}
    def need(path, privileges):
        """Collect the effective privileges required at a selected resource path."""
        required.setdefault(path, set()).update(privileges)
    need('/vms/' + str(vmid), ['VM.Allocate', 'VM.Audit', 'VM.PowerMgmt', 'VM.Config.CPU',
                             'VM.Config.Memory', 'VM.Config.Disk', 'VM.Config.Network', 'VM.Config.Options'])
    need('/storage/' + request['storage_id'], ['Datastore.AllocateSpace', 'Datastore.Audit'])
    need('/storage/' + request['template_storage'], ['Datastore.Audit'])
    need('/sdn/zones/localnetwork/' + request['bridge'], ['SDN.Use'])
    need('/nodes/' + node, ['Sys.Audit'])
    if any(not privileges <= set(effective[path]) for path, privileges in required.items()):
        raise RuntimeError('Required effective token privileges are missing')
    result.update(exact_token_acl=actual, token_metadata=metadata[0])
    result['status'] = 'ready'
    return result


if __name__ == '__main__':
    try:
        result = grant(json.loads(sys.argv[1]), emit=lambda value: print(json.dumps(value), flush=True))
        print(json.dumps(result), flush=True)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # Never remove a partially created credential or retry its creation.
        print(json.dumps({'status': 'held', 'reason': str(exc), 'automatic_retry': False}), flush=True)
        raise SystemExit(1)
