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
    if '--output-format' in args and args[args.index('--output-format') + 1] == 'json':
        return json.loads(proc.stdout)
    return proc.stdout.strip() or None


def declared_grants(request):
    """Return the closed, nonpropagating bootstrap and application ACL scope."""
    grants = {}

    def add(path, role):
        grants.setdefault(path, set()).add(role)

    def resource(value):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*', value):
            raise RuntimeError('Use an individual existing storage or bridge name')
        return value

    def network(nic):
        if set(nic) != {'bridge', 'vlan'}:
            raise RuntimeError('Declare only the bridge and VLAN for each interface')
        bridge, vlan = resource(nic['bridge']), nic['vlan']
        if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094):
            raise RuntimeError('Use one integer VLAN or explicit null')
        add('/sdn/zones/localnetwork/' + bridge, 'PVESDNUser')
        if vlan is not None:
            add('/sdn/zones/localnetwork/' + bridge + '/' + str(vlan), 'PVESDNUser')

    vmid = request['vmid']
    if type(vmid) is not int or not 100 <= vmid <= 999999999 or vmid in (4914, 4915, 4920):
        raise RuntimeError('Choose a valid bootstrap ID, never a protected guest')
    add('/vms/' + str(vmid), 'PVEVMAdmin')
    add('/storage/' + resource(request['storage_id']), 'PVEDatastoreUser')
    add('/storage/' + resource(request['template_storage']), 'PVEAuditor')
    network({'bridge': request['bridge'], 'vlan': request.get('vlan')})
    add('/nodes/' + resource(request['node']), 'PVEAuditor')
    applications = request.get('applications', [])
    if not isinstance(applications, list) or len(applications) > 64:
        raise RuntimeError('Declare a finite application guest list')
    seen = {vmid}
    for app in applications:
        if set(app) != {'vmid', 'storage_id', 'template_storage', 'interfaces'}:
            raise RuntimeError('Use the documented application access fields')
        guest = app['vmid']
        if (type(guest) is not int or not 100 <= guest <= 999999999
                or guest in {900, 4914, 4915, 4920} or guest in seen):
            raise RuntimeError('Duplicate or protected application guest ID')
        seen.add(guest)
        add('/vms/' + str(guest), 'PVEVMAdmin')
        add('/storage/' + resource(app['storage_id']), 'PVEDatastoreUser')
        add('/storage/' + resource(app['template_storage']), 'PVEAuditor')
        if not isinstance(app['interfaces'], list) or not 1 <= len(app['interfaces']) <= 8:
            raise RuntimeError('Declare the application guest interfaces')
        for nic in app['interfaces']:
            network(nic)
    return grants


def reconcile(request, execute=command, apply=False):
    """Add only reviewed missing rows to a saved token; never rotate or adopt it."""
    desired = declared_grants(request)
    node, vmid = request['node'], request['vmid']
    if socket.gethostname().split('.')[0] != node or not node_ready(node):
        raise RuntimeError('SSH host is not the selected ready Proxmox node')
    saved = request['expected']
    token_name = 'homelab-deploy-' + str(vmid)
    token_id = 'root@pam!' + token_name
    if saved.get('status') != 'ready' or saved.get('token_id') != token_id:
        raise RuntimeError('Use the successfully saved token receipt for this guest')
    tokens = [x for x in execute(['pveum', 'user', 'token', 'list', 'root@pam',
                                 '--output-format', 'json']) if x.get('tokenid') == token_name]
    expiry = request.get('expires_at', saved['expires_at'])
    if type(expiry) is not int or expiry < 0 or expiry > time.time() + 31536000:
        raise RuntimeError('Use an explicit supported token expiry')
    if expiry and expiry <= time.time():
        raise RuntimeError('Token expired; explicitly review a new expiry before configuring it')
    if (len(tokens) != 1 or tokens[0].get('privsep') not in (1, True)
            or tokens[0].get('expire') != saved['expires_at']):
        raise RuntimeError('Saved token metadata changed; no renewal or replacement')
    baseline = {(x['path'], role, 0) for x in saved['grants']
                for role in (x['roles'].split(',') if isinstance(x['roles'], str) else x['roles'])
                if x['propagate'] is False}
    if not baseline or any(x.get('propagate') is not False for x in saved['grants']):
        raise RuntimeError('The saved exact nonpropagating grants are required')
    rows = [x for x in execute(['pveum', 'acl', 'list', '--output-format', 'json'])
            if x.get('ugid') == token_id]
    actual = {(x['path'], x['roleid'], int(x.get('propagate', 1))) for x in rows}
    if len(rows) != len(actual) or any(x.get('type') != 'token' for x in rows) or actual != baseline:
        raise RuntimeError('Live token ACLs differ from the saved receipt; preserve drift for review')
    wanted = {(path, role, 0) for path, roles in desired.items() for role in roles}
    if not baseline <= wanted:
        raise RuntimeError('This configuration would remove earlier grants; review revocation separately')
    census = execute(['pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'])
    for path, _, _ in wanted - baseline:
        if path.startswith('/vms/') and any(int(x['vmid']) == int(path.split('/')[-1]) for x in census):
            raise RuntimeError('Newly selected application guest ID already exists; no adoption')
    owner = [x for x in census if int(x['vmid']) == vmid]
    if len(owner) != 1 or owner[0].get('node') != node or owner[0].get('name') != 'deploy':
        raise RuntimeError('The existing deployment guest identity differs')
    config = execute(['pvesh', 'get', '/nodes/' + node + '/lxc/' + str(vmid) + '/config',
                      '--output-format', 'json'])
    nic = dict(x.split('=', 1) for x in config.get('net0', '').split(',') if '=' in x)
    if (config.get('hostname') != 'deploy' or config.get('unprivileged') not in (1, True)
            or nic.get('hwaddr', '').lower() != request['guest_mac'].lower()):
        raise RuntimeError('The deployment guest hostname, MAC or unprivileged mode differs')
    missing = [{'path': path, 'roles': sorted({r for p, r, _ in wanted - baseline if p == path}),
                'propagate': False} for path in sorted({p for p, _, _ in wanted - baseline})]
    result = {'status': 'ready', 'token_id': token_id, 'expires_at': expiry,
              'changed': bool(missing) or expiry != saved['expires_at'], 'missing': missing,
              'expiry_change': expiry != saved['expires_at'],
              'grants': [{'path': p, 'roles': ','.join(sorted(r)), 'propagate': False}
                         for p, r in sorted(desired.items())]}
    if not apply:
        return result
    if expiry != saved['expires_at']:
        execute(['pveum', 'user', 'token', 'modify', 'root@pam', token_name,
                 '--expire', str(expiry)])
    for item in missing:
        execute(['pveum', 'acl', 'modify', item['path'], '--tokens', token_id,
                 '--roles', ','.join(sorted(desired[item['path']])), '--propagate', '0'])
    metadata = [x for x in execute(['pveum', 'user', 'token', 'list', 'root@pam',
                                   '--output-format', 'json']) if x.get('tokenid') == token_name]
    if (len(metadata) != 1 or metadata[0].get('privsep') not in (1, True)
            or metadata[0].get('expire') != expiry):
        raise RuntimeError('Token expiry/privsep readback mismatch; no automatic retry')
    after = [x for x in execute(['pveum', 'acl', 'list', '--output-format', 'json'])
             if x.get('ugid') == token_id]
    if ({(x['path'], x['roleid'], int(x.get('propagate', 1))) for x in after} != wanted
            or any(x.get('type') != 'token' for x in after)):
        raise RuntimeError('Applied token grants failed exact readback; no automatic retry')
    effective = execute(['pveum', 'user', 'token', 'permissions', 'root@pam', token_name,
                         '--output-format', 'json'])
    effective = {p: perms for p, perms in effective.items() if perms}
    if set(effective) != set(desired) or any(flag not in (0, False) for perms in effective.values() for flag in perms.values()):
        raise RuntimeError('Effective permission paths or propagation differ')
    for path, roles in desired.items():
        needed = set()
        if path.startswith('/vms/'):
            needed.update(['VM.Allocate', 'VM.Audit', 'VM.PowerMgmt', 'VM.Config.CPU',
                           'VM.Config.Memory', 'VM.Config.Disk', 'VM.Config.Network', 'VM.Config.Options'])
        elif path.startswith('/storage/'):
            needed.add('Datastore.Audit')
            if 'PVEDatastoreUser' in roles:
                needed.add('Datastore.AllocateSpace')
        elif path.startswith('/nodes/'):
            needed.add('Sys.Audit')
        else:
            needed.add('SDN.Use')
        if not needed <= set(effective[path]):
            raise RuntimeError('Required effective permissions are missing')
    result['effective_permissions'] = effective
    return result


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
    vlan = request.get('vlan')
    if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094):
        raise RuntimeError('Use no VLAN or one integer VLAN from 1 to 4094')
    seconds = request['expires_in']
    if type(seconds) is not int or (seconds != 0 and not 3600 <= seconds <= 31536000):
        raise RuntimeError('Token lifetime must be zero or between one hour and one year')
    if type(request['download_template']) is not bool:
        raise RuntimeError('Template download selection must be explicit')
    if request['download_template']:
        raise RuntimeError('Use a cached template over pinned SSH; API template downloads are outside this MVP')
    if not node_ready(node):
        raise RuntimeError('Proxmox cluster filesystem/local node is not ready')
    grants = declared_grants(request)
    guests = execute(['pvesh', 'get', '/cluster/resources', '--type', 'vm', '--output-format', 'json'])
    selected_ids = {int(p.split('/')[-1]) for p in grants if p.startswith('/vms/')}
    if any(int(row['vmid']) in selected_ids for row in guests):
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
    if vlan is not None:
        need('/sdn/zones/localnetwork/' + request['bridge'] + '/' + str(vlan), ['SDN.Use'])
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
