"""Provision or verify the deliberately privileged bootstrap CD API identity."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

TOKEN = 'homelab-bootstrap-cd-900'
IDENTITY = 'root@pam!' + TOKEN


def command(args):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=20, check=True)
    return json.loads(proc.stdout) if '--output-format' in args else None


def provision(node, verify=False, execute=command, emit=lambda row: None):
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', node)
            or socket.gethostname().split('.')[0] != node or not os.path.ismount('/etc/pve')
            or Path('/etc/pve/local').resolve() != Path('/etc/pve/nodes') / node):
        raise ValueError('The pinned SSH host is not the selected ready Proxmox node')
    tokens = execute(['pveum', 'user', 'token', 'list', 'root@pam', '--output-format', 'json'])
    selected = [r for r in tokens if r['tokenid'] == TOKEN]
    def acls():
        return [r for r in execute(['pveum', 'acl', 'list', '--output-format', 'json']) if r.get('ugid') == IDENTITY]
    if not verify:
        if selected or acls():
            raise ValueError('Bootstrap CD identity already exists; no adoption or rotation')
        minted = execute(['pveum', 'user', 'token', 'add', 'root@pam', TOKEN,
                          '--privsep', '1', '--expire', '0', '--output-format', 'json'])
        emit({'status': 'credential_created_acl_pending', 'token': IDENTITY + '=' + minted['value']})
        execute(['pveum', 'acl', 'modify', '/', '--tokens', IDENTITY,
                 '--roles', 'Administrator', '--propagate', '1'])
        selected = [r for r in execute(['pveum', 'user', 'token', 'list', 'root@pam',
                                       '--output-format', 'json']) if r['tokenid'] == TOKEN]
    rows = acls()
    if (len(selected) != 1 or selected[0].get('privsep') != 1 or selected[0].get('expire') != 0
            or len(rows) != 1 or rows[0].get('path') != '/' or rows[0].get('roleid') != 'Administrator'
            or rows[0].get('propagate') != 1 or rows[0].get('type') != 'token'):
        raise ValueError('Bootstrap CD credential metadata or ACL readback differs')
    return {'status': 'ready', 'token_id': IDENTITY, 'expires_at': 0,
            'role': 'Administrator', 'path': '/', 'propagate': True}


if __name__ == '__main__':
    request = json.loads(sys.argv[1])
    try:
        result = provision(request['node'], request['verify'],
                           emit=lambda row: print(json.dumps(row), flush=True))
        print(json.dumps(result), flush=True)
    except Exception:
        raise SystemExit('Credential setup stopped; preserve its private partial receipt. No automatic retry.') from None
