"""Create-once private monitoring credentials; source packets contain no keys.

One immutable record belongs to each guest identity. The monitoring server reads
that same record; neither a rerun nor a source change implicitly rotates a key.
"""
import json
import fcntl
import os
import re
import secrets
import stat
from pathlib import Path

from private_io import encoded, private_directory, read_json, regular, require, write_new

PROVIDER = Path('/var/lib/homelab-bootstrap/monitoring-access/token.json')
TOKEN_ID = 'homelab-zabbix@pve!monitoring'


def identity(cfg):
    return {'node': cfg['site']['node'], 'vmid': cfg['guest']['vmid'],
            'hostname': cfg['guest']['hostname']}


def credential(root, name, owner, fields):
    require(re.fullmatch(r'[a-z0-9-]+\.json', name), 'Use a fixed monitoring credential name')
    root.mkdir(mode=0o700, exist_ok=True)
    private_directory(root)
    fd = os.open(root / 'credentials.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                'Preserve safe monitoring credential custody')
        # Serialize only create/read of these small credential records, never
        # guest deployment, package installation or service operations.
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _credential(root / name, owner, fields)


def _credential(path, owner, fields):
    require(not path.is_symlink(), 'Refuse a linked monitoring credential')
    if not path.exists() and not path.is_symlink():
        value = {'schema': 'homelab-monitoring-credential-v1', 'owner': owner,
                 'secrets': {field: ('Zbx!7' if field == 'admin_password' else '')
                            + secrets.token_hex(32) for field in fields}}
        write_new(path, encoded(value))
    value = read_json(path, private=True)
    require(set(value) == {'schema', 'owner', 'secrets'}
            and value['schema'] == 'homelab-monitoring-credential-v1'
            and value['owner'] == owner and set(value['secrets']) == set(fields)
            and all(isinstance(v, str) and re.fullmatch(
                r'Zbx!7[0-9a-f]{64}' if k == 'admin_password' else '[0-9a-f]{64}', v)
                    for k, v in value['secrets'].items()),
            'Monitoring credentials differ; preserve the original without rotation')
    return value['secrets']


def agent(root, member, node):
    owner = {'node': node, 'vmid': member['vmid'], 'hostname': member['guest_hostname']}
    return credential(root, 'guest-' + str(member['vmid']) + '.json', owner, ['psk'])['psk']


def provider(cfg):
    """Admit the existing bootstrap result before touching any monitored guest."""
    root = PROVIDER.parent
    require(not (root / 'HOLD.json').exists() and not (root / 'HOLD.json').is_symlink(),
            'Preserve the held monitoring bootstrap attempt')
    owner = read_json(root / 'owner.json', private=True)
    require(set(owner) == {'schema', 'endpoint', 'node', 'address', 'backup_source'}
            and owner['schema'] == 'homelab-zabbix-access-v1'
            and owner['endpoint'] == cfg['site']['api_endpoint'] and owner['node'] == cfg['site']['node']
            and owner['address'] + ':10051' == cfg['app']['monitoring']['server_active'],
            'Commission monitoring access for this exact node and server address')
    require(read_json(root / 'READY.json', private=True) == {'identity': TOKEN_ID, 'read_only': True},
            'Complete read-only monitoring bootstrap before guest changes')
    value = read_json(PROVIDER, private=True)
    require(set(value) == {'identity', 'token'} and value['identity'] == TOKEN_ID
            and re.fullmatch(re.escape(TOKEN_ID) + r'=[A-Za-z0-9-]+', value['token']),
            'Use the commissioned dedicated read-only Proxmox monitoring identity')
    return value


def source_files():
    return [str(PROVIDER), str(PROVIDER.parent / 'owner.json'), str(PROVIDER.parent / 'READY.json')]


def prepare(cfg, stack, destination):
    selected = cfg['app'].get('monitoring')
    if selected is None:
        return {}
    access = provider(cfg)
    root = Path(cfg['paths']['state_root']) / 'monitoring-credentials'
    private_directory(root.parent)
    own = {'vmid': cfg['guest']['vmid'], 'guest_hostname': cfg['guest']['hostname']}
    result = {'monitoring-agent.json': encoded({'psk': agent(root, own, cfg['site']['node'])})}
    if set(selected['profiles']) & {'postgresql', 'mysql'}:
        values = credential(root, 'database-' + str(cfg['guest']['vmid']) + '.json',
                            identity(cfg), ['password'])
        result['monitoring-database-password'] = values['password'].encode()
    if cfg['app']['kind'] in {'postgresql', 'monitoring'}:
        owner = {'node': cfg['site']['node'], 'vmid': selected['server_vmid'], 'hostname': 'zabbix'}
        shared = credential(root, 'server-' + str(selected['server_vmid']) + '.json',
                            owner, ['database_password', 'admin_password'])
        result['monitoring-storage-password'] = shared['database_password'].encode()
    if cfg['app']['kind'] == 'monitoring':
        result['database-password'] = shared['database_password'].encode()
        result['proxmox-ca.pem'] = regular(Path(cfg['paths']['ca_file']))
        members = [{**m, 'psk': agent(root, m, cfg['site']['node'])} for m in selected['members']]
        result['monitoring-server.json'] = encoded({
            'admin_password': shared['admin_password'], 'members': members,
            'proxmox': {**selected['proxmox'], 'token_id': TOKEN_ID,
                        'token_secret': access['token'].split('=', 1)[1]}})
    return result
