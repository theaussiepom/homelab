"""Phase-owned preparation using the existing monitoring credential authority.

This module does not invent a store, lock, credential schema or source role.
Only the ordinary selected-input caller may invoke it after source/binding and
attempt guards. No target/API operation is performed here.
"""
from pathlib import Path
import re

import monitoring_inputs as owned
from private_io import encoded, private_directory, regular, require


def _server_owner(cfg, selected):
    hostname = selected.get('server_hostname')
    require(isinstance(hostname, str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', hostname)
            and type(selected.get('server_vmid')) is int and selected['server_vmid'] >= 100,
            'Preserve the explicit monitoring server identity')
    return {'node': cfg['site']['node'], 'vmid': selected['server_vmid'], 'hostname': hostname}


def _leaf(selected, key, filename):
    path = selected.get(key)
    require(isinstance(path, str) and Path(path).is_absolute() and '..' not in Path(path).parts
            and Path(path).name == filename,
            'Use the selected immutable monitoring payload leaf')


def prepare(cfg, *, app=None, agent=False):
    """Materialize only the agent, storage DB, or selected root server inputs."""
    require(type(agent) is bool, 'Select an explicit monitoring preparation phase')
    selected = cfg['app'].get('monitoring')
    if selected is None:
        return {}
    require(isinstance(selected, dict) and (app is None if agent else isinstance(app, dict)),
            'Select either this guest agent or one owned application')
    if not agent:
        require(isinstance(app.get('adapter'), str) and isinstance(app.get('id'), str)
                and sum(row.get('id') == app['id'] and row.get('adapter') == app['adapter']
                        for row in cfg['deployment']['applications'].values()) == 1,
                'Bind only this guest selected application identity')
        storage = app['adapter'] == 'postgresql' and 'storage_password_file' in selected
        server = app['adapter'] == 'zabbix' and app.get('settings', {}).get('database_credential') == {
            'type': 'monitoring-owned', 'server': app['id']}
        if not storage and not server:
            return {}
    else:
        storage = server = False
    owner = _server_owner(cfg, selected)
    if storage:
        _leaf(selected, 'storage_password_file', 'monitoring-storage-password')
    if server:
        require(owner == owned.identity(cfg) and {'members', 'proxmox', 'server_file'} <= set(selected),
                'Only the selected monitoring server may prepare its member/admin records')
        _leaf(selected, 'server_file', 'monitoring-server.json')
    if agent:
        _leaf(selected, 'credential_file', 'monitoring-agent.json')
        require(isinstance(selected.get('profiles'), list), 'Preserve selected agent workload profiles')
        if set(selected['profiles']) & {'postgresql', 'mysql'}:
            _leaf(selected, 'database_password_file', 'monitoring-database-password')
    # Existing owner/READY/HOLD/token admission runs before any create-once key.
    access = owned.provider(cfg)
    root = Path(cfg['paths']['state_root'])/'monitoring-credentials'
    private_directory(root.parent)
    if agent:
        member = {'vmid': cfg['guest']['vmid'], 'guest_hostname': cfg['guest']['hostname']}
        result = {'monitoring-agent.json': encoded({'psk': owned.agent(root, member, cfg['site']['node'])})}
        if set(selected['profiles']) & {'postgresql', 'mysql'}:
            values = owned.credential(root, 'database-'+str(cfg['guest']['vmid'])+'.json',
                                      owned.identity(cfg), ['password'])
            result['monitoring-database-password'] = values['password'].encode()
        return result
    shared = owned.credential(root, 'server-'+str(selected['server_vmid'])+'.json', owner,
                              ['database_password', 'admin_password'])
    if storage:
        return {'monitoring-storage-password': shared['database_password'].encode()}
    members = [{**member, 'psk': owned.agent(root, member, cfg['site']['node'])}
               for member in selected['members']]
    return {'database-password': shared['database_password'].encode(),
            'proxmox-ca.pem': regular(Path(cfg['paths']['ca_file'])),
            'monitoring-server.json': encoded({'admin_password': shared['admin_password'],
                'members': members, 'proxmox': {**selected['proxmox'], 'token_id': owned.TOKEN_ID,
                    'token_secret': access['token'].split('=', 1)[1]}})}
