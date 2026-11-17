"""Restore and inspect deployment-managed controls through the Ansible owner."""
import os
import base64
import json
from pathlib import Path

import component_ansible
import component_control
import component_ssh
from component_payload import AppPayload
from private_io import digest, encoded, private_directory, read_json, regular, require, write, sha

SOURCE = Path(__file__).resolve().parent


def verify_inventory(selection, captured):
    require(isinstance(captured, dict) and isinstance(captured.get('files'), dict)
            and set(captured['files']) == set(selection['files']),
            'Saved control inventory differs; reconcile before adopting new managed controls')


def descriptor(owner, cfg):
    """Derive only fixed owned control leaves, exact packages and service IDs."""
    import component_generation
    selected, _ = component_generation.sealed_inputs(owner['binding'])
    require(selected == cfg, 'Restore exactly the verified sealed configuration')
    directory = Path(cfg['deployment']['input_directory'])
    files, expected, metadata, projects, units, images, health, native_files = {}, {}, {}, {}, set(), [], [], []

    def source(path, target, *, uid=0, gid=0, mode=0o600):
        path = Path(path)
        raw = regular(path, limit=component_control.MAX_BYTES)
        files[target] = None
        expected[target] = digest(raw)
        metadata[target] = {key: value for key, value in {'uid': uid, 'gid': gid, 'mode': mode}.items()
                            if value is not None}

    for phase, proof in owner['phase_inputs'].items():
        if proof is None:
            continue
        payload = AppPayload.load(Path(owner['binding']['app_inputs_directory'])/proof['app'], proof)
        if phase in ('zabbix-agent', 'pbs-agent'):
            continue  # Agent settings are inspected separately, never restored here.
        values = component_ansible.variables(cfg, phase, payload=payload, previously_owned=True)
        app = values['component_application']
        for row in values['component_runtime_files']:
            source(payload.directory/row['source'], row['destination'],
                   uid=row['uid'], gid=row['gid'], mode=int(row['mode'], 8))
        for row in values['component_helpers']:
            source(SOURCE/row['source'], row['destination'], mode=int(row['mode'], 8))
        if 'component_compose_file' in values:
            source(SOURCE/'component-preflight.py', '/usr/local/bin/homelab-component-preflight.py', mode=0o700)
            source(values['component_compose_source'], values['component_compose_file'])
            args = ['docker', 'compose', '-f', values['component_compose_file']]
            if 'component_environment_file' in values:
                source(values['component_environment_source'], values['component_environment_file'])
                args += ['-f', values['component_environment_file']]
            key = tuple(args)
            projects.setdefault(key, [])
            projects[key].extend(values['component_services'])
            for role, image in app['software_selection'].get('images', {}).items():
                images.append({'project': app['project_name'],
                               'service': app['identity']['services'][role], 'image': image['image']})
        else:
            native = values['app']['database']
            for row in native['config_files']:
                source(row['source'].replace('${inputs}', str(directory)), row['destination'],
                       uid=native.get('uid'), gid=native.get('gid'))
                native_files.append({'path': row['destination'], 'user': native['user'], 'group': native['group']})
            units.update(values['component_native_services'])
        health.extend(values['app']['health_checks'])
    # These fixed helpers are touched by ordinary preparation, never app data.
    if 'frontend_routing' in cfg['app']:
        source(SOURCE/'ingress_routing.py', '/opt/homelab-app/ingress-routing.py', mode=0o700)
        files['/opt/homelab-app/frontend-routing.json'] = None
        files['/etc/systemd/system/homelab-frontend-routing.service'] = None
    result = {'files': files, 'expected': expected, 'metadata': metadata, 'packages': cfg['app'].get('packages', []),
            'images': images, 'units': sorted(units), 'health': health, 'native_files': native_files,
            'projects': [{'argv': list(argv), 'services': list(dict.fromkeys(services))}
                         for argv, services in projects.items()]}
    if cfg['ssh_public_keys']:
        files[component_ssh.ROOT_KEYS] = None
        metadata[component_ssh.ROOT_KEYS] = {'uid': 0, 'gid': 0}
        result['root_ssh_keys'] = cfg['ssh_public_keys'].copy()
    return result


def agent_descriptor(owner, cfg):
    """Verify installed agent settings and retained credentials without applying them."""
    import backup_agent
    import monitoring_paths
    files, expected, metadata, named, semantic, absent, packages, health = {}, {}, {}, [], {}, [], [], []

    def control(target, raw=None, *, mode=0o600, user='root', group='root', value=None):
        files[target] = None
        metadata[target] = {'mode': mode}
        named.append({'path': target, 'user': user, 'group': group, 'mode': f'{mode:04o}'})
        if raw is not None:
            expected[target] = digest(raw)
        if value is not None:
            semantic[target] = value

    for phase in ('pbs-agent', 'zabbix-agent'):
        proof = owner['phase_inputs'].get(phase)
        if proof is None:
            continue
        payload = AppPayload.load(Path(owner['binding']['app_inputs_directory'])/proof['app'], proof)
        values = component_ansible.variables(cfg, phase, payload=payload, previously_owned=True)
        if phase == 'pbs-agent':
            control('/etc/homelab-backup/coverage.json', values['backup_agent']['inventory'].encode())
            control('/opt/homelab-backup/OWNER.json', value={'schema': 'homelab-backup-source-v1'})
            for name, raw in backup_agent.verify_inputs(cfg['app']['backup'], payload).items():
                if name != 'application.json':
                    control('/etc/homelab-backup/'+name, raw)
        else:
            paths = monitoring_paths.PATHS
            control(paths['configuration'], values['monitoring_agent_configuration'].encode(), mode=0o640, group='zabbix')
            control(paths['key'], (read_json(payload.directory/'monitoring-agent.json', private=True)['psk']+'\n').encode(),
                    mode=0o400, user='zabbix', group='zabbix')
            control(paths['receipt'], value={**{key: cfg['app']['monitoring'][key] for key in ('hostname', 'psk_identity')},
                                            'version': values['monitoring_agent_package']['version']})
            files[paths['hold']] = None; absent.append(paths['hold'])
            packages.append('zabbix-agent2='+values['monitoring_agent_package']['version'])
            if 'postgresql' in cfg['app']['monitoring']['profiles']:
                packages.append('zabbix-agent2-plugin-postgresql='+values['monitoring_postgresql_package']['version'])
            health.append({'argv': ['systemctl', 'is-active', '--quiet', 'zabbix-agent2']})
    return {'files': files, 'expected': expected, 'metadata': metadata, 'native_files': named,
            'json': semantic, 'absent': absent, 'packages': packages, 'health': health,
            'projects': [], 'images': [], 'units': []}


def verify_agents(owner, cfg, operation):
    """Locally prepared payloads do not prove the guest installed their settings."""
    selection = agent_descriptor(owner, cfg)
    if selection['files']:
        expected(selection, execute(cfg, operation, selection, mode='capture'))


def execute(cfg, operation, selection, *, mode, captured=None, allowed=None):
    """No fresh provisioning or database/schema action is present in this playbook."""
    import proxmox_guest
    from ansible_guest import ansible_environment
    require(mode in ('capture', 'restore', 'verify'), 'Select one fixed managed-control operation')
    if mode != 'capture':
        verify_inventory(selection, captured)
    proxmox_guest.guest_trust(cfg, Path(cfg['paths']['state_root'])/str(cfg['guest']['vmid']), persist=False)
    from component_recovery import attempt_directory
    folder = attempt_directory(operation, 'controls-'+mode)
    request = {'mode': 'capture' if mode == 'capture' else 'verify',
               'files': selection['files'] if mode == 'capture' else captured['files'],
               'packages': selection['packages'],
               'images': selection['images'] if mode == 'capture' else captured['images'], 'allowed': {}}
    restore = {'mode': 'restore', 'files': captured['files'] if captured else {},
               'packages': [], 'images': captured['images'] if captured else [], 'allowed': allowed or {}}
    variables = {'recovery_app': cfg['app'], 'recovery_mode': mode,
                 'recovery_program': base64.b64encode(Path(component_control.__file__).read_bytes()).decode(),
                 'recovery_request': request, 'recovery_restore': restore,
                 'recovery_packages': captured['packages'] if captured else [],
                 'recovery_projects': selection['projects'], 'recovery_units': selection['units'],
                 'recovery_native_files': selection['native_files'],
                 'recovery_health': selection['health'], 'recovery_output': str(folder/'result.json')}
    if 'root_ssh_keys' in selection:
        metadata = None if mode == 'capture' else {
            key: captured['files'][component_ssh.ROOT_KEYS][key] for key in ('uid', 'gid', 'mode')}
        variables['recovery_root_keys'] = component_ssh.transport(
            selection['root_ssh_keys'], mode='verify', metadata=metadata)
        if mode == 'restore':
            restore['metadata'] = {component_ssh.ROOT_KEYS: metadata}
    write(folder/'variables.json', variables)
    write(folder/'inventory.json', {'application': {'hosts': {cfg['app']['hostname']: {
        'ansible_host': cfg['app']['address'], 'ansible_user': 'root'}}}})
    args = ['ansible-playbook', '-i', str(folder/'inventory.json'), '--private-key',
            cfg['paths']['private_key'], str(SOURCE/'ansible/component-rollback.yml'),
            '--extra-vars', '@'+str(folder/'variables.json')]
    environment = {key: value for key, value in os.environ.items()
                   if key != 'PBS_API_TOKEN' and not key.startswith('HOMELAB_APP_SECRET_')}
    component_ansible.quiet(args, ansible_environment(cfg, environment), folder/'application.log')
    result = read_json(folder/'result.json', private=True)
    require(isinstance(result, dict) and set(result) == {'files', 'packages', 'images'}
            and set(result['files']) == set(selection['files']), 'Account for every managed control')
    if mode != 'capture':
        require(result['files'] == captured['files'] and result['packages'] == captured['packages'],
                'Restored configuration and package versions must match the selected baseline')
        require(captured.get('images', result['images']) == result['images'],
                'Restored containers must use the exact previous image identities')
    return result


def expected(selection, captured):
    """Read-only reconciliation compares installed controls with selected source."""
    if 'root_ssh_keys' in selection:
        component_ssh.verify(captured['files'][component_ssh.ROOT_KEYS], selection['root_ssh_keys'])
    for path, wanted in selection['expected'].items():
        row = captured['files'][path]
        require(row.get('exists') and row['sha256'] == wanted,
                'Installed managed configuration differs from selected source')
    for path, wanted in selection.get('json', {}).items():
        row = captured['files'][path]
        require(row.get('exists') and json.loads(base64.b64decode(row['content'], validate=True)) == wanted,
                'Installed agent ownership differs from selected source')
    for path, wanted in selection['metadata'].items():
        require(all(captured['files'][path].get(key) == value for key, value in wanted.items()),
                'Installed managed configuration permissions differ from selected source')
    require(all(captured['files'][path] == {'exists': False} for path in selection.get('absent', [])),
            'An interrupted monitoring installation requires engineer repair')
    for wanted, actual in zip(selection['packages'], captured['packages'], strict=True):
        require('=' not in wanted or wanted == actual, 'Installed package differs from selected source')
    return captured
