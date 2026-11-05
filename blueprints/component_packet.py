"""Compile resolved components to versioned inputs consumed by the native engines."""
import copy
import hashlib
import json
from pathlib import Path

import component_checks
import component_runtime
import component_routes
import component_native
import managed_credentials
from component_adapters import adapter,ordered_services
from component_lower import provider_config, runtime_config
from component_sources import require
from component_errors import ComponentError
from private_io import encoded
from component_workflows import application_order

PACKET_SCHEMA = 'homelab-component-guest-deployment-v1'
CONFIG_SCHEMA = 'homelab-component-guest-v1'
INPUTS = Path('/var/lib/homelab-inputs/ordinary')


def _account_paths(runtime, directory):
    """Bind only compiler-owned credential slots, never authored string values."""
    for app_id, app in runtime['applications'].items():
        selected = list(app.get('database_administrators', {}).values())
        if app['adapter'] == 'cloudbeaver':
            selected += list(app['settings']['managed_connections'].values())
        broker = app.get('settings', {}).get('broker', {})
        if 'managed_credential' in broker:
            selected.append(broker['managed_credential'])
        for row in selected:
            filename = managed_credentials.input_name(row['credential_id'])
            require(row['credential_file'] == '${inputs}/applications/' + app_id + '/' + filename,
                    'component.credential-slot')
            row['credential_file'] = str(directory / 'applications' / app_id / filename)


def _credential(plan, context, role):
    selected = plan.site['secret_sources'][context['credentials'][role]]
    require(selected['type'] == 'file', 'component.context-file-credential')
    return selected['path']


def lower_guest(plan, guest_id, *, inputs=INPUTS):
    plan.check()
    require(guest_id in plan.resolved['guests'], 'component.reference')
    guest = plan.resolved['guests'][guest_id]
    context = plan.resolved['contexts'][guest['context']]
    provider = provider_config(plan, guest_id)
    runtime = runtime_config(plan, guest_id)
    try:
        artifacts=component_runtime.artifacts(runtime)
    except component_native.NativeNamespaceError:
        raise ComponentError('component.native-namespace',('guests',guest_id,'native'))from None
    files = {name: raw.decode() for name, raw in artifacts.items()}
    software = guest['software_selection']
    repositories = []
    for row in software['repositories']:
        name = 'repository-' + row['name'] + '.asc'
        asset = plan.library['assets'][row['key_asset']]
        require(name not in files and asset['type'] == 'raw-utf8', 'component.artifact-conflict')
        files[name] = asset['text']
        repositories.append({'name': row['name'], 'source': row['source'],
            'key_path': '${inputs}/' + name, 'key_sha256': asset['sha256']})
    ordered = application_order(plan, guest_id)
    checks, payload_phases, applications, required = {}, {}, {}, {}
    for app_id in ordered:
        app = runtime['applications'][app_id]
        phase = app['identity']['phase']
        compose = '/opt/homelab-app/' + app['project_file'] if 'project_file' in app else None
        selected = component_checks.checks(app, runtime['guest'], compose_file=compose)
        require(bool(selected), 'component.health-required')
        checks[phase] = selected
        payload_phases[phase] = app_id
        applications[phase] = {'id': app_id, 'adapter': app['adapter'], 'lifecycle': app['lifecycle'],
            'runtime_id': app['identity']['runtime_id'],
            **({'project': app['project_name'], 'compose_file': app['project_file'],
                'services': ordered_services(app)} if compose else {})}
        for row in app['storage_paths'].values():
            if app['lifecycle'] == 'fresh' and 'initialize' in row:
                continue
            expected = {'path': row['source'], 'type': row['kind']}
            require(row['source'] not in required or required[row['source']] == expected,
                    'component.storage-conflict')
            required[row['source']] = expected
    capabilities = ['linux'] + (['docker'] if any(adapter(app['adapter'])['services']
        for app in runtime['applications'].values()) else [])
    cfg = {'schema': CONFIG_SCHEMA, **provider, 'routes': component_routes.provider_routes(plan, guest_id),
        'paths': {**copy.deepcopy(context['paths']), 'ca_file': context['trust']['ca_file'],
            'known_hosts': context['trust']['known_hosts'],
            'api_token': _credential(plan, context, 'api_token'),
            'private_key': _credential(plan, context, 'ssh_private_key')},
        'deployment': {'contract': 3, 'capabilities': capabilities,
            'input_identity': '${input_identity}', 'input_directory': '${inputs}',
            'runtime_file': '${inputs}/component-runtime.json', 'lifecycle': guest['lifecycle'],
            'protected_guests': copy.deepcopy(context['protected_guests']),
            'applications': applications, 'payload_phases': payload_phases,
            'phases': ['preparation', *checks]},
        'app': {'vmid': guest['identity']['vmid'],
            'hostname': guest['identity']['hostname'], 'memory_mib': guest['resources']['memory_mib'],
            'address': guest['control']['address'], 'mac': guest['control']['mac'],
            'packages': copy.deepcopy(software['packages']), 'repositories': repositories,
            'required_paths': list(required.values()), 'service_health_checks': checks,
            'health_checks': [row for rows in checks.values() for row in rows]}}
    if 'frontend_routing' in guest:
        cfg['app']['frontend_routing'] = copy.deepcopy(guest['frontend_routing'])
    if 'monitoring' in guest:
        cfg['app']['monitoring'] = copy.deepcopy(guest['monitoring'])
        cfg['deployment']['payload_phases']['zabbix-agent'] = 'agent'
        cfg['deployment']['phases'].append('zabbix-agent')
    if 'serial_device' in provider['guest']:
        devices = [plan.site['devices'][ref] for app in plan.resolved['apps'].values()
                   if app['guest'] == guest_id for ref in app.get('devices', {}).values()]
        capability = context['capabilities'][devices[0]['capability']]
        source = plan.site['secret_sources'][capability['ssh_private_key']]
        require(source['type'] == 'file', 'component.context-file-credential')
        cfg['paths'].update(host_device_key=source['path'], host_known_hosts=capability['known_hosts'])
    # Identity binds the abstract slot, including source/public desired artifacts.
    identity = hashlib.sha256(encoded({'config': cfg, 'runtime': runtime, 'files': files})).hexdigest()
    directory = Path(inputs) / guest_id / identity
    cfg['deployment'].update(input_identity=identity, input_directory=str(directory),
                             runtime_file=str(directory / 'component-runtime.json'))
    for row in cfg['app']['repositories']:
        row['key_path'] = str(directory / ('repository-' + row['name'] + '.asc'))
    for key in ('credential_file', 'database_password_file', 'storage_password_file', 'server_file'):
        if key in cfg['app'].get('monitoring', {}):
            value = cfg['app']['monitoring'][key]
            require(value.startswith('${inputs}/') and Path(value).name == value.removeprefix('${inputs}/'),
                    'component.monitoring-input-slot')
            owner='agent'
            if key=='storage_password_file':
                owners=[key for key,app in runtime['applications'].items() if app['adapter']=='postgresql'
                        and 'monitoring_hba_source' in app]
                require(len(owners)==1,'component.monitoring-input-owner')
                owner=owners[0]
            if key=='server_file':
                owner=plan.resolved['monitoring']['server']
                require(owner in runtime['applications'],'component.monitoring-input-owner')
            cfg['app']['monitoring'][key] = str(directory/'applications'/owner/Path(value).name)
    _account_paths(runtime, directory)
    if 'component-native.json' in files:
        native = json.loads(files['component-native.json'])
        for app in native.values():
            for row in app['identity']['config_files']:
                value = row['source']
                require(value.startswith('${inputs}/') and Path(value).name == value.removeprefix('${inputs}/'),
                        'component.native-input-slot')
                row['source'] = str(directory / Path(value).name)
        files['component-native.json'] = encoded(native).decode()
    files['component-runtime.json'] = encoded(runtime).decode()
    files['site.json'] = encoded(cfg).decode()
    return {'schema': PACKET_SCHEMA, 'guest': guest_id,
            'enabled': guest_id in plan.resolved['enabled'], 'identity': identity, 'files': files}


def lower_plan(plan, *, inputs=INPUTS):
    plan.check()
    return {guest_id: lower_guest(plan, guest_id, inputs=inputs) for guest_id in plan.resolved['guests']}
