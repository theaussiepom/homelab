"""Closed component packet receiver; runtime/deployment remains stdlib-only."""
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import network_endpoints
from application_contract import ADAPTERS,ordered_services
from private_io import require

PACKET_SCHEMA = 'homelab-component-guest-deployment-v1'
CONFIG_SCHEMA = 'homelab-component-guest-v1'
AGENT_PHASE = 'zabbix-agent'
RESERVED = {'infrastructure', 'preparation', AGENT_PHASE, 'validate', 'selection', 'agent'}


def identifier(value):
    return isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', value)


def path(value):
    require(isinstance(value, str) and value.startswith('/') and not value.startswith('//') and str(Path(value)) == value
            and not any(part in ('.', '..') for part in value.split('/'))
            and not any(char in value for char in '$\\')
            and not any(ord(char) < 32 or ord(char) == 127 for char in value),
            'Use literal component controller paths')
    return Path(value)


def phases(cfg):
    deployment = cfg['deployment']
    require(deployment['contract'] == 3 and isinstance(deployment['applications'], dict)
            and isinstance(deployment['payload_phases'], dict), 'Use component deployment contract three')
    selected = deployment['phases']
    applications = deployment['applications']
    require(isinstance(selected, list) and selected and selected[0] == 'preparation'
            and all(identifier(value) for value in selected) and len(selected) == len(set(selected)),
            'Use an explicit ordered component phase list')
    monitored = 'monitoring' in cfg['app']
    require(set(selected) == {'preparation', *applications} | ({AGENT_PHASE} if monitored else set())
            and (not monitored or selected[-1] == AGENT_PHASE)
            and set(deployment['payload_phases']) == set(applications) | ({AGENT_PHASE} if monitored else set()),
            'Bind every component phase exactly once')
    ids = []
    for phase, row in applications.items():
        require(identifier(phase) and phase not in RESERVED and isinstance(row, dict)
                and set(row) in ({'id', 'adapter', 'lifecycle', 'runtime_id'},
                    {'id', 'adapter', 'lifecycle', 'runtime_id', 'project', 'compose_file', 'services'})
                and identifier(row['id']) and row['lifecycle'] in ('fresh', 'retained')
                and deployment['payload_phases'][phase] == row['id'],
                'Bind selected application phases to stable owned identities')
        require(row['adapter'] in ADAPTERS and ('services' in row) == bool(ADAPTERS[row['adapter']]['services']),
                'Bind native or container phase shape to its actual app adapter')
        ids.append(row['id'])
    require(len(ids) == len(set(ids)) and set(cfg['app']['service_health_checks']) == set(applications)
            and all(cfg['app']['service_health_checks'].values()), 'Preserve each selected app health contract')
    require(not monitored or deployment['payload_phases'][AGENT_PHASE] == 'agent',
            'Bind the explicit monitoring agent payload')
    return selected[:]


def validate(cfg):
    require(isinstance(cfg, dict) and cfg.get('schema') == CONFIG_SCHEMA
            and {'schema', 'site', 'guest', 'ssh_public_keys', 'paths', 'deployment', 'app'} <= set(cfg)
            <= {'schema', 'site', 'guest', 'ssh_public_keys', 'paths', 'deployment', 'app', 'routes'},
            'Use an explicit versioned component guest configuration')
    deployment, app, guest = cfg['deployment'], cfg['app'], cfg['guest']
    require('exclusive_writer_confirmed' not in app and 'coordinated_custody_inputs' not in cfg['paths'],
            'Retire authored migration assertions; validate genuine ordinary ownership')
    require(isinstance(deployment, dict) and set(deployment) == {'contract', 'capabilities',
        'input_identity', 'input_directory', 'runtime_file', 'lifecycle', 'protected_guests',
        'applications', 'payload_phases', 'phases'},
        'Use only the component deployment contract fields')
    require(re.fullmatch('[0-9a-f]{64}', deployment['input_identity']) and
            deployment['lifecycle'] in ('fresh', 'retained') and
            deployment['capabilities'] in (['linux'], ['linux', 'docker']),
            'Bind component identity, lifecycle and capabilities')
    require(isinstance(deployment['protected_guests'], list) and
            all(type(value) is int and value >= 1 for value in deployment['protected_guests']) and
            len(set(deployment['protected_guests'])) == len(deployment['protected_guests']),
            'Preserve the explicit execution context protected guests')
    vmid = guest['vmid']
    require(type(vmid) is int and vmid >= 100 and vmid not in deployment['protected_guests']
            and app['vmid'] == vmid and app['hostname'] == guest['hostname']
            and app['memory_mib'] == guest['memory_mib'], 'Bind one unprotected component guest')
    addresses = network_endpoints.addresses(guest)
    require(app['address'] in addresses and any(str(network_endpoints.interface(nic).ip) == app['address']
            and nic['mac'].lower() == app['mac'].lower() for nic in guest['interfaces'] if nic['ipv4'] != 'manual'),
            'Bind the explicit control interface address and MAC')
    require(isinstance(app['packages'], list) and all(isinstance(value, str) and re.fullmatch(
        '[a-z0-9][a-z0-9+.-]*=[0-9][A-Za-z0-9.+:~\\-]*', value) for value in app['packages']),
        'Use declared exact component packages')
    endpoint = urlsplit(cfg['site']['api_endpoint'])
    require(endpoint.scheme == 'https' and endpoint.hostname and endpoint.port == 8006
            and not endpoint.username and not endpoint.password and not endpoint.query
            and not endpoint.fragment and endpoint.path in ('', '/'), 'Use the declared trusted PVE endpoint')
    for key, value in cfg['paths'].items():
        if key != 'backup_source':
            path(value)
    directory = path(deployment['input_directory'])
    require(path(deployment['runtime_file']) == directory/'component-runtime.json',
            'Bind the actual component runtime input file')
    phases(cfg)
    return vmid


def packet(value, inputs):
    require(isinstance(value, dict) and set(value) == {'schema', 'guest', 'enabled', 'identity', 'files'}
            and value['schema'] == PACKET_SCHEMA and value['enabled'] is True
            and identifier(value['guest']) and re.fullmatch('[0-9a-f]{64}', value['identity'])
            and isinstance(value['files'], dict) and all(isinstance(name, str) and
                re.fullmatch('[a-z][a-z0-9_.-]{0,127}', name) and isinstance(raw, str)
                for name, raw in value['files'].items()), 'Enable one reviewed component packet')
    require({'site.json', 'component-runtime.json'} <= set(value['files']), 'Include actual component engine inputs')
    cfg = json.loads(value['files']['site.json'])
    validate(cfg)
    directory = Path(inputs)/value['guest']/value['identity']
    require(cfg['deployment']['input_identity'] == value['identity'] and
            cfg['deployment']['input_directory'] == str(directory), 'Bind immutable component input location')
    runtime = json.loads(value['files']['component-runtime.json'])
    require(runtime.get('schema') == 'homelab-component-runtime-v1' and runtime['guest']['id'] == value['guest']
            and set(runtime['applications']) == {row['id'] for row in cfg['deployment']['applications'].values()}
            and all('private_environment' not in app for app in runtime['applications'].values()),
            'Keep actual runtime applications and private values in their declared boundaries')
    for row in cfg['deployment']['applications'].values():
        app = runtime['applications'][row['id']]
        require(app['adapter'] == row['adapter'] and app['lifecycle'] == row['lifecycle']
                and app['identity']['runtime_id'] == row['runtime_id']
                and app['identity']['phase'] in cfg['deployment']['applications']
                and cfg['deployment']['applications'][app['identity']['phase']] == row,
                'Bind each compiled phase to its actual runtime application')
        for storage in app.get('storage_paths',{}).values():
            if app['lifecycle']=='fresh' and 'initialize' in storage:
                root=storage.get('volume_root')
                require(root in {volume['path'] for volume in cfg['guest'].get('volumes',{}).values()}
                        and path(root) in path(storage['source']).parents,
                        'Bind fresh initialization beneath its actual provider volume')
        if 'services' in row:
            require(isinstance(row['compose_file'],str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}\\.ya?ml',row['compose_file'])
                    and row['compose_file'] in value['files']
                    and row['project'] == app['project_name'] and row['compose_file'] == app['project_file']
                    and row['services'] == ordered_services(app),
                    'Bind actual runtime services and file identity')
    return cfg, directory
