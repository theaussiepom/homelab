"""Optional browser client with a file-only authenticated, unpublished backend."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import discovery
import managed_credentials
from private_io import read_json, require

DATA = '/srv/homelab/data/mqtt-explorer'
SERVICES = {'mqtt_explorer', 'explorer_gateway'}
RUNTIME = '/opt/homelab-app/runtime/'


def validate(cfg, *, compiled=False):
    value = cfg.get('mqtt_explorer')
    require(cfg.get('kind') == 'mqtt' or 'mqtt_explorer' not in cfg,
            'MQTT Explorer belongs to the selected broker guest')
    if 'mqtt_explorer' not in cfg:
        return None
    require(isinstance(value, dict) and set(value) - ({'broker_connection', 'broker_address'} if compiled else {'broker_connection'}) == {
        'public_url', 'bind_address', 'authentik_outpost_url', 'data_path'},
        'Use the closed MQTT Explorer configuration')
    require(value['data_path'] == DATA, 'Keep Explorer data separate from retained broker data')
    public = value['public_url']
    require(isinstance(public, str) and len(public) <= 2048 and not any(c.isspace() for c in public)
            and not any(c in public for c in '\\?#'), 'Use a credential-free canonical HTTPS URL')
    try:
        url = urlsplit(public)
        require(url.scheme == 'https' and not url.username and not url.password and url.port in (None, 443)
                and url.path in ('', '/'), 'Use a canonical HTTPS origin on port443')
        discovery.hostname(url.hostname)
        address = ipaddress.IPv4Address(value['bind_address'])
    except (ValueError, TypeError):
        raise ValueError('Use selected Explorer HTTPS and private listener addresses') from None
    require(address.is_private and not (address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_unspecified), 'Bind only the assigned private backend address')
    discovery.origin(value['authentik_outpost_url'])
    require(set(cfg.get('services', {})) == {'mqtt', *SERVICES},
            'Keep the broker and exactly the two Explorer services')
    for name in SERVICES:
        service = cfg['services'][name]
        require(isinstance(service, dict) and not service.get('environment') and not any(key in service for key in (
            'user', 'command', 'entrypoint', 'extra_mounts', 'extra_hosts', 'ports', 'network_mode',
            'cap_add', 'privileged', 'security_opt')), 'Generate Explorer placement and authentication without overrides')
    if 'broker_connection' in value:
        broker = value['broker_connection']
        require(isinstance(broker, dict) and set(broker) == {'name', 'hostname', 'port', 'username',
                'credential_id', 'credential_file', 'password_file', 'access'},
                'Select one dedicated managed Explorer broker account')
        require(isinstance(broker['name'], str) and 1 <= len(broker['name']) <= 100
                and not any(c in broker['name'] for c in '\r\n\x00')
                and type(broker['port']) is int and broker['port'] == 1883
                and isinstance(broker['username'], str) and re.fullmatch('[a-z][a-z0-9_]{2,31}', broker['username'])
                and broker['access'] == 'read-write-all', 'Declare the dedicated broker account and access')
        discovery.hostname(broker['hostname'])
        managed_credentials.identifier(broker['credential_id'])
        require(isinstance(broker['credential_file'], str)
                and (Path(broker['credential_file']).is_absolute() or broker['credential_file'].startswith('${inputs}/'))
                and '..' not in Path(broker['credential_file']).parts
                and Path(broker['credential_file']).name == managed_credentials.input_name(broker['credential_id'])
                and isinstance(broker['password_file'], str)
                and re.fullmatch('/mosquitto/config/[A-Za-z0-9_.-]{1,100}', broker['password_file'])
                and Path(broker['password_file']).name not in {'.', '..'},
                'Bind fixed private account input and selected broker password file')
    if 'broker_address' in value:
        require('broker_connection' in value and isinstance(value['broker_address'], str),
                'Derive the broker address only for its saved connection')
        address = ipaddress.IPv4Address(value['broker_address'])
        require(address.is_private and not (address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_unspecified), 'Use the derived private broker listener')
    return value


def prepare(cfg, stack, destination):
    value = validate(stack, compiled=True)
    if value is None or 'broker_connection' not in value:
        return {}
    broker = value['broker_connection']
    owner = {'node': cfg['site']['node'], 'vmid': cfg['guest']['vmid'], 'hostname': cfg['guest']['hostname'],
             'purpose': 'mqtt-explorer', 'username': broker['username']}
    path, result = managed_credentials.payload(cfg['paths']['state_root'], broker['credential_id'], owner, destination)
    require(broker['credential_file'] == path, 'Bind the generated account to its immutable ordinary input')
    return result


def source_files(cfg):
    value = validate(cfg, compiled=True)
    return [value['broker_connection']['credential_file']] if value is not None and 'broker_connection' in value else []


def configuration(value):
    host = urlsplit(value['public_url']).hostname
    outpost = value['authentik_outpost_url'].rstrip('/')
    static = {'entryPoints': {'web': {'address': ':4180'}, 'health': {'address': '127.0.0.1:8082'}},
        'ping': {'entryPoint': 'health'}, 'providers': {'file': {'filename': '/etc/traefik/explorer.yml', 'watch': True}},
        'log': {'level': 'INFO'}}
    canonical = {'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': host, 'X-Forwarded-Port': '443',
                 'X-Forwarded-Uri': '', 'X-Forwarded-Method': '', 'X-Forwarded-For': ''}
    for name in ('X-Authentik-Username', 'X-Authentik-Groups', 'X-Authentik-Email',
                 'X-Authentik-Name', 'X-Authentik-Uid'):
        canonical[name] = ''
    common = ['canonical', 'security']
    dynamic = {'http': {'routers': {
        'explorer': {'rule': 'Host(`'+host+'`)', 'entryPoints': ['web'], 'priority': 10,
            'service': 'explorer', 'middlewares': [*common, 'authentik']},
        'outpost': {'rule': 'Host(`'+host+'`) && PathPrefix(`'+discovery.AUTHENTIK_PREFIX+'`)',
            'entryPoints': ['web'], 'priority': 20, 'service': 'outpost', 'middlewares': common}},
        'middlewares': {'canonical': {'headers': {'customRequestHeaders': canonical}},
            'security': {'headers': {'contentTypeNosniff': True, 'frameDeny': True}},
            'authentik': {'forwardAuth': {'address': outpost+discovery.AUTHENTIK_AUTH_PATH,
                'trustForwardHeader': True}}},
        'services': {'explorer': {'loadBalancer': {'servers': [{'url': 'http://mqtt_explorer:3000'}]}},
                     'outpost': {'loadBalancer': {'servers': [{'url': outpost}]}}}}}
    return static, dynamic


def files(cfg):
    value = validate(cfg, compiled=True)
    if value is None:
        return []
    static, dynamic = configuration(value)
    rows = [{'path': name, 'content': json.dumps(document, sort_keys=True)+'\n',
             'uid': 65532, 'gid': 65532, 'mode': '0400'}
            for name, document in [('explorer-traefik.json', static), ('explorer-routes.yml', dynamic)]]
    public = {**value, 'images': {name: cfg['services'][name]['image'] for name in SERVICES},
        'runtime_sha256': {row['path']: hashlib.sha256(row['content'].encode()).hexdigest() for row in rows}}
    if 'broker_connection' in value:
        broker = value['broker_connection']
        credential = read_json(Path(broker['credential_file']), private=True)
        require(isinstance(credential, dict) and set(credential) == {'schema', 'owner', 'password'}
                and credential['schema'] == 'homelab-application-account-v1'
                and isinstance(credential['owner'], dict)
                and credential['owner'].get('purpose') == 'mqtt-explorer'
                and credential['owner'].get('username') == broker['username']
                and isinstance(credential['password'], str) and re.fullmatch('[0-9a-f]{64}', credential['password']),
                'Use the owned dedicated Explorer account credential')
        rows.append({'path': 'mqtt-explorer-account.json', 'uid': 0, 'gid': 0, 'mode': '0600',
            'content': json.dumps({'connection': {k: v for k, v in broker.items() if k != 'credential_file'},
                'credential': credential, 'image': cfg['services']['mqtt']['image']}, sort_keys=True)+'\n'})
    return [*rows, {'path': 'mqtt-explorer-public.json', 'content': json.dumps(public, sort_keys=True)+'\n',
                   'uid': 0, 'gid': 0, 'mode': '0400'}]


def configure(cfg, document):
    value = validate(cfg, compiled=True)
    if value is None:
        return document
    document['networks'] = {'explorer': {}}
    for name in SERVICES:
        service = document['services'][name]
        service.pop('network_mode')
        service.update(networks=['explorer'], cap_drop=['ALL'], security_opt=['no-new-privileges:true'], read_only=True)
    app = document['services']['mqtt_explorer']
    if 'broker_address' in value:
        app['extra_hosts'] = {value['broker_connection']['hostname']: value['broker_address']}
    app['user'] = '1001:1001'
    app['environment'] = {'NODE_ENV': 'production', 'PORT': '3000', 'NODE_OPTIONS': '--max-old-space-size=128',
        'MQTT_EXPLORER_SKIP_AUTH': 'true', 'ALLOWED_ORIGINS': 'https://'+urlsplit(value['public_url']).hostname,
        'UPGRADE_INSECURE_REQUESTS': 'true', 'X_FRAME_OPTIONS': 'true'}
    app['command'] = ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"]
    app['volumes'] = [{'type': 'bind', 'source': DATA, 'target': '/app/data', 'bind': {'create_host_path': False}}]
    app['healthcheck'] = {'test': ['CMD', 'node', '-e',
        "const h=require('http');const r=h.get('http://127.0.0.1:3000/',s=>process.exit(s.statusCode===200?0:1));r.setTimeout(3000,()=>r.destroy());r.on('error',()=>process.exit(1))"],
        'start_period': '20s', 'interval': '5s', 'timeout': '4s', 'retries': 24}
    gateway = document['services']['explorer_gateway']
    gateway['user'] = '65532:65532'
    gateway['environment'] = {}
    gateway['ports'] = [value['bind_address']+':80:4180']
    gateway['volumes'] = [{'type': 'bind', 'source': RUNTIME+source, 'target': target, 'read_only': True,
        'bind': {'create_host_path': False}} for source, target in (
            ('explorer-traefik.json', '/etc/traefik/traefik.json'), ('explorer-routes.yml', '/etc/traefik/explorer.yml'))]
    gateway['command'] = ['--configFile=/etc/traefik/traefik.json']
    gateway['healthcheck'] = {'test': ['CMD', 'traefik', 'healthcheck', '--configFile=/etc/traefik/traefik.json'],
        'start_period': '10s', 'interval': '5s', 'timeout': '4s', 'retries': 24}
    gateway['depends_on'] = {'mqtt_explorer': {'condition': 'service_healthy'}}
    return document
