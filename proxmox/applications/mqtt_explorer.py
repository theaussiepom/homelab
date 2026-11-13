"""Optional browser client with a file-only authenticated, unpublished backend."""
import re
from urllib.parse import urlsplit

import discovery
from private_io import require

DATA = '/srv/homelab/data/mqtt-explorer'
SERVICES = {'mqtt_explorer', 'explorer_gateway'}








def configuration(value, *, explorer_service='mqtt_explorer'):
    require(isinstance(explorer_service, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', explorer_service),
            'Use the exact owned Explorer service name')
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
        'services': {'explorer': {'loadBalancer': {'servers': [{'url': 'http://' + explorer_service + ':3000'}]}},
                     'outpost': {'loadBalancer': {'servers': [{'url': outpost}]}}}}}
    return static, dynamic




def service_configuration(value, services, *, mount, data_path=DATA,
                          explorer_service='mqtt_explorer', ports=None):
    """Pure owned GUI pair; credential/profile lifecycle stays with its owner."""
    require(isinstance(explorer_service, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', explorer_service),
            'Use the exact owned Explorer service name')
    for name in SERVICES:
        service = services[name]
        service.pop('network_mode', None)
        service.update(cap_drop=['ALL'], security_opt=['no-new-privileges:true'], read_only=True)
    app = services['mqtt_explorer']
    app['extra_hosts'] = {value['broker_connection']['hostname']: value['broker_address']}
    app['user'] = '1001:1001'
    app['environment'] = {'NODE_ENV': 'production', 'PORT': '3000', 'NODE_OPTIONS': '--max-old-space-size=128',
        'MQTT_EXPLORER_SKIP_AUTH': 'true', 'ALLOWED_ORIGINS': 'https://'+urlsplit(value['public_url']).hostname,
        'UPGRADE_INSECURE_REQUESTS': 'true', 'X_FRAME_OPTIONS': 'true'}
    app['command'] = ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"]
    app['volumes'] = [{'type': 'bind', 'source': data_path, 'target': '/app/data', 'bind': {'create_host_path': False}}]
    app['healthcheck'] = {'test': ['CMD', 'node', '-e',
        "const h=require('http');const r=h.get('http://127.0.0.1:3000/',s=>process.exit(s.statusCode===200?0:1));r.setTimeout(3000,()=>r.destroy());r.on('error',()=>process.exit(1))"],
        'start_period': '20s', 'interval': '5s', 'timeout': '4s', 'retries': 24}
    gateway = services['explorer_gateway']
    gateway['user'] = '65532:65532'
    gateway['environment'] = {}
    gateway['ports'] = ports if ports is not None else [value['bind_address']+':80:4180']
    gateway['volumes'] = [mount(source, target) for source, target in (
        ('explorer-traefik.json', '/etc/traefik/traefik.json'),
        ('explorer-routes.yml', '/etc/traefik/explorer.yml'))]
    gateway['command'] = ['--configFile=/etc/traefik/traefik.json']
    gateway['healthcheck'] = {'test': ['CMD', 'traefik', 'healthcheck', '--configFile=/etc/traefik/traefik.json'],
        'start_period': '10s', 'interval': '5s', 'timeout': '4s', 'retries': 24}
    gateway['depends_on'] = {explorer_service: {'condition': 'service_healthy'}}
    return services
