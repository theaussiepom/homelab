"""Finite source-only readiness rows for seven supported application adapters.

These are declarations, not execution or acceptance. Existing installed helpers
and native protocol primitives perform the later protected deployment checks.
"""
from pathlib import PurePosixPath
import ipaddress
from urllib.parse import urlsplit
import re

import component_native
import component_app_hooks
import dns_records
from component_errors import at
from component_sources import require
import component_types as types

ADAPTERS = {'postgresql', 'mariadb', 'influxdb', 'pihole', 'unbound', 'homeassistant', 'node_red'}
AUTOMATION_HELPER = '/opt/homelab-app/automation-health.py'


def _row(name, argv, expect):
    return {'name': name, 'argv': argv, 'expect': expect}


def _declared(app):
    declarations = app.get('health', {})
    require(isinstance(declarations, dict), 'component.health')
    for row in declarations.values():
        types.health(row)
        require('source_interface' not in row or (app['adapter'] == 'music_assistant'
                and row['source_interface'] == 'web_interface' and
                'interface' in app['interfaces']['web_interface']), 'component.health-source-unsupported')
    return bool(declarations)


def _native_address(app):
    try:
        return component_native._address(app['role_addresses']['service_interface'])
    except (ValueError, TypeError, KeyError):
        require(False, 'component.health')


def _native_version(app):
    try:
        return component_native._version(app)[0]
    except (ValueError, TypeError, KeyError):
        require(False, 'component.health')


def _listener(app, service, port, namespace):
    selected = [row for row in app.get('listeners', {}).values() if row.get('service') == service]
    require(len(selected) == 1 and selected[0].get('protocol') == 'tcp'
            and selected[0].get('namespace') == namespace and selected[0].get('port') == port
            and 'publish' not in selected[0], 'component.health-listener')


def _compose_exec(app, compose_file, role, *command):
    require(isinstance(compose_file, str) and compose_file.startswith('/')
            and not compose_file.startswith('//') and PurePosixPath(compose_file).as_posix() == compose_file
            and not any(part in ('.', '..') for part in compose_file.split('/'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in compose_file)
            and '\\' not in compose_file, 'component.health-compose')
    name = app['identity']['services'][role]
    require(isinstance(name, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', name),
            'component.health-service')
    return ['docker', 'compose', '-f', compose_file, 'exec', '-T', name, *command]


def _service(unit):
    return _row('Service is enabled and active', ['python3', '-c',
        "import subprocess; assert subprocess.check_output(['systemctl','is-enabled','" + unit
        + "'],text=True).strip()=='enabled'; subprocess.run(['systemctl','is-active','--quiet','"
        + unit + "'],check=True); print('SERVICE_OK')"], 'SERVICE_OK')


def _tcp(address, port):
    return _row('Backend TCP listener', ['python3', '-c',
        'import socket; s=socket.create_connection((' + repr(address) + ',' + str(port)
        + "),timeout=5); s.close(); print('BACKEND_OK')"], 'BACKEND_OK')


def _postgresql(app, compose_file):
    address = _native_address(app)
    _listener(app, 'postgresql', 5432, 'host')
    return [_service('postgresql'),
        _row('PostgreSQL backend listener accepts connections',
             ['pg_isready', '-h', address, '-p', '5432'], 'accepting connections'),
        _row('Local maintenance query', ['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At',
             '-v', 'ON_ERROR_STOP=1', '-d', 'postgres', '-c', 'SELECT 1'], '1'), _tcp(address, 5432)]


def _mariadb(app, compose_file):
    address = _native_address(app)
    _listener(app, 'mariadb', 3306, 'host')
    return [_service('mariadb'), _row('Local root socket query',
        ['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names', '-e',
         'SELECT VERSION();'], _native_version(app)), _tcp(address, 3306)]


def _influxdb(app, compose_file):
    """Check the database and optional web listeners without a data query."""
    address, version = _native_address(app), _native_version(app)
    frontend = component_native.web_frontend(app)
    if not frontend['enabled']:
        _listener(app, 'influxdb', 8086, 'host')
    rows = [_service('influxdb'), _row('InfluxDB health without initial setup or application data',
        ['python3', '-c', "import json,urllib.request; d=json.load(urllib.request.urlopen('http://"
         + address + ":8086/health',timeout=5)); assert d['status']=='pass' and d['version']=='v"
         + version + "'; print('INFLUX_OK')"], 'INFLUX_OK'), _tcp(address, 8086)]
    if frontend['enabled']:
        web = _ipv4(app['role_addresses']['web_interface'])
        rows += [_service('homelab-influxdb-web.socket'), _row('InfluxDB Apps frontend reaches the unchanged local API',
            ['python3', '-c', "import json,urllib.request; d=json.load(urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://"
             + web + ":8086/health',timeout=5)); assert d['status']=='pass' and d['version']=='v"
             + version + "'; print('INFLUX_FRONTEND_OK')"], 'INFLUX_FRONTEND_OK')]
    return rows


def _pihole(app, compose_file):
    rows = [_row('pihole ready', _compose_exec(app, compose_file, 'pihole', 'pihole', 'status'), '')]
    try:
        records = dns_records.validate(app.get('settings', {}).get('dns_records', {}))
    except (ValueError, TypeError, KeyError):
        require(False, 'component.health-dns')
    for name, address in sorted(records.items()):
        rows.append(_row('DNS service record ' + name,
            ['python3', '/opt/homelab-app/dns_records.py', 'probe', name, address],
            '"read_only_dns_check": "passed"'))
    if 'web_interface' in app.get('role_addresses', {}):
        rows.extend(_bound_web_checks(app, 80))
    return rows


def _unbound(app, compose_file):
    return [_row('unbound ready', _compose_exec(app, compose_file, 'unbound', 'unbound-checkconf',
                 '/opt/unbound/etc/unbound/unbound.conf'), '')]


def _bound_web_checks(app, port):
    """Require the selected web socket and reject wildcard or legacy binds."""
    if not any(row.get('bind')=='interface' for row in app['listeners'].values()):
        return []
    address=_ipv4(app['role_addresses']['web_interface'])
    code="import subprocess; rows=subprocess.check_output(['ss','-H','-ltn','sport = :"+str(port)+"'],text=True).splitlines(); sockets={r.split()[3] for r in rows}; assert "+repr(address+':'+str(port))+" in sockets and sockets <= "+"set("+repr([address+':'+str(port),'127.0.0.1:'+str(port),'[::1]:'+str(port)])+")"+"; print('WEB_BIND_OK')"
    return [_row('Web socket is bound only to its selected interface and loopback',
        ['python3','-c',code],'WEB_BIND_OK')]


def _homeassistant(app, compose_file):
    """Keep the local HA challenge probe and optional bound-socket check."""
    _listener(app, 'homeassistant', 8123, 'host')
    require(app['lifecycle'] in ('retained', 'fresh'), 'component.health-lifecycle')
    retained = app['lifecycle'] == 'retained'
    return [_row('HA web responds and unauthenticated API refused' if retained else
        'HA onboarding or login ready and unauthenticated API refused',
        ['python3', AUTOMATION_HELPER, 'homeassistant' if retained else 'homeassistant-fresh'],
        '"read_only_probe": "passed"'), *_bound_web_checks(app,8123)]


def _node_red(app, compose_file):
    """Probe the declared Node-RED web address and optional socket binding."""
    _listener(app, 'node_red', 1880, 'host')
    require(app['lifecycle'] in ('retained', 'fresh'), 'component.health-lifecycle')
    retained = app['lifecycle'] == 'retained'
    extra=['--address',_ipv4(app['role_addresses']['web_interface'])] if any(row.get('bind')=='interface' for row in app['listeners'].values()) else []
    return [_row('Node-RED native login ready and unauthenticated flows refused' if retained else
        'Node-RED public UI responds', ['python3', AUTOMATION_HELPER,
        'node_red' if retained else 'node_red-fresh',*extra],
        '"read_only_probe": "passed"' if retained else '"scope": "ui_only"'), *_bound_web_checks(app,1880)]


HANDLERS = {'postgresql': _postgresql, 'mariadb': _mariadb, 'influxdb': _influxdb,
            'pihole': _pihole, 'unbound': _unbound, 'homeassistant': _homeassistant, 'node_red': _node_red}


def _ipv4(value):
    try:
        require(isinstance(value,str) and str(ipaddress.IPv4Address(value))==value,'component.health-address')
    except (TypeError,ValueError):
        require(False,'component.health-address')
    return value


def _backend(app, port):
    row=app['listeners']['web_listener'];publish=row.get('publish',{})
    require(row['protocol']=='tcp' and row['port']==port and publish.get('scope')=='guest-interface'
            and publish.get('interface')=='web_interface' and publish.get('port')==port,'component.health-listener')
    address=_ipv4(app['role_addresses']['web_interface'])
    require(row.get('publication_address',address)==address,'component.health-listener')
    return 'http://'+address+':'+str(port)


def _runtime_file(app, leaf):
    path=app['identity']['runtime_directory'];prefix='/opt/homelab-app/runtime'
    require(isinstance(path,str) and (path==prefix or path.startswith(prefix+'/'))
            and PurePosixPath(path).as_posix()==path and not any(x in ('.','..') for x in path.split('/'))
            and not any(ord(x)<32 or ord(x)==127 for x in path) and '\\' not in path,'component.health-runtime')
    return path+'/'+leaf


def _public(app):
    public=app['resolved_connections']['public'];target=public['target'];origin=app['origin_url']
    require(public['type']=='https' and target['protocol']=='https' and target['port']==443,'component.health-public')
    address=_ipv4(target['address']);parsed=urlsplit(origin)
    require(parsed.scheme=='https' and parsed.hostname and parsed.netloc==parsed.hostname
            and parsed.path in ('','/') and not parsed.query and not parsed.fragment
            and '?' not in origin and '#' not in origin,'component.health-public')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{0,252}',parsed.hostname),'component.health-public')
    return origin.rstrip('/'),parsed.hostname,address,public


def _curl(*, maximum=15, retry=30, budget=180):
    return ['curl','--retry',str(retry),'--retry-delay','2','--retry-all-errors','--retry-max-time',str(budget),
            '--fail','--silent','--show-error','--max-time',str(maximum)]


def _authentik(app, compose_file):
    return [_row('Authentik application ready on its backend',_curl()+[_backend(app,9000)+'/-/health/ready/'],'')]


def _traefik(app, compose_file):
    # Existing adapter static config owns loopback health; it is not a published endpoint.
    return [_row('Proxy health endpoint',_curl(maximum=10)+['http://127.0.0.1:8082/ping'],'OK')]


def _cloudbeaver(app, compose_file):
    origin,host,address,_=_public(app)
    return [_row('CloudBeaver and authentication gateway',['python3','/opt/homelab-app/cloudbeaver-runtime.py',
        'health','--config',_runtime_file(app,'cloudbeaver-public.json')],'"cloudbeaver": "passed"'),
        _row('CloudBeaver HTTPS sign-in redirect',_curl(retry=1200,budget=2250)+['--resolve',host+':443:'+address,
        '--output','/dev/null','--write-out','%{http_code}',origin+'/'],'302')]


def _bitwarden(app, compose_file):
    require(app['lifecycle']=='retained','component.health-lifecycle')
    return [_row('Bitwarden alive/config/identity',['python3','/opt/homelab-app/bitwarden.py','--origin',
        _backend(app,8080),'--issuer',app['settings']['runtime']['issuer'],'--backend'],'"status": "passed"')]


def _pegaprox(app, compose_file):
    service=app['identity']['services']['pegaprox']
    import pegaprox_health
    pegaprox_health.command(compose_file,service)
    options=[] if (compose_file,service)==('/opt/homelab-app/compose.yml','pegaprox') else [
        '--compose-file',compose_file,'--service',service]
    return [_row('PegaProx health and closed initial setup',['python3','/opt/homelab-app/pegaprox-health.py',*options],
        'PegaProx verification passed')]


def _zabbix(app, compose_file):
    return [_row('Zabbix frontend ready',['curl','--fail','--silent','--show-error','--max-time','10',
        _backend(app,8080)+'/'],'')]


def _mqtt(app, compose_file):
    require(app['lifecycle']=='retained','component.health-lifecycle')
    selected=_runtime_file(app,'mqtt-probe.json')
    require(re.fullmatch(r'/opt/homelab-app/runtime(?:/[a-z0-9_-]+)*/mqtt-probe\.json',selected),
            'component.health-runtime')
    options=[] if selected=='/opt/homelab-app/runtime/mqtt-probe.json' else ['--mqtt-probe',selected]
    return [_row('Retained MQTT credentials accepted and anonymous refused',['python3',AUTOMATION_HELPER,'mqtt-broker',*options],
        '"read_only_probe": "passed"')]


def _mqtt_explorer(app, compose_file):
    return [_row('MQTT Explorer private service and authentication gateway',
        ['python3','/usr/local/bin/homelab-mqtt-explorer.py','health','--config',
         _runtime_file(app,'mqtt-explorer-public.json')],'"mqtt_explorer": "passed"')]


def _music_assistant(app, compose_file):
    """Check web and stream roles separately, then the existing HTTPS route."""
    require(all(any(r.get('protocol')=='tcp' and r.get('namespace')=='host' and r.get('port')==port
                    for r in app['listeners'].values()) for port in (8095,8097)),'component.health-listener')
    address=_ipv4(app['role_addresses']['web_interface']);origin,host,ingress,public=_public(app)
    stream=_ipv4(app['role_addresses'].get('stream_interface',address))
    source=_ipv4(public.get('source_address'))
    require(source in app['role_addresses'].values(),'component.health-source')
    code="import socket,urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://"+address+":8095/info',timeout=5).close(); socket.create_connection(('"+stream+"',8097),timeout=3).close(); print('core service only: passed')"
    return [_row('Music Assistant core info and stream listener',_compose_exec(app,compose_file,'music_assistant',
        'python3','-c',code),'core service only: passed'),
        _row('Music Assistant HTTPS route',_curl()+['--interface',source,'--resolve',host+':443:'+ingress,
         origin+'/info'],'server_version')]


def _winet(app, compose_file):
    project,service=app['project_name'],app['identity']['services']['winet']
    require(all(isinstance(x,str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',x) for x in (project,service)),
            'component.health-service')
    container=project+'-'+service+'-1'
    code="import json,subprocess,sys; d=json.loads(subprocess.check_output(['docker','inspect','--type=container',"+repr(container)+"],timeout=5)); healthy=len(d)==1 and d[0]['State']['Running'] and d[0]['State'].get('Health',{}).get('Status')=='healthy'; print(json.dumps({'healthy':healthy})); sys.exit(0 if healthy else 1)"
    return [_row('WiNet broker and inverter availability',['python3','-c',code],'"healthy": true')]


def _zigbee2mqtt(app, compose_file):
    return [_row('Zigbee frontend and preserved network configuration',
                 component_app_hooks.zigbee_argv(app, 'health'), '"healthy": true')]


HANDLERS.update({'authentik':_authentik,'traefik':_traefik,'cloudbeaver':_cloudbeaver,'bitwarden':_bitwarden,
          'pegaprox':_pegaprox,'zabbix':_zabbix,'mqtt':_mqtt,'mqtt_explorer':_mqtt_explorer,
          'music_assistant':_music_assistant,'winet':_winet,'zigbee2mqtt':_zigbee2mqtt})
ADAPTERS.update(HANDLERS)


def checks(app, guest, *, compose_file):
    """Build only declared finite adapter checks; never execute their argv."""
    require(isinstance(app, dict) and isinstance(guest, dict)
            and isinstance(app.get('adapter'), str) and app['adapter'] in ADAPTERS, 'component.health-adapter')
    with at('apps', app.get('id', app['adapter']), 'health'):
        return HANDLERS[app['adapter']](app, compose_file) if _declared(app) else []
