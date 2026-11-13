"""Pure owned proxy-app runtime files from already prepared finite inputs.

No authored/private path is opened and no credential/account is generated here.
The only source reads are fixed public Java/PHP assets from this selected tree.
Rows retain leaf filenames; the owning writer binds the app runtime directory.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re

import cloudbeaver as community
import database_admin
import monitoring
import mqtt_explorer as explorer
from private_io import require

RUNTIME = '/opt/homelab-app/runtime'
SERVICES = {'cloudbeaver': ('cloudbeaver', 'auth_gateway'),
            'mqtt_explorer': ('mqtt_explorer', 'explorer_gateway'),
            'zabbix': ('zabbix_server', 'zabbix_web')}


def _context(app):
    require(isinstance(app, dict) and app.get('adapter') in SERVICES,
            'Select a supported proxy file component')
    identity = app.get('identity', {})
    names = identity.get('services', {})
    require(isinstance(names, dict) and set(names) == set(SERVICES[app['adapter']])
            and all(isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', value)
                    for value in names.values()) and len(set(names.values())) == len(names), 'Bind only this app owned service identities')
    directory = identity.get('runtime_directory')
    require(isinstance(directory, str) and (directory == RUNTIME or
            re.fullmatch(re.escape(RUNTIME) + '/[a-z0-9_-]+(?:/[a-z0-9_-]+)*', directory)),
            'Bind a confined app runtime directory')
    project = app.get('project_name')
    require(isinstance(project, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', project),
            'Bind the owned Compose project identity')
    return names, directory, project


def _public_source(name):
    allowed = {'CloudBeaverHealth.java': Path(community.__file__).with_name('CloudBeaverHealth.java'),
               'CloudBeaverDatabaseHealth.java': Path(community.__file__).with_name('CloudBeaverDatabaseHealth.java'),
               'saml-login.php': monitoring.ROOT / 'saml-login.php'}
    require(name in allowed, 'Select a fixed public runtime source asset')
    return allowed[name].read_text()


def _text(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536 and b'\x00' not in raw,
            'Supply a bounded prepared runtime input')
    try:
        return raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('Supply UTF-8 prepared runtime input') from None


def _inputs(secrets, records, roles, credential_ids, public_ca, *, ca=False):
    require(isinstance(secrets, dict) and set(secrets) == set(roles)
            and all(isinstance(value, bytes) for value in secrets.values()),
            'Supply exactly this selected app finite secret roles')
    require(isinstance(records, dict) and set(records) == set(credential_ids),
            'Supply exactly this app selected managed account records')
    require(isinstance(public_ca, bytes) if ca else public_ca is None,
            'Supply public CA bytes only for the selected monitoring component')


def _row(path, content, uid, gid=None, mode='0400'):
    return {'path': path, 'content': content, 'uid': uid,
            'gid': uid if gid is None else gid, 'mode': mode}


def _dynamic(public, names, directory, *, project=None):
    if any(key != value for key, value in names.items()):
        public['services'] = copy.deepcopy(names)
    if directory != RUNTIME:
        public['runtime_directory'] = directory
    if project is not None and project != 'homelab-mqtt':
        public['project'] = project


def _cloudbeaver(app, secrets, records, public_ca, context):
    names, directory, project = context
    value = copy.deepcopy(app['settings'])
    managed = database_admin.connections(value)
    _inputs(secrets, records, {'client_secret'}, {row['credential_id'] for row in managed.values()}, public_ca)
    _text(secrets['client_secret'])
    selected = app.get('authentication_resolved')
    require(isinstance(selected, dict) and selected.get('version') == 1,
            'Bind the resolved Community authentication capability')
    alpha, options = community.gateway(value, selected, secrets['client_secret'],
                                       server_service=names['cloudbeaver'])
    encoded_name = value['server_name'].encode('utf-16-be').hex()
    properties_name = ''.join('\\u' + encoded_name[i:i+4] for i in range(0, len(encoded_name), 4))
    auto = ('CB_SERVER_NAME=' + properties_name + '\nCB_ADMIN_NAME=' + value['recovery_admin']
            + '\nCB_ADMIN_PASSWORD=' + base64.urlsafe_b64encode(
                community.derive(secrets['client_secret'], 'local-recovery')).decode() + 'aA1!\n')
    public = dict(value, workspace=app['storage_paths']['workspace']['source'], project=project)
    _dynamic(public, names, directory)
    for field,default in (('lifecycle','retained'),('project_file','compose.yml')):
        if app.get(field,default)!=default:public[field]=app[field]
    for field,default in (('custody_directory','/var/lib/homelab-db-tools'),('runtime_id','cloudbeaver')):
        selected=app['identity'].get(field,default)
        if selected!=default:public[field]=selected
    rows = [('CloudBeaverHealth.java', _public_source('CloudBeaverHealth.java'), 8978),
            ('cloudbeaver.conf', json.dumps(community.configuration(value)), 8978),
            ('cloudbeaver.auto.conf', auto, 8978),
            ('cloudbeaver-connections.json', json.dumps(community.connection_document(value)), 8978),
            ('cloudbeaver-permissions.json', json.dumps({key: ['user'] for key in value['connections']}), 8978),
            ('oauth2-alpha.json', json.dumps(alpha), 65532), ('oauth2.cfg', options, 65532),
            ('cloudbeaver-public.json', json.dumps(public), 0)]
    if managed:
        public['cloudbeaver_image'] = app['software_selection']['images']['cloudbeaver']['image']
        artifact = community.jdbc(value)
        if artifact is not None:
            artifact['source'] = directory + '/' + Path(artifact['source']).name
            public['mariadb_jdbc'] = artifact
        document = json.loads(database_admin.document_from_records(value, records))
        public['managed_sha256'] = hashlib.sha256((json.dumps(document, sort_keys=True)+'\n').encode()).hexdigest()
        rows[-1] = ('cloudbeaver-public.json', json.dumps(public), 0)
        rows += [('cloudbeaver-admin-connections.json', json.dumps(document, sort_keys=True), 0),
                 ('CloudBeaverDatabaseHealth.java', _public_source('CloudBeaverDatabaseHealth.java'), 8978)]
    return [_row(name, content+'\n', uid) for name, content, uid in rows]


def _explorer_runtime(app,names,directory,project):
    result={}
    if project!='homelab-mqtt':result['project']=project
    if any(key!=value for key,value in names.items()):result['services']=copy.deepcopy(names)
    if app['storage_paths']['data']['source']!=explorer.DATA:result['data_path']=app['storage_paths']['data']['source']
    if directory!=RUNTIME:result['runtime_directory']=directory
    runtime_id=app['identity'].get('runtime_id','mqtt_explorer')
    require(isinstance(runtime_id,str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',runtime_id),
            'Bind the stable Explorer runtime identity')
    if runtime_id!='mqtt_explorer':result['runtime_id']=runtime_id
    custody=app['identity'].get('custody_directory','/var/lib/homelab-mqtt-explorer')
    require(isinstance(custody,str) and (custody=='/var/lib/homelab-mqtt-explorer' or re.fullmatch(
        '/var/lib/homelab-mqtt-explorer/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',custody)),
        'Bind the explicit owned Explorer custody directory')
    if custody!='/var/lib/homelab-mqtt-explorer':result['custody_directory']=custody
    return result


def _mqtt_explorer(app, secrets, records, public_ca, context):
    names,directory,project=context
    settings=app['settings'];broker=settings['broker']
    runtime=_explorer_runtime(app,names,directory,project)
    managed='managed_credential' in broker
    require(managed != ('credential' in broker),'Select one explicit Explorer credential owner')
    if managed:
        selected=broker['managed_credential'];owner=selected['owner']
        _inputs(secrets,records,set(),{selected['credential_id']},public_ca)
        record=records[selected['credential_id']]
        require(isinstance(record,dict) and set(record)=={'schema','owner','password'}
                and record['schema']=='homelab-application-account-v1' and record['owner']==owner
                and isinstance(owner,dict) and owner.get('purpose')=='mqtt-explorer'
                and owner.get('username')==broker['account']['principal']
                and isinstance(record['password'],str) and re.fullmatch('[0-9a-f]{64}',record['password']),
                'Use the exact selected dedicated Explorer credential owner')
        require(isinstance(broker.get('image'),str)
                and re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}',broker['image']),
                'Bind the exact selected broker image before managed account preparation')
        connection={'name':app['properties']['connection_name'],'hostname':broker['hostname'],'port':broker['target']['port'],
            'username':owner['username'],'credential_id':selected['credential_id'],'credential_file':selected['credential_file'],
            'password_file':broker['password_file'],'access':broker['account']['access']}
        private={'connection':{key:value for key,value in connection.items() if key!='credential_file'},
                 'credential':record,'image':broker['image']}
        if runtime:private['runtime']=runtime
        selected_broker=broker.get('runtime',{'project':'homelab-mqtt','service':'mqtt','config_path':'/srv/homelab/data/mqtt/config'})
        require(isinstance(selected_broker,dict) and set(selected_broker)=={'project','service','config_path'},
                'Bind only the compiled broker runtime identity')
        if selected_broker!={'project':'homelab-mqtt','service':'mqtt','config_path':'/srv/homelab/data/mqtt/config'}:
            private['broker_runtime']=copy.deepcopy(selected_broker)
        filename='mqtt-explorer-account.json'
    else:
        _inputs(secrets,records,{'broker_password'},set(),public_ca)
        password=_text(secrets['broker_password'])
        require(password.strip() and not any(c in password for c in '\r\n'),
                'Supply the explicit unchanged existing broker password')
        runtime_id=app['identity'].get('runtime_id','mqtt_explorer')
        connection={'name':app['properties']['connection_name'],'hostname':broker['hostname'],'port':broker['target']['port'],
                    'username':broker['credential']['principal'],'profile_id':runtime_id}
        private={'schema':'homelab-mqtt-explorer-existing-profile-v1','profile_id':runtime_id,
                 'connection':{key:value for key,value in connection.items() if key!='profile_id'},'password':password}
        if runtime:private['runtime']=runtime
        filename='mqtt-explorer-profile.json'
    value={'public_url':app['origin_url'],'bind_address':app['role_addresses']['web_interface'],
        'authentik_outpost_url':settings['authentik_outpost_url'],'data_path':app['storage_paths']['data']['source'],
        'broker_connection':connection,'broker_address':broker['target']['address']}
    static,dynamic=explorer.configuration(value,explorer_service=names['mqtt_explorer'])
    rows=[_row(name,json.dumps(document,sort_keys=True)+'\n',65532)
          for name,document in [('explorer-traefik.json',static),('explorer-routes.yml',dynamic)]]
    public={**value,'images':{name:app['software_selection']['images'][name]['image'] for name in explorer.SERVICES},
            'runtime_sha256':{row['path']:hashlib.sha256(row['content'].encode()).hexdigest() for row in rows}}
    _dynamic(public,names,directory,project=project)
    if 'runtime_id' in runtime:public['runtime_id']=runtime['runtime_id']
    if 'custody_directory' in runtime:public['custody_directory']=runtime['custody_directory']
    rows.append(_row(filename,json.dumps(private,sort_keys=True)+'\n',0,mode='0600'))
    return [*rows,_row('mqtt-explorer-public.json',json.dumps(public,sort_keys=True)+'\n',0)]


def _zabbix(app, secrets, records, public_ca, context):
    _inputs(secrets, records, {'database_password'}, set(), public_ca, ca=True)
    password = _text(secrets['database_password']); monitoring.text(password.rstrip('\n'))
    ca = _text(public_ca)
    require(bool(ca.strip()) and ca.count('-----BEGIN CERTIFICATE-----') == 1
            and ca.count('-----END CERTIFICATE-----') == 1 and 'PRIVATE KEY' not in ca,
            'Supply the selected public Proxmox root CA')
    rows = [_row('database-password', password, 1997, 1995),
            _row('proxmox-ca.pem', ca, 1997, 1995)]
    if 'authentication_resolved' in app:
        selected = app['authentication_resolved']; monitoring.saml_settings(selected)
        if selected.get('default_login') == 'saml':
            rows.append(_row('saml-login.php', _public_source('saml-login.php'), 1997, 1995))
    return rows


HANDLERS = {'cloudbeaver': _cloudbeaver, 'mqtt_explorer': _mqtt_explorer, 'zabbix': _zabbix}


def files(app, *, secrets, records, public_ca):
    context = _context(app)
    return HANDLERS[app['adapter']](app, secrets, records, public_ca, context)
