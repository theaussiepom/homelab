"""Prepare only one admitted app's immutable payload, never a peer's secrets."""
import copy
import json
import os
from pathlib import Path
import re

import component_inputs
import component_input_secrets
import component_payload
import component_private_inputs
import component_proxy_files
import component_foundation_files
import component_monitoring_inputs
import component_app_hooks
import component_continuity
import component_private_material
import component_generation
import component_ownership
import dns_records
from application_contract import runtime_files,SIDECAR_FILES
import managed_credentials
from private_io import encoded, read_json, regular, require

# Further adapters install their fixed owned file generator here. A rendered
# preview is not permission to execute an incomplete private input path.
SUPPORTED = {'renovate', 'unbound', 'pihole', 'homeassistant', 'node_red', 'music_assistant', 'scrypted',
             'postgresql', 'mariadb', 'influxdb', 'bitwarden', 'pegaprox', 'winet',
             'cloudbeaver', 'mqtt_explorer', 'authentik', 'mqtt', 'traefik', 'zabbix','zigbee2mqtt'}


def sidecar(app,name,raw,payload):
    fixed=SIDECAR_FILES.get(app['adapter'],{})
    require(app.get('sidecar_files')==fixed and name in fixed and name not in payload
            and isinstance(raw,bytes),'Install only the fixed owned adapter sidecar')
    payload[name]=raw
    return {'source':name,**fixed[name]}


def install_rows(app, rows, payload):
    """Bind fixed builder leaves to this app's reserved file ownership only."""
    allowed = runtime_files(app)
    require(isinstance(rows,list),'Use the selected fixed runtime file rows')
    if not allowed:
        require(not rows,'This adapter owns no generated runtime leaves')
        return []
    selected = app.get('runtime_files')
    root = app['identity']['runtime_directory']
    require(isinstance(root,str) and (root=='/opt/homelab-app/runtime' or re.fullmatch(
                '/opt/homelab-app/runtime/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',root))
            and isinstance(selected, dict) and selected['app'] == app['id']
            and selected['directory'] == root and set(selected['files']) == allowed,
            'Preserve the compiled runtime leaf ownership')
    downloaded=set()
    if app['adapter']=='cloudbeaver' and app['settings'].get('mariadb_jdbc'):
        downloaded={'mariadb-java-client-'+app['settings']['mariadb_jdbc']['version']+'.jar'}
    require({row.get('path') for row in rows if isinstance(row,dict)}==allowed-downloaded,
            'Prepare every selected owned runtime leaf exactly once')
    result = []
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'path','content','uid','gid','mode'}
                and isinstance(row['path'],str) and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,127}',row['path'])
                and row['path'] in allowed and row['path'] not in payload
                and type(row['uid']) is int and 0 <= row['uid'] <= 65535
                and type(row['gid']) is int and 0 <= row['gid'] <= 65535
                and row['mode'] in ('0400','0600') and isinstance(row['content'], (bytes,str)),
                'A runtime builder emitted an undeclared or conflicting owned file')
        payload[row['path']] = row['content'].encode() if isinstance(row['content'],str) else row['content']
        result.append({'source':row['path'],'destination':root+'/'+row['path'],
                       **{key:row[key] for key in ('uid','gid','mode')}})
    return result


def account_records(cfg, app, payload):
    """Consumer reads a producer-owned record; only the owned broker GUI creates."""
    adapter = app['adapter']
    selected = app['settings'].get('managed_connections', {}) if adapter == 'cloudbeaver' else {}
    if adapter == 'mqtt_explorer' and 'managed_credential' in app['settings']['broker']:
        selected = {'broker':app['settings']['broker']['managed_credential']}
    records = {}
    for row in selected.values():
        name = row['credential_id']
        record = managed_credentials.credential(cfg['paths']['state_root'], name, row['owner'],
                                               create=adapter == 'mqtt_explorer')
        filename = managed_credentials.input_name(name)
        require(name not in records and filename not in payload,
                'Bind one canonical account record to each selected credential')
        payload[filename] = encoded(record)
        records[name] = record
    return records


def overlay(app, environment):
    require(app['adapter'] in ('node_red', 'bitwarden', 'renovate') and isinstance(environment, dict)
            and environment and all(isinstance(name, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name)
                and isinstance(value, str) and not any(char in value for char in '\r\n\x00')
                for name, value in environment.items()), 'Use the selected adapter private environment only')
    role = app['adapter']
    service = app['identity']['services'][role]
    return encoded({'services': {service: {'environment': {
        name: value.replace('$', '$$') for name, value in environment.items()}}}})


def dns_document(cfg, app, attempt):
    """Derive prior DNS names from the genuine same-app sealed ordinary payload."""
    previous = {}
    owned = component_generation.previous(attempt)
    if owned is not None and app['id'] in owned[2]:
        receipt, old_cfg, applications = owned
        old = applications[app['id']]
        require(old['adapter'] == app['adapter'] == 'pihole'
                and component_ownership.identity(old_cfg, old) == component_ownership.identity(cfg, app),
                'Preserve the exact prior DNS application owner')
        selected = read_json(Path(receipt['binding']['app_inputs_directory']) / app['id'] / 'dns-records.json',
                             private=True)
        require(isinstance(selected,dict),'Preserve a sealed DNS sidecar map')
        # Only a hash-bound historical sidecar may use the former flat shape.
        previous = dns_records.selection(selected)[0] if 'schema' in selected else dns_records.validate(selected)
        require(previous == old['settings']['dns_records'], 'Preserve the prior sealed DNS selection')
        if receipt['binding']['input_identity'] == cfg['deployment']['input_identity']:
            require('schema' in selected and previous == app['settings']['dns_records'],
                    'Preserve this exact immutable DNS input generation')
            # Reuse this generation's already sealed predecessor map. Computing
            # it again from the latest success would change immutable payload
            # bytes on an otherwise unchanged ordinary repeat.
            return selected
    else:
        require(app['lifecycle'] == 'fresh', 'Retained DNS requires its genuine prior app payload')
    return dns_records.document(app['settings']['dns_records'], previous)


def prepare(cfg, app_id, environment=None, *, attempt):
    runtime = read_json(Path(cfg['deployment']['runtime_file']), private=True)
    require(app_id in runtime['applications'], 'Select this guest owned application')
    app = copy.deepcopy(runtime['applications'][app_id])
    require(app['adapter'] in SUPPORTED, 'Selected app private input materialization is not yet implemented')
    parent = component_inputs.app_directory(cfg, create=True)
    component_payload.existing(parent, cfg['deployment']['input_identity'], app_id)
    values = component_input_secrets.selected(app['adapter'], app.get('input_sources', {}), environment)
    if app['adapter']=='zabbix':
        require(not values,'Select the root-owned monitoring server credential capability')
    material=component_continuity.document(app,component_private_material.project(app,values))
    component_continuity.verify(attempt,app,material)
    payload, install = {component_continuity.FILE:encoded(material)}, []
    selected_monitoring=cfg['app'].get('monitoring',{})
    for key,leaf in (('storage_password_file','monitoring-storage-password'),('server_file','monitoring-server.json')):
        relevant=(key=='storage_password_file' and app['adapter']=='postgresql' and 'monitoring_hba_source' in app
                  or key=='server_file' and app['adapter']=='zabbix' and app['settings'].get('database_credential')=={
                      'type':'monitoring-owned','server':app_id})
        if relevant:
            require(selected_monitoring.get(key)==str(parent/app_id/leaf),
                    'Bind the monitoring input to its exact selected app payload')
    monitoring = component_monitoring_inputs.prepare(cfg,app=app)
    if app['adapter']=='zabbix':
        require(set(monitoring)=={'database-password','proxmox-ca.pem','monitoring-server.json'}
                and not values,'Select the root-owned monitoring server credential capability')
        rows=component_proxy_files.files(app,secrets={'database_password':monitoring['database-password']},
            records={},public_ca=monitoring['proxmox-ca.pem'])
        install += install_rows(app,rows,payload)
        import monitoring_templates
        server=json.loads(monitoring['monitoring-server.json'])
        server['owner']={key:cfg['site'][key] for key in ('node',)}
        server['owner'].update({key:cfg['guest'][key] for key in ('vmid','hostname')})
        server['templates']=[monitoring_templates.prepared(name)
            for name in monitoring_templates.monitoring.VERSIONS['templates']]
        payload['monitoring-server.json']=encoded(server)
    else:
        payload.update(monitoring)
    if app['adapter'] == 'renovate':
        import renovate
        payload['environment.yml'] = overlay(app, renovate.secrets(values))
    elif app['adapter'] == 'postgresql' and 'application_database' in app['settings']:
        require(set(values) == {'application_database_password'}, 'Supply the selected application database password')
        import renovate
        renovate.scalar(values['application_database_password'])
        payload['application-database-password'] = values['application_database_password']
    elif app['adapter']=='zigbee2mqtt':
        hook=component_app_hooks.descriptors(app,compose_file='/opt/homelab-app/'+app['project_file'])
        row=hook['zigbee_state']['settings_file']
        install.append(sidecar(app,'zigbee-settings.json',row['content'].encode(),payload))
    elif app['adapter']=='zabbix':
        pass
    elif app['adapter'] in component_private_inputs.ROLES:
        prepared = component_private_inputs.bind(app, values)
        install += install_rows(app, prepared['files'], payload)
        if prepared['environment']:
            payload['environment.yml'] = overlay(app, prepared['environment'])
            if app['adapter']=='bitwarden':payload['bitwarden-environment.json']=values['runtime_environment']
    elif app['adapter']=='authentik':
        install += install_rows(app,component_foundation_files.files(app,secrets=values),payload)
    elif app['adapter']=='traefik':
        # Persist the selected record for the existing read-only permission
        # check AFTER STARTED binds this payload. Preparation performs no API call.
        payload['provider-record.json']=values['proxmox_token']
        rows=component_foundation_files.files(app,secrets=values,
            public_ca=regular(Path(cfg['paths']['ca_file'])),
            route_cas={key:regular(Path(row['source'])) for key,row in app['settings'].get('route_ca_files',{}).items()},
            route_plan=app['route_plan'])
        install += install_rows(app,rows,payload)
    elif app['adapter'] in ('cloudbeaver','mqtt_explorer'):
        records = account_records(cfg, app, payload)
        install += install_rows(app, component_proxy_files.files(app, secrets=values,
                                records=records, public_ca=None), payload)
    elif app['adapter'] == 'node_red':
        require(set(values) <= {'api_token'}, 'Use only the owned Node-RED runtime input')
        if values:
            payload['environment.yml'] = overlay(app, {'NODE_RED_API_TOKEN': values['api_token'].decode()})
    else:
        require(not values, 'This adapter has no selected scalar or external file inputs')
    if app['adapter'] == 'pihole':
        install.append(sidecar(app,'dns-records.json',encoded(dns_document(cfg,app,attempt)),payload))
    for account in app.get('database_administrators', {}).values():
        expected, files = managed_credentials.payload(cfg['paths']['state_root'], account['credential_id'],
            account['owner'], parent/app_id)
        require(expected == account['credential_file'] and not set(files) & set(payload),
                'Preserve exact administrator credential ownership and input location')
        payload.update(files)
    if 'project_file' in app:
        base = read_json(Path(cfg['deployment']['input_directory'])/app['project_file'], private=True)
        require(all('env_file' not in service for service in base['services'].values()),
                'The shared base cannot require a peer late environment input')
        if app['adapter']=='zabbix':
            web=app['identity']['services']['zabbix_web']
            require('127.0.0.1:8081:8080' in base['services'][web]['ports'],
                    'Initial monitoring setup needs its declared guest-loopback publication')
            initial=copy.deepcopy(base)
            initial['services'][web]['ports']=['127.0.0.1:8081:8080']
            payload['initial-compose.yml']=encoded(initial)
    payload['runtime-files.json'] = encoded(install)
    payload['application.json'] = encoded(app)
    return component_payload.prepare(parent, cfg['deployment']['input_identity'], app_id, payload)


def prepare_agent(cfg,environment=None):
    """The explicit final agent phase owns no application scalar inputs."""
    require('monitoring' in cfg['app'],'Select the compiled root monitoring feature')
    component_input_secrets.selected('agent',{},environment)
    parent=component_inputs.app_directory(cfg,create=True)
    component_payload.existing(parent,cfg['deployment']['input_identity'],'agent')
    selected=cfg['app']['monitoring']
    for key,leaf in (('credential_file','monitoring-agent.json'),('database_password_file','monitoring-database-password')):
        if key in selected:
            require(selected[key]==str(parent/'agent'/leaf),'Bind monitoring agent inputs to their own payload')
    payload=component_monitoring_inputs.prepare(cfg,agent=True)
    payload['application.json']=encoded({'schema':'homelab-component-agent-input-v1',
                                        'monitoring':cfg['app']['monitoring']})
    return component_payload.prepare(parent,cfg['deployment']['input_identity'],'agent',payload)


def prepare_backup(cfg, environment=None):
    """Enroll this guest under its ordinary locks and seal its own worker inputs."""
    import backup_agent
    backup_agent.configuration(cfg)
    component_input_secrets.selected('agent', {}, environment)
    parent = component_inputs.app_directory(cfg, create=True)
    component_payload.existing(parent, cfg['deployment']['input_identity'], 'backup-agent')
    if 'job' in cfg['app']['backup']:
        import backup_setup
        backup_setup.enroll(cfg, os.environ if environment is None else environment)
    return component_payload.prepare(parent, cfg['deployment']['input_identity'], 'backup-agent',
        {'application.json': encoded(cfg['app']['backup']), **backup_agent.inputs(cfg['app']['backup'])})
