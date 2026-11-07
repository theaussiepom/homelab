"""Translate the admitted component phase to the existing Ansible engine."""
import copy
import os
from pathlib import Path
import re

import component_guest
import component_inputs
import component_input_secrets
import component_discovery
import component_app_hooks
import bitwarden_runtime
from application_contract import ordered_services
import proxmox_guest
from commands import quiet
from private_io import private_directory, read_json, regular, require, write

SOURCE = Path(__file__).resolve().parent
HELPERS = {'pihole': [('dns_records.py','dns_records.py')],
    'homeassistant': [('automation-health.py','automation-health.py')],
    'node_red': [('automation-health.py','automation-health.py')],
    'mqtt': [('automation-health.py','automation-health.py')],
    'cloudbeaver':[('cloudbeaver-runtime.py','/opt/homelab-app/cloudbeaver-runtime.py')],
    'mqtt_explorer':[('mqtt-explorer-runtime.py','/usr/local/bin/homelab-mqtt-explorer.py'),
        ('mqtt-explorer-account.py','/opt/homelab-app/mqtt-explorer-account.py'),
        ('mqtt_explorer_state.py','/opt/homelab-app/mqtt_explorer_state.py','0600')],
    'music_assistant': [('music_assistant.py','music_assistant.py')]}


def variables(cfg, phase, *, payload=None, previously_owned=False):
    phases = component_guest.phases(cfg)
    require(phase in phases and type(previously_owned) is bool, 'Select one actual component phase')
    app = copy.deepcopy(cfg['app'])
    app.update(kind='component', start_services=phase != 'preparation')
    result = {'app':app, 'preparation_capabilities':cfg['deployment']['capabilities'],
        'network_ready_interfaces':['eth'+str(index) for index,nic in enumerate(cfg['guest']['interfaces'])
                                    if nic['ipv4']!='manual'],
        'component_helpers':[], 'component_native_applications':[]}
    directory = Path(cfg['deployment']['input_directory'])
    native_path = directory/'component-native.json'
    native = read_json(native_path,private=True) if native_path.exists() else {}
    runtime = read_json(Path(cfg['deployment']['runtime_file']),private=True)
    if phase == 'preparation':
        require(payload is None, 'Preparation cannot consume an app secret payload')
        for app_id, row in native.items():
            selected = runtime['applications'][app_id]
            result['component_native_applications'].append({
                'kind':selected['adapter'], 'database':row['identity']})
        result['component_preparation_app']=result.pop('app')
        return result
    if phase == component_guest.BACKUP_PHASE:
        import backup_agent
        require(payload is not None and payload.check()['app'] == 'backup-agent',
                'Bind the exact selected PBS preparation payload')
        require(read_json(payload.directory/'application.json', private=True) == cfg['app']['backup'],
                'Keep PBS preparation bound to the compiled guest coverage')
        result['backup_agent'] = backup_agent.configuration(cfg)
        if 'job' in cfg['app']['backup']:
            import backup_controller
            from deployment_inputs import source_hash
            bundle = '/opt/homelab-backup/framework/' + source_hash() + '/proxmox'
            sources = [path for parent in (SOURCE, SOURCE.parent/'common') for path in parent.rglob('*')
                if path.is_file() and not any(part in {'.terraform', '__pycache__', '.work'} for part in path.parts)]
            result['backup_controller_files'] = [{'source': str(path),
                'destination': str(Path(bundle)/path.relative_to(SOURCE.parent))} for path in sorted(sources)]
            result['backup_controller_directories'] = sorted({str(parent) for row in result['backup_controller_files']
                for parent in [Path(row['destination']).parent, *Path(row['destination']).parent.parents]
                if str(parent).startswith('/opt/homelab-backup/framework/')}, key=lambda path: (path.count('/'), path))
            result['backup_controller'] = backup_controller.units(read_json(Path(cfg['deployment']['input_directory'])/'backup-group.json', private=True),
                bundle+'/applications', os.getuid())
            result['backup_controller']['source_hash'] = source_hash()
            result['backup_controller']['directory'] = bundle+'/applications'
            job = cfg['app']['backup']['job']
            names = ['pbs-password', 'pbs-key'] + (['pbs-key-password'] if 'key_password' in job['secrets'] else [])
            names += ['influx-'+key for key in job['capture']['influx_tokens']]
            from private_io import sha
            result['backup_agent']['credentials'] = [
                {'source': str(payload.directory/name), 'name': name, 'sha256': sha(payload.directory/name)} for name in names]
            result['backup_agent']['staging'] = job['staging']['path']+'/.homelab-backup'
        app['start_services'] = False
        return result
    if phase==component_guest.AGENT_PHASE:
        import monitoring_agent
        require(payload is not None and payload.check()['app']=='agent',
                'Bind the exact selected monitoring agent payload')
        require(read_json(payload.directory/'application.json',private=True)=={
            'schema':'homelab-component-agent-input-v1','monitoring':cfg['app']['monitoring']},
            'Keep the selected agent metadata bound to this guest')
        selected=monitoring_agent.validate(cfg)
        require(selected['credential_file']==str(payload.directory/'monitoring-agent.json'),
                'The agent cannot read another phase payload')
        password=None
        if 'database_password_file' in selected:
            require(selected['database_password_file']==str(payload.directory/'monitoring-database-password'),
                    'The database agent cannot read another phase payload')
            password=regular(payload.directory/'monitoring-database-password',private=True).decode()
            workload=next(kind for kind in ('postgresql','mysql') if kind in selected['profiles'])
            result['zabbix_agent']={'manage_database_accounts':True,'workloads':{workload:{
                'uri':selected['database_uri'],'password_file':selected['database_password_file']}}}
        result.update(monitoring_agent_package=monitoring_agent.AGENT_PACKAGE,
            monitoring_postgresql_package=monitoring_agent.POSTGRESQL_PACKAGE,
            monitoring_agent_configuration=monitoring_agent.configuration(cfg,password))
        import monitoring_paths
        result['monitoring_agent_paths'] = monitoring_paths.PATHS.copy()
        app['start_services']=False
        return result
    app_id = cfg['deployment']['applications'][phase]['id']
    require(payload is not None and payload.check()['app']==app_id, 'Bind the selected app payload before Ansible')
    selected = read_json(payload.directory/'application.json',private=True)
    require(selected == runtime['applications'][app_id], 'Preserve the exact selected runtime descriptor')
    app.update(kind=selected['adapter'], required_paths=[{'path':row['source'],'type':row['kind']}
        for row in selected['storage_paths'].values()], health_checks=cfg['app']['service_health_checks'][phase])
    result['component_application']=selected
    result['component_fresh_directories']={'previously_owned':previously_owned, 'directories':[
        {'root':row['volume_root'],'path':row['source'],
         **{key:row['initialize'][key] for key in ('uid','gid','mode')}}
        for row in selected['storage_paths'].values() if selected['lifecycle']=='fresh' and 'initialize' in row]}
    result['component_payload_directory']=str(payload.directory)
    result['component_runtime_files']=read_json(payload.directory/'runtime-files.json',private=True)
    if 'runtime_directory' in selected['identity']:
        result['component_runtime_directory']={'directory':selected['identity']['runtime_directory'],
            'lifecycle':selected['lifecycle'],'previously_owned':previously_owned}
    result['component_helpers']=[{'source':row[0],
        'destination':row[1] if row[1].startswith('/') else '/opt/homelab-app/'+row[1],
        'mode':row[2] if len(row)==3 else '0700'} for row in HELPERS.get(selected['adapter'],[])]
    if selected['adapter'] in component_app_hooks.HANDLERS:
        hooks=component_app_hooks.descriptors(selected,compose_file='/opt/homelab-app/'+selected['project_file'])
        result['component_helpers']=hooks.pop('helpers')
        result.update(hooks)
    if selected['adapter']=='authentik' and 'allowed_callback_additions' in selected['settings']:
        result['component_helpers'].append({'source':'identity_callbacks.py',
            'destination':'/opt/homelab-app/identity_callbacks.py','mode':'0700'})
        result['component_identity_callbacks']={
            'config':selected['identity']['runtime_directory']+'/identity-callbacks.json',
            'service':selected['identity']['services']['server']}
    if selected['adapter'] in ('cloudbeaver','mqtt_explorer'):
        owner={'node':cfg['site']['node'],**{key:cfg['guest'][key] for key in ('vmid','hostname')}}
        config=selected['identity']['runtime_directory']+'/'+(
            'cloudbeaver-public.json' if selected['adapter']=='cloudbeaver' else 'mqtt-explorer-public.json')
        result['component_proxy_lifecycle']={'adapter':selected['adapter'],'owner':owner,'config':config}
        if selected['adapter']=='cloudbeaver':
            public=read_json(payload.directory/'cloudbeaver-public.json',private=True)
            result['component_jdbc']=public.get('mariadb_jdbc',{})
        else:
            result['component_proxy_lifecycle']['profile']=selected['identity']['runtime_directory']+'/'+(
                'mqtt-explorer-account.json' if 'managed_credential' in selected['settings']['broker']
                else 'mqtt-explorer-profile.json')
    if selected['adapter']=='pegaprox':
        app['pegaprox']={'key_source':str(payload.directory/'pegaprox-db-key'),
            'key_runtime_path':selected['identity']['runtime_directory']+'/pegaprox-db-key'}
    if selected['adapter']=='bitwarden':
        environment=bitwarden_runtime.environment_bytes(regular(payload.directory/'bitwarden-environment.json',private=True),
            selected['settings']['runtime'],selected['settings']['settings'])
        result['component_bitwarden']={'settings':selected['settings']['settings'],'environment':environment,
            'image':selected['software_selection']['images']['bitwarden']['image']}
    result['component_image_archives']={selected['identity']['services'][role]:image
        for role,image in selected['software_selection']['images'].items() if 'archive' in image}
    if selected['adapter']=='zabbix':
        owner={key:cfg['site'][key] for key in ('node',)}
        owner.update({key:cfg['guest'][key] for key in ('vmid','hostname')})
        result.update(monitoring_server_owner=owner,
            monitoring_server_configuration_file=str(payload.directory/'monitoring-server.json'),
            component_initial_compose_source=str(payload.directory/'initial-compose.yml'))
    if app_id in native:
        app['database']=native[app_id]['identity']
        if selected.get('database_administrators'):
            app['database_administrators']=selected['database_administrators']
        result['component_native_services']=native[app_id]['services']
        return result
    project=read_json(directory/'component-projects.json',private=True)[selected['project_name']]
    require(project['file']==selected['project_file'] and
            project['applications'][app_id]==ordered_services(selected),
            'Bind the selected services to the declared project file')
    services=project['applications'][app_id]
    peers=[service for key,rows in project['applications'].items() if key!=app_id for service in rows]
    result.update(component_compose_source=str(directory/project['file']),
        component_compose_file='/opt/homelab-app/'+project['file'], component_services=services,
        component_preflight={'project':selected['project_name'],'services':services,'peers':peers,
            'lifecycle':selected['lifecycle'],'previously_owned':previously_owned})
    if selected['adapter']=='zabbix':
        result.update(monitoring_compose_source=result['component_compose_source'],
            monitoring_compose_file=result['component_compose_file'],monitoring_services=services)
    overlay=payload.directory/'environment.yml'
    if overlay.exists() or overlay.is_symlink():
        regular(overlay,private=True)
        result.update(component_environment_source=str(overlay),
            component_environment_file='/opt/homelab-app/component-'+app_id+'-environment.yml')
    return result


def run_phase(cfg, site, work, operation, expected, phase, *, payload=None, previously_owned=False):
    require(component_inputs.binding(cfg,site)==expected, 'Static component inputs changed before Ansible')
    if payload is not None:payload.check()
    if payload is not None and phase not in ('preparation',component_guest.AGENT_PHASE,component_guest.BACKUP_PHASE):
        app=read_json(payload.directory/'application.json',private=True)
        if app['adapter']=='traefik':
            component_discovery.verify(cfg,app,regular(payload.directory/'provider-record.json',private=True))
    proxmox_guest.dhcp_admission(cfg)
    proxmox_guest.guest_trust(cfg,work)
    phase_work=operation/phase
    private_directory(phase_work,create=True)
    selected=variables(cfg,phase,payload=payload,previously_owned=previously_owned)
    phase_app=selected['component_preparation_app'] if phase=='preparation' else selected['app']
    phase_app['render_dir']=str(phase_work/'rendered')
    write(phase_work/'variables.json',selected)
    write(phase_work/'inventory.json',{'application':{'hosts':{cfg['app']['hostname']:{
        'ansible_host':cfg['app']['address'],'ansible_user':'root'}}}})
    playbook='component-preparation.yml' if phase=='preparation' else (
        'component-agent.yml' if phase==component_guest.AGENT_PHASE else
        'component-backup.yml' if phase==component_guest.BACKUP_PHASE else 'component-reconcile.yml')
    command=['ansible-playbook','-i',str(phase_work/'inventory.json'),'--private-key',
        cfg['paths']['private_key'],str(SOURCE/'ansible'/playbook),'--extra-vars','@'+str(phase_work/'variables.json')]
    from ansible_guest import ansible_environment
    environment={key:value for key,value in os.environ.items()
                 if not key.startswith(component_input_secrets.PREFIX)}
    quiet(command,ansible_environment(cfg,environment),phase_work/'application.log')
    require(component_inputs.binding(cfg,site)==expected, 'Static component inputs changed during Ansible')
    if payload is not None:payload.check()
    counts=re.findall(r'changed=(\d+)',(phase_work/'application.log').read_text())
    require(counts,'Ansible did not produce its component completion recap')
    return {'status':'passed','changed':any(int(value) for value in counts)}
