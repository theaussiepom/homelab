"""Lower source-resolved component ownership to existing engine descriptors."""
import copy
from pathlib import PurePosixPath
from component_sources import require
from component_adapters import adapter

RUNTIME_SCHEMA = 'homelab-component-runtime-v1'


def provider_config(plan, guest_id):
    """The actual existing OpenTofu module inputs, without guest-kind templates."""
    plan.check()
    require(guest_id in plan.resolved['guests'], 'component.reference')
    guest = plan.resolved['guests'][guest_id]
    context = plan.resolved['contexts'][guest['context']]
    selected = {'vmid': guest['identity']['vmid'], 'hostname': guest['identity']['hostname'],
        'cpu': guest['resources']['cpu_cores'], 'memory_mib': guest['resources']['memory_mib'],
        'root_gib': guest['resources']['root_gib'],
        'storage_id': plan.site['storage'][guest['root_storage']]['pool'],
        'template_file_id': guest['template_file_id'],
        **copy.deepcopy(guest['startup']),
        'nesting': guest['security']['nesting'], 'keyctl': guest['security']['keyctl'],
        'dns_servers': copy.deepcopy(guest['dns_servers']),
        'interfaces': copy.deepcopy(guest['provider_interfaces']),
        'volumes': {key: {'path': row['path'], 'size_gib': row['size_gib']}
                    for key, row in sorted(guest.get('volumes', {}).items(), key=lambda pair: pair[1]['slot'])},
        'volume_order': [key for key, _ in sorted(guest.get('volumes', {}).items(), key=lambda pair: pair[1]['slot'])],
        'rules': copy.deepcopy(guest['rules'])}
    devices = [plan.site['devices'][ref] for app in plan.resolved['apps'].values()
               if app['guest'] == guest_id for ref in app.get('devices', {}).values()]
    require(len(devices) <= 1, 'component.device-backend')
    if devices:
        selected['serial_device'] = {'path': devices[0]['path']}
    return {'site': {'node': context['node'], 'api_endpoint': context['api_endpoint'].rstrip('/') + '/'},
            'guest': selected,
            'ssh_public_keys': copy.deepcopy(guest.get('ssh_public_keys', context['ssh_public_keys']))}


def runtime_config(plan, guest_id):
    """Feed the actual runtime renderer, with no fixed guest-kind template."""
    plan.check()
    require(guest_id in plan.resolved['guests'], 'component.reference')
    guest = plan.resolved['guests'][guest_id]
    applications = {}
    for app_id, app in plan.resolved['apps'].items():
        if app['guest'] != guest_id:
            continue
        selected = copy.deepcopy(app)
        if app['adapter'] == 'traefik':
            selected['route_plan'] = {
                'routes': copy.deepcopy(plan.resolved['routes'].get(app_id, {})),
                **{key:copy.deepcopy(plan.resolved[key]) for key in
                   ('middlewares', 'transports', 'canonical_middlewares')}}
        selected['input_sources'] = copy.deepcopy(app.get('secret_bindings', {}))
        if app['adapter'] == 'cloudbeaver' and 'client_secret' in app.get('authentication_resolved', {}):
            source = app['authentication_resolved']['client_secret']
            selected['input_sources']['client_secret'] = copy.deepcopy(plan.site['secret_sources'][source])
        if app['adapter'] == 'mqtt_explorer' and 'credential' in app['settings']['broker']:
            source = app['settings']['broker']['credential']['secret']
            selected['input_sources']['broker_password'] = copy.deepcopy(plan.site['secret_sources'][source])
        if 'project' in app['identity']:
            project = guest['compose_projects'][app['identity']['project']]
            selected['project_name'] = project['name']
            selected['project_file'] = project['file']
        else:
            require(bool(adapter(app['adapter'])['native']), 'component.runtime-incomplete')
        selected['storage_paths'] = {}
        profile = plan.library['app_profiles'][app['profile']]
        for role, binding in app.get('storage', {}).items():
            require('asset' not in binding, 'component.runtime-incomplete')
            kind = 'root_paths' if 'root_path' in binding else 'volumes'
            key = binding.get('root_path', binding.get('volume'))
            source = str(PurePosixPath(guest[kind][key]['path']) / binding['subpath'])
            selected['storage_paths'][role] = dict(profile['storage'][role], source=source)
            if app['lifecycle'] == 'fresh' and 'initialize' in profile['storage'][role]:
                require(kind == 'volumes' and binding['subpath'] != '',
                        'component.storage-initialization-volume')
                selected['storage_paths'][role]['volume_root'] = guest['volumes'][key]['path']
        if app['adapter']=='mqtt_explorer':
            broker=selected['settings']['broker']
            if 'managed_credential' in broker:
                producer=plan.resolved['apps'][broker['target']['app']]
                owning=plan.resolved['guests'][producer['guest']]
                binding=producer['storage']['config']
                kind='root_paths' if 'root_path' in binding else 'volumes'
                ref=binding.get('root_path',binding.get('volume'))
                broker['runtime']={'project':owning['compose_projects'][producer['identity']['project']]['name'],
                    'service':producer['identity']['services']['mqtt'],
                    'config_path':str(PurePosixPath(owning[kind][ref]['path'])/binding['subpath'])}
        applications[app_id] = selected
    return {'schema': RUNTIME_SCHEMA,
            'guest': {'id': guest_id, 'memory_mib': guest['resources']['memory_mib'],
                      'os_reserve_mib': guest['effective_os_reserve_mib'], 'timezone': guest['timezone']},
            'applications': applications}
