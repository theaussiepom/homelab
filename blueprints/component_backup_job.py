"""Operational backup bindings; source resolution never opens a private input."""
import copy
import re

from component_sources import closed, identifier, named, require
import component_types as types
import component_backup_key
import backup_group
import backup_capture
import backup_policy
import backup_identity
from component_errors import ComponentError


def job(value):
    """Validate the closed public job shape before resolving any references."""
    closed(value, ('name', 'destination', 'schedule', 'clients', 'capture', 'limits'))
    require(identifier(value['name']), 'component.backup-job-name')
    destination = value['destination']
    closed(destination, ('endpoint', 'datastore', 'namespace', 'fingerprint'))
    closed(destination['endpoint'], ('external',))
    require(identifier(destination['endpoint']['external']), 'component.backup-destination')
    require(backup_policy.destination_names(destination), 'component.backup-destination')
    require(isinstance(destination['fingerprint'], str) and re.fullmatch(
        r'[0-9a-f]{2}(?::[0-9a-f]{2}){31}', destination['fingerprint']),
        'component.backup-fingerprint')
    schedule = value['schedule']
    closed(schedule, ('calendar', 'jitter_seconds'))
    require(isinstance(schedule['calendar'], str) and re.fullmatch(
        r'hourly|daily|[0-2][0-9]:[0-5][0-9]', schedule['calendar'])
        and (':' not in schedule['calendar'] or int(schedule['calendar'][:2]) < 24),
        'component.backup-schedule')
    types.integer(schedule['jitter_seconds'], 0, 3600)
    for row in named(value['clients']).values():
        closed(row, ('staging_volume', 'interface'), ('backup_id',))
        require(all(identifier(row[key]) for key in set(row) - {'backup_id'})
                and ('backup_id' not in row or backup_group.identifier(row['backup_id']) and len(row['backup_id']) <= 32),
                'component.backup-client')
    capture = value['capture']
    closed(capture, ('pause', 'database_lock', 'influx_tokens'))
    types.strings(capture['pause'], ids=True)
    types.strings(capture['database_lock'], ids=True)
    require(all(identifier(ref) for ref in named(capture['influx_tokens']).values()),
            'component.backup-secret')
    limits = value['limits']
    closed(limits, ('max_bytes', 'max_files', 'timeout_seconds'))
    types.integer(limits['max_bytes'], 1024*1024, 2**50)
    types.integer(limits['max_files'], 1, 1000000)
    types.integer(limits['timeout_seconds'], 60, 86400)


def bind(resolver, value):
    """Resolve endpoint/credential references and explicit capture permissions."""
    job(value)
    enrolled = {key: row for key, row in resolver.guests.items() if 'backup' in row}
    require(set(value['clients']) == set(enrolled), 'component.backup-client-coverage')
    recovery = component_backup_key.bind(resolver, resolver.site['backup']['recovery_public_key'])
    endpoint = resolver.endpoint(value['destination']['endpoint'])
    require(endpoint['protocol'] == 'https', 'component.backup-destination')
    capture = value['capture']
    apps = {key: app for key, app in resolver.apps.items() if app['guest'] in enrolled}
    require(set(capture['pause']) <= set(apps)
            and set(capture['database_lock']) == {key for key, app in apps.items()
                if app['adapter'] == 'mariadb'}
            and set(capture['influx_tokens']) == {key for key, app in apps.items()
                if app['adapter'] == 'influxdb'}, 'component.backup-capture-selection')

    def secret(ref):
        require(ref in resolver.site['secret_sources'], 'component.backup-secret')
        source = resolver.site['secret_sources'][ref]
        require(source['type'] == 'file', 'component.backup-file-secret')
        return copy.deepcopy(source)

    for guest_id, guest in enrolled.items():
        client = value['clients'][guest_id]
        stage = client['staging_volume']
        require(stage in guest.get('volumes', {}), 'component.backup-staging-volume')
        volume = guest['volumes'][stage]
        interface = client['interface']
        require(interface in guest['interfaces']
                and guest['interfaces'][interface].get('address', {}).get('mode') == 'static'
                and guest['interface_addresses'].get(interface) is not None,
                'component.backup-interface')
        require('backup' not in volume and volume['size_gib']*1024**3 >= 4*value['limits']['max_bytes']
                and not any(binding.get('volume') == stage for app in resolver.apps.values()
                    if app['guest'] == guest_id for binding in app.get('storage', {}).values()),
                'component.backup-staging-volume')
        context = resolver.site['contexts'][guest['context']]
        destination = {**{key: copy.deepcopy(row) for key, row in value['destination'].items()
            if key != 'endpoint'}, 'server': endpoint['address'], 'port': endpoint['port'],
            'backup_id': client.get('backup_id', 'guest-'+str(guest['identity']['vmid']))}
        require(len('/datastore/' + destination['datastore'] + '/' + destination['namespace']
                    + '/' + destination['backup_id']) <= 128, 'component.backup-namespace-path')
        managed = backup_identity.binding(destination, {'node': context['node'], **guest['identity']},
            value['name'], context['paths']['state_root'])
        guest['backup']['job'] = {
            'recovery_public_key': copy.deepcopy(recovery),
            'destination': {**destination, 'auth_id': managed['auth_id']},
            'schedule': copy.deepcopy(value['schedule']), 'limits': copy.deepcopy(value['limits']),
            'secrets': managed['secrets'],
            'staging': {'path': volume['path'], 'size_bytes': volume['size_gib']*1024**3},
            'transport': {'device': 'eth'+str(guest['interfaces'][interface]['slot']),
                'address': guest['interface_addresses'][interface]},
            'capture': {'pause': [key for key in capture['pause'] if resolver.apps[key]['guest'] == guest_id],
                'database_lock': [key for key in capture['database_lock'] if resolver.apps[key]['guest'] == guest_id],
                'influx_tokens': {key: secret(ref) for key, ref in capture['influx_tokens'].items()
                    if resolver.apps[key]['guest'] == guest_id}}}
        guest['backup']['job']['group'] = {'name': value['name'],
            'member': guest['backup']['job']['destination']['backup_id']}
        try:
            backup_policy.validate(guest['backup']['job'])
        except ValueError:
            raise ComponentError('component.backup-job-binding') from None
        for app in guest['backup'].get('applications', {}).values():
            for relation in app['databases']:
                target = relation['target']
                require('app' in target and target['app'] in resolver.apps
                        and resolver.apps[target['app']]['adapter'] == relation['type']
                        and resolver.apps[target['app']]['guest'] in enrolled,
                        'component.backup-database-producer')
        try:
            backup_capture.normalize(guest['backup'])
            backup_capture.recipes(guest['backup'])
        except ValueError:
            raise ComponentError('component.backup-capture-binding') from None
    members = {}
    for guest_id, guest in enrolled.items():
        context = resolver.site['contexts'][guest['context']]
        api = resolver.endpoint(context['api_endpoint'])
        owner = guest['identity']
        backup_id = guest['backup']['job']['destination']['backup_id']
        require(backup_id not in members, 'component.backup-member-identity')
        members[backup_id] = {'state_root': context['paths']['state_root'], 'node': context['node'],
            'vmid': owner['vmid'], 'api_address': api['address'], 'api_port': api['port'],
            'hostname': owner['hostname']}
    group = {'name': value['name'], 'members': members}
    backup_group.configuration(group)
    return {'schema': 'homelab-pbs-schedule-v1', 'group': group,
        'schedule': copy.deepcopy(value['schedule']), 'limits': copy.deepcopy(value['limits'])}
