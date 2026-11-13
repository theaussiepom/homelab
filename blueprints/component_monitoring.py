"""Explicit root monitoring expansion over selected component ownership."""
import copy
import ipaddress

from component_errors import at
from component_sources import closed, identifier, require
import component_types as types

PROFILES = {'linux', 'docker', 'postgresql', 'mysql', 'influxdb'}


def profile(value):
    closed(value, ('type', 'profiles'))
    require(value['type'] == 'zabbix-agent', 'component.monitoring-profile')
    types.strings(value['profiles'])
    require(bool(value['profiles']) and set(value['profiles']) <= PROFILES, 'component.monitoring-profile')


def reference(value):
    closed(value, ('profile',))
    require(identifier(value['profile']), 'component.reference')


def server(resolver):
    if 'zabbix' not in resolver.site:
        return None
    selected = resolver.site['zabbix']
    if selected is None:
        candidates = [key for key, app in resolver.apps.items() if app['adapter'] == 'zabbix']
        require(len(candidates) == 1, 'component.monitoring-server')
        return candidates[0]
    key = selected['server']
    require(key in resolver.apps and resolver.apps[key]['adapter'] == 'zabbix', 'component.monitoring-server')
    return key


def source_address(guest, destination):
    """Connected longest prefix, else the one explicit ordinary route."""
    target = ipaddress.IPv4Address(destination)
    nics = []
    for nic in guest['provider_interfaces']:
        text = nic.get('ipv4_endpoint') if nic['ipv4'] == 'dhcp' else nic['ipv4']
        if text == 'manual':
            continue
        endpoint = ipaddress.IPv4Interface(text)
        nics.append((nic, endpoint))
    connected = [(nic, ip) for nic, ip in nics if target in ip.network]
    if connected:
        prefix = max(ip.network.prefixlen for _, ip in connected)
        choices = [(nic, ip) for nic, ip in connected if ip.network.prefixlen == prefix]
    else:
        choices = [(nic, ip) for nic, ip in nics if 'gateway' in nic]
    require(len(choices) == 1, 'component.network-source')
    return str(choices[0][1].ip)


def rule(direction, source, destination, port):
    return {'direction': direction, 'source': source + '/32', 'destination': destination + '/32',
            'proto': 'tcp', 'port': str(port), 'comment': 'Blueprint Zabbix monitoring'}


def bind(resolver, exposures):
    """Expand the selected monitoring edges without changing transport roles."""
    selected = server(resolver)
    if selected is None:
        return None
    application = resolver.apps[selected]
    owning_guest = resolver.guests[application['guest']]
    endpoint = resolver.endpoint({'app': selected, 'endpoint': 'server_endpoint'})
    require(endpoint.get('protocol') == 'tcp' and endpoint.get('port') == 10051,
            'component.monitoring-server')
    address = endpoint['address']
    # The existing root feature is an explicit grant capability. Ordinary value
    # references and connections never call this expansion or add these rules.
    if 'origin' in application:
        exposure = exposures.resolved[application['origin']['exposure']]
        ingress = resolver.apps[exposure['ingress_target']['app']]
        guest = resolver.guests[ingress['guest']]
        web = exposure['target']
        guest['rules'].append(rule('out', source_address(guest, web['address']),
                                   web['address'], web['port']))
    members = []
    for guest_id, guest in resolver.guests.items():
        with at('guests', guest_id, 'monitoring'):
            references = [guest.get('monitoring_profile')]
            references += [resolver.library['app_profiles'][app['profile']].get('monitoring')
                           for app in resolver.apps.values() if app['guest'] == guest_id]
            profiles = []
            for ref in references:
                if ref is None:
                    continue
                reference(ref)
                key = ref['profile']
                require(key in resolver.library['monitoring_profiles'], 'component.reference')
                for value in resolver.library['monitoring_profiles'][key]['profiles']:
                    if value not in profiles:
                        profiles.append(value)
            require('linux' in profiles, 'component.monitoring-profile')
            context = resolver.site['contexts'][guest['context']]
            hostname = context['node'] + '-' + str(guest['identity']['vmid'])
            guest['monitoring'] = {'hostname': hostname, 'psk_identity': hostname,
                'server_active': address + ':10051', 'profiles': profiles,
                'server_vmid': owning_guest['identity']['vmid'],
                'server_hostname': owning_guest['identity']['hostname'],
                'credential_file': '${inputs}/monitoring-agent.json'}
            member = {'guest': guest_id, 'vmid': guest['identity']['vmid'],
                'guest_hostname': guest['identity']['hostname'], 'hostname': hostname,
                'psk_identity': hostname, 'profiles': list(profiles)}
            members.append(member)
            if guest_id != application['guest']:
                source = source_address(guest, address)
                guest['rules'].append(rule('out', source, address, 10051))
                owning_guest['rules'].append(rule('in', source, address, 10051))
            for app in resolver.apps.values():
                if app['guest'] != guest_id or app['adapter'] not in ('postgresql', 'mariadb'):
                    continue
                require('database_uri' not in guest['monitoring'], 'component.monitoring-database')
                target = '127.0.0.1' if app['adapter'] == 'postgresql' else app['role_addresses']['service_interface']
                port = 5432 if app['adapter'] == 'postgresql' else 3306
                guest['monitoring']['database_uri'] = 'tcp://' + target + ':' + str(port)
                guest['monitoring']['database_password_file'] = '${inputs}/monitoring-database-password'
    metadata = owning_guest['monitoring']
    metadata['members'] = members
    metadata['server_file'] = '${inputs}/monitoring-server.json'
    context = resolver.site['contexts'][owning_guest['context']]
    api = resolver.endpoint(context['api_endpoint'])
    metadata['proxmox'] = {'hostname': context['node'], 'endpoint': 'https://' + api['address'] + ':8006/',
                           'ca_file': context['trust']['ca_file']}
    require(len({row['hostname'] for row in members}) == len(members), 'component.monitoring-identity')
    for role, kind, port in (('database', 'postgresql', 5432), ('metrics', 'influxdb', 8086)):
        connection = application['resolved_connections'].get(role)
        if connection is None:
            continue
        target = connection['target']
        require(connection['type'] == kind and target.get('port') == port and target.get('app') in resolver.apps
                and resolver.apps[target['app']]['adapter'] == kind, 'component.monitoring-target')
        producer = resolver.apps[target['app']]
        target_guest = resolver.guests[producer['guest']]
        source = source_address(owning_guest, target['address'])
        require(source == connection['source_address'], 'component.connection-source')
        metadata[kind + '_address'] = target['address']
        owning_guest['rules'].append(rule('out', source, target['address'], port))
        target_guest['rules'].append(rule('in', source, target['address'], port))
        if kind == 'postgresql':
            target_guest['monitoring']['storage_password_file'] = '${inputs}/monitoring-storage-password'
            producer['monitoring_hba_source'] = source
        else:
            for member in members:
                if member['guest'] == producer['guest']:
                    member['url'] = 'http://' + target['address'] + ':8086'
    return {'server': selected, 'guest': application['guest']}
