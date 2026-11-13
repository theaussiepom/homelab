"""Resolve component value references independently of deployment readiness.

Resolution is pure source work. It produces engine input descriptors, never host
observations, generated credentials, grants, acceptance records or target calls.
"""
import copy
import hashlib
import ipaddress
import itertools
import json
from pathlib import Path
import sys

# Closed per-application contracts are shared with their installed runtime
# helpers; no fixed guest compiler/renderer is imported for these primitives.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'proxmox/applications'))

import component_sources as sources
import component_types as types
import component_exposures
import component_connections
import component_auth
import component_secrets
import component_foundations
import component_properties
import component_identity
import component_traffic
import component_monitoring
import component_admission
import component_accounts
import component_addresses
import component_backup
from component_adapters import adapter
from component_errors import at, checked

require = sources.require
RESERVED = {'validate', 'selection', 'infrastructure', 'preparation', 'agent', 'zabbix-agent', 'pbs-agent', 'backup-agent'}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class Plan:
    """A source-resolved snapshot; lowerers reject accidental post-resolution edits."""
    def __init__(self, library, site, resolved, pins):
        self.library, self.site, self.resolved, self.pins = library, site, resolved, pins
        self._seal = _digest([library, site, resolved, pins])

    def check(self):
        require(self._seal == _digest([self.library, self.site, self.resolved, self.pins]))


class Resolver:
    def __init__(self, stack_root, site_path):
        self.library, self.library_sources = sources.library(stack_root)
        self.site, self.site_sources = sources.site(site_path)
        self.guests, self.apps, self.endpoints = {}, {}, {}
        self.sockets = []
        self.policy = {}
        for kind in sources.POLICIES:
            old, new = self.library['policies'][kind], self.site['policies'][kind]
            require(not set(old) & set(new))
            self.policy[kind] = dict(old, **new)

    def validate(self):
        for collection, check in (('guest_templates', types.template), ('app_profiles', types.profile),
                                  ('software', types.software), ('runtime_profiles', types.runtime),
                                  ('health_profiles', types.health),
                                  ('monitoring_profiles', component_monitoring.profile),
                                  ('backup_profiles', component_backup.profile)):
            for name, value in self.library[collection].items():
                checked(check, value, collection, name)
        for collection, check in (('contexts', types.context), ('networks', types.network),
                                  ('guests', types.guest), ('apps', types.app)):
            for name, value in self.site[collection].items():
                checked(check, value, collection, name)
        for name, value in self.policy['network'].items():
            checked(types.network_policy, value, 'policies', 'network', name)
        for name, value in self.site.get('address_groups', {}).items():
            checked(component_addresses.group, value, 'address_groups', name)
        for name,value in self.site['storage'].items():
            with at('storage',name):
                sources.closed(value, ('context', 'pool'))
                require(value['context'] in self.site['contexts'])
                types.text(value['pool'])
        for name, value in self.site['secret_sources'].items():
            checked(component_secrets.source, value, 'secret_sources', name)
        for name,value in self.site['devices'].items():
            checked(types.device,value,'devices',name)
            with at('devices',name):
                require(value['context'] in self.site['contexts'],'component.reference')
                require(value['capability'] in self.site['contexts'][value['context']].get('capabilities', {}),
                        'component.reference')

    def image_values(self):
        references = {image for row in self.library['software'].values()
                      for image in row.get('images', {}).values()}
        if not references and not self.site['images']:
            return {}
        catalogue = sources.named(self.library_sources.document('images.json'))
        require(references <= set(catalogue) and set(self.site['images']) <= set(catalogue),
                'component.image-binding')
        # Reuse the existing declared digest/latest/versioned-archive contract;
        # the component path adds no image version or publishing mechanism.
        from image_selection import image
        result = {}
        for name, original in catalogue.items():
            value = self.site['images'].get(name, original)
            if name in self.site['images']:
                require(isinstance(original, dict) and isinstance(value, dict) and
                        set(original) == set(value) == {'local_id', 'archive', 'archive_sha256'},
                        'component.image-binding')
            with at('images', name):
                try:
                    result[name] = image(value)
                except (ValueError, TypeError, KeyError):
                    require(False, 'component.image-binding')
        return result

    def guest_values(self):
        used_ids, used_macs, used_addresses = set(), set(), set()
        for name, value in self.site['guests'].items():
            require(name not in RESERVED, 'component.reserved-id')
            require(value['context'] in self.site['contexts'] and value['template'] in self.library['guest_templates'])
            context = self.site['contexts'][value['context']]
            require('external' in context['api_endpoint'], 'component.reference')
            api = self.endpoint(context['api_endpoint'])
            authority = (api['address'], context['node'])
            require(value['identity']['vmid'] not in context['protected_guests'])
            identity = (api['address'].casefold(),api['port'],value['identity']['vmid'])
            require(identity not in used_ids,'component.guest-identity')
            used_ids.add(identity)
            template = self.library['guest_templates'][value['template']]
            guest = copy.deepcopy(value)
            for field in ('resources', 'startup', 'security'):
                guest[field] = dict(template[field], **value.get(field, {}))
            require(guest['resources']['os_reserve_mib'] < guest['resources']['memory_mib'])
            guest['display_name'] = value.get('display_name', value['identity']['hostname'])
            guest['timezone'] = value.get('timezone', context.get('timezone', 'Etc/UTC'))
            if 'monitoring' in value or 'monitoring' in template:
                guest['monitoring_profile'] = value.get('monitoring', template.get('monitoring'))
            guest.pop('monitoring', None)
            for field in ('software', 'runtime'):
                guest[field] = template.get(field, []) + value.get(field, [])
            require(value['root_storage'] in self.site['storage'] and
                    self.site['storage'][value['root_storage']]['context'] == value['context'])
            guest['provider_interfaces'] = []
            guest['interface_addresses'] = {}
            for key, row in sorted(value['interfaces'].items(), key=lambda pair: pair[1]['slot']):
                require(row['network'] in self.site['networks'])
                network = self.site['networks'][row['network']]
                require(network['context'] == value['context'])
                selected = ipaddress.IPv4Network(network['cidr'])
                address = row['address'].get('value', row['address'].get('endpoint'))
                if address is not None:
                    candidate = ipaddress.IPv4Address(address)
                    require(candidate in selected and candidate not in (selected.network_address, selected.broadcast_address))
                    allocation = (*authority, network['bridge'], network['vlan'], address)
                    require(allocation not in used_addresses)
                    used_addresses.add(allocation)
                mac = (*authority, row['mac'].lower())
                require(mac not in used_macs)
                used_macs.add(mac)
                provider = {'bridge': network['bridge'], 'vlan': network['vlan'], 'mac': row['mac'],
                            'ipv4': address + '/' + str(selected.prefixlen)
                            if row['address']['mode'] == 'static' else row['address']['mode']}
                if row.get('default_route', False):
                    require('gateway' in network)
                    provider['gateway'] = network['gateway']
                elif row['address']['mode'] == 'dhcp':
                    provider['gateway'] = None
                    provider['ipv4_endpoint'] = address + '/' + str(selected.prefixlen)
                if 'ipv6' in row:
                    provider['ipv6'] = row['ipv6']
                guest['provider_interfaces'].append(provider)
                guest['interface_addresses'][key] = address
            control = value['interfaces'][value['control_interface']]
            guest['control'] = {'interface': value['control_interface'],
                                'address': guest['interface_addresses'][value['control_interface']],
                                'mac': control['mac']}
            if 'source_policy_route' in value:
                key = value['source_policy_route']['interface']
                row = value['interfaces'][key]
                network = self.site['networks'][row['network']]
                require('gateway' in network, 'component.source-policy-route')
                selected = ipaddress.IPv4Network(network['cidr'])
                require(ipaddress.IPv4Address(network['gateway']) !=
                        ipaddress.IPv4Address(row['address']['value']), 'component.source-policy-route')
                guest['frontend_routing'] = {
                    'address': row['address']['value'] + '/' + str(selected.prefixlen),
                    'gateway': network['gateway'], 'mac': row['mac']}
            slots = []
            for row in value.get('volumes', {}).values():
                require(row['storage'] in self.site['storage'] and row['storage'] == value['root_storage'])
                slots.append(row['slot'])
            require(sorted(slots) == list(range(len(slots))))
            self.guests[name] = guest

    def role_address(self, app, name):
        require(name in app['interfaces'])
        role = app['interfaces'][name]
        if 'interface' in role:
            address = self.guests[app['guest']]['interface_addresses'][role['interface']]
            require(address is not None)
            return address
        if role['scope'] == 'guest-loopback':
            return '127.0.0.1'
        return None

    def app_values(self):
        owned_services, native_units, phases, owned_devices = set(), set(), set(), set()
        for name, value in self.site['apps'].items():
            require(name not in RESERVED, 'component.reserved-id')
            require(value['guest'] in self.guests and value['profile'] in self.library['app_profiles'])
            profile = self.library['app_profiles'][value['profile']]
            owner = adapter(profile['adapter'])
            app = copy.deepcopy(value)
            app['id'] = name
            app['adapter'] = profile['adapter']
            app['display_name'] = value.get('display_name', profile['display_name'])
            guest = self.guests[value['guest']]
            identity = copy.deepcopy(value.get('identity', {}))
            if value['lifecycle'] == 'retained':
                require({'phase', 'runtime_id'} <= set(identity))
                require(not owner['services'] or 'project' in identity)
                require(set(identity.get('services', {})) == set(owner['services']))
                require(set(identity.get('networks', {})) == set(owner['networks']))
            identity.setdefault('phase', name)
            identity.setdefault('runtime_id', name)
            require(identity['phase'] not in RESERVED, 'component.reserved-id')
            identity.setdefault('services', {})
            identity.setdefault('networks', {})
            require(set(identity['services']) <= set(owner['services']) and
                    set(identity['networks']) <= set(owner['networks']))
            if owner['services']:
                identity.setdefault('project', name)
                projects = guest.setdefault('compose_projects', {})
                if 'project' in value.get('identity', {}):
                    require(identity['project'] in projects)
                else:
                    require(identity['project'] not in projects)
                    projects[identity['project']] = {'name': 'homelab-' + value['guest'] + '-' + name}
                projects[identity['project']].setdefault('file', 'compose-' + identity['project'] + '.yml')
                require(len({row.get('file', 'compose-' + key + '.yml') for key, row in projects.items()})
                        == len(projects), 'component.project-file-conflict')
                for service in owner['services']:
                    identity['services'].setdefault(service, name + '_' + service)
                    socket_owner = (value['guest'], projects[identity['project']]['name'], identity['services'][service])
                    require(socket_owner not in owned_services)
                    owned_services.add(socket_owner)
                for network in owner['networks']:
                    identity['networks'].setdefault(network, network)
            for unit in owner['native']:
                key = (value['guest'], unit)
                require(key not in native_units)
                native_units.add(key)
            phase = (value['guest'], identity['phase'])
            require(phase not in phases)
            phases.add(phase)
            require(set(value['interfaces']) <= set(profile['interfaces']))
            require(all(not spec['required'] or key in value['interfaces'] for key, spec in profile['interfaces'].items()))
            for role, binding in value['interfaces'].items():
                scope = 'guest-interface' if 'interface' in binding else binding['scope']
                require(scope in profile['interfaces'][role]['accepts'])
                if scope == 'guest-interface':
                    require(binding['interface'] in guest['interfaces'])
                elif scope == 'app-network':
                    require(binding['network'] in owner['networks'])
            require(set(value.get('storage', {})) <= set(profile.get('storage', {})))
            for role, spec in profile.get('storage', {}).items():
                require(not spec['required'] or role in value.get('storage', {}))
                if role not in value.get('storage', {}):
                    continue
                binding = value['storage'][role]
                if 'asset' in binding:
                    require(spec['read_only'] and binding['asset'] in self.library['assets'])
                else:
                    kind = 'root_path' if 'root_path' in binding else 'volume'
                    require(binding[kind] in guest.get('root_paths' if kind == 'root_path' else 'volumes', {}))
            app['identity'] = identity
            app['role_addresses'] = {role: self.role_address(app, role) for role in app['interfaces']}
            require(set(value.get('devices', {})) <= set(profile.get('devices', {})))
            for role, requirement in profile.get('devices', {}).items():
                require(not requirement['required'] or role in value.get('devices', {}))
                if role in value.get('devices', {}):
                    device_id = value['devices'][role]
                    require(device_id in self.site['devices'])
                    device = self.site['devices'][device_id]
                    require(device['context'] == guest['context'] and device['type'] == requirement['type'])
                    key = (device['context'], device['path'])
                    require(key not in owned_devices)
                    owned_devices.add(key)
            app['health'] = {}
            for key, authored in profile.get('health', {}).items():
                if 'profile' in authored:
                    require(authored['profile'] in self.library['health_profiles'])
                    row = copy.deepcopy(self.library['health_profiles'][authored['profile']])
                    if 'source_interface' in authored:
                        row['source_interface'] = authored['source_interface']
                else:
                    row = copy.deepcopy(authored)
                if 'source_interface' in row:
                    require(row['source_interface'] in app['interfaces'] and
                            'interface' in app['interfaces'][row['source_interface']])
                app['health'][key] = row
            require('mariadb_jdbc' not in value.get('properties', {}), 'component.software-authority')
            properties = dict(profile.get('properties', {}), **value.get('properties', {}))
            if app['adapter'] in component_foundations.OWNED:
                checked(lambda selected: component_foundations.validate(app['adapter'], selected),
                        properties, 'apps', name, 'properties')
            else:
                checked(lambda selected: component_properties.validate(app['adapter'], selected),
                        properties, 'apps', name, 'properties')
            app['properties'] = properties
            self.apps[name] = app

    def socket(self, scope, address, protocol, port, owner):
        for old_scope, old_address, old_protocol, old_port, old_owner in self.sockets:
            if old_scope == scope and old_protocol == protocol and old_port == port:
                overlap = address == old_address or '0.0.0.0' in (address, old_address)
                require(not overlap or owner == old_owner and address == old_address)
        self.sockets.append((scope, address, protocol, port, owner))

    def external_values(self):
        def external(name, trail):
            require(name not in trail, 'component.reference-cycle')
            require(name in self.site['external_endpoints'], 'component.reference')
            if ('external', name) in self.endpoints:
                return self.endpoints[('external', name)]
            row = self.site['external_endpoints'][name]
            sources.closed(row, ('protocol', 'address', 'port'), ('transport',))
            require(row['protocol'] in ('http', 'https', 'tcp', 'udp'))
            if isinstance(row['address'], dict):
                sources.closed(row['address'], ('external',))
                require(sources.identifier(row['address']['external']))
                address = external(row['address']['external'], trail | {name})['address']
            else:
                address = types.text(row['address'])
                require(not any(char in address for char in '/?#@\r\n '))
            types.integer(row['port'], 1, 65535)
            result = dict(row, address=address)
            self.endpoints[('external', name)] = result
            return result
        for name in self.site['external_endpoints']:
            with at('external_endpoints', name):
                external(name, set())

    def endpoint_values(self):
        for name, app in self.apps.items():
            profile = self.library['app_profiles'][app['profile']]
            listeners = {}
            for listener_id, authored in profile.get('listeners', {}).items():
                listener = copy.deepcopy(authored)
                if app['adapter'] == 'unbound' and listener.get('publish', {}).get('scope') == 'guest-loopback':
                    listener['publish']['port'] = app['properties'].get('publish_port', 5335)
                require(listener['interface'] in app['interfaces'])
                role = app['interfaces'][listener['interface']]
                private = listener['namespace'] == 'app-network'
                require(private == (role.get('scope') == 'app-network'))
                actual = ('0.0.0.0' if listener['bind'] == 'wildcard' else '127.0.0.1'
                          if listener['bind'] == 'loopback' else self.role_address(app, listener['interface']))
                require(actual is not None)
                service = app['identity']['services'].get(listener['service'], listener['service'])
                project = self.guests[app['guest']].get('compose_projects', {}).get(
                    app['identity'].get('project'), {}).get('name')
                scope = (app['guest'], 'container', project, service) if private else (app['guest'], 'host')
                owner = (name, service, listener['namespace'], actual, listener['port'])
                self.socket(scope, actual, listener['protocol'], listener['port'], owner)
                result = dict(listener, actual_bind=actual)
                if 'publish' in listener:
                    require(private)
                    publication = listener['publish']
                    address = ('127.0.0.1' if publication['scope'] == 'guest-loopback'
                               else self.role_address(app, publication['interface']))
                    require(address is not None)
                    self.socket((app['guest'], 'host'), address, listener['protocol'], publication['port'], owner)
                    result['publication_address'] = address
                listeners[listener_id] = result
            app['listeners'] = listeners
            for endpoint_id, endpoint in profile.get('endpoints', {}).items():
                if 'internal' in endpoint:
                    if app['properties'].get('dashboard', False):
                        self.endpoints[('app', name, endpoint_id)] = {'internal': 'dashboard',
                            'service': 'api@internal', 'app': name, 'guest': app['guest']}
                    continue
                listener = listeners[endpoint['listener']]
                require(endpoint['via'] in app['interfaces'])
                address = self.role_address(app, endpoint['via'])
                if 'publish' in listener:
                    require(address == listener['publication_address'])
                    port = listener['publish']['port']
                elif listener['namespace'] == 'host':
                    require(address is not None and listener['actual_bind'] in ('0.0.0.0', address))
                    port = listener['port']
                else:
                    require(address is None)
                    address = app['identity']['services'][listener['service']]
                    port = listener['port']
                require(('udp' if endpoint['protocol'] == 'udp' else 'tcp') == listener['protocol'])
                self.endpoints[('app', name, endpoint_id)] = {'address': address, 'port': port,
                    'protocol': endpoint['protocol'], 'guest': app['guest'], 'app': name}

    def endpoint(self, reference):
        types.endpoint(reference)
        key = (('external', reference['external']) if 'external' in reference else
               ('app', reference['app'], reference['endpoint']))
        require(key in self.endpoints)
        return self.endpoints[key]

    def context_values(self):
        result = {}
        for name, context in self.site['contexts'].items():
            require(all(secret in self.site['secret_sources'] for secret in context['credentials'].values()))
            api = self.endpoint(context['api_endpoint'])
            require('external' in context['api_endpoint'] and api['protocol'] == 'https' and api['port'] == 8006)
            result[name] = dict(context, api_endpoint='https://' + api['address'] + ':8006')
        for name, guest in self.guests.items():
            context = self.site['contexts'][guest['context']]
            references = guest.get('dns_servers', context['dns_servers'])
            guest['dns_servers'] = []
            for reference in references:
                selected = self.endpoint(reference)
                require(selected.get('port') == 53 and selected.get('protocol') in ('tcp', 'udp'))
                types.ip(selected['address'])
                if selected['address'] not in guest['dns_servers']:
                    guest['dns_servers'].append(selected['address'])
        return result

    def policy_values(self, guest):
        result = []
        for value in guest.get('network_policy', []):
            binding = {'policy': value} if isinstance(value, str) else value
            require(binding['policy'] in self.policy['network'])
            used = {'interfaces': set(), 'networks': set(), 'endpoints': set(), 'address_groups': set()}

            def resolve(kind, role):
                used[kind].add(role)
                require(role in binding.get(kind, {}))
                selected = binding[kind][role]
                if kind == 'address_groups':
                    return component_addresses.selected(selected, self.address_groups)
                if kind == 'endpoints':
                    return self.endpoint(selected)
                if kind == 'interfaces':
                    if isinstance(selected, dict):
                        require(selected['app'] in self.apps)
                        app = self.apps[selected['app']]
                        require(selected['interface'] in app['interfaces'] and
                                'interface' in app['interfaces'][selected['interface']])
                        address = self.role_address(app, selected['interface'])
                        candidate = ipaddress.IPv4Address(address)
                        require(not (candidate.is_loopback or candidate.is_unspecified or
                                     candidate.is_multicast or candidate.is_link_local))
                        return address
                    require(selected in guest['interfaces'])
                    return guest['interface_addresses'][selected]
                require(selected in self.site['networks'] and self.site['networks'][selected]['context'] == guest['context'])
                return self.site['networks'][selected]['cidr']

            for authored in self.policy['network'][binding['policy']]['rules']:
                row = copy.deepcopy(authored)
                expansion = {}
                if 'interface' in row:
                    role = row['interface']
                    require(isinstance(binding.get('interfaces', {}).get(role), str))
                    resolve('interfaces', role)
                    row['interface'] = 'net' + str(guest['interfaces'][binding['interfaces'][role]]['slot'])
                for field in ('source', 'destination', 'port'):
                    if isinstance(row.get(field), dict):
                        ref_kind, role = next(iter(row[field].items()))
                        if ref_kind == 'address_group':
                            require(field in ('source', 'destination'))
                            expansion[field] = resolve('address_groups', role)
                        elif ref_kind == 'endpoint':
                            selected = resolve('endpoints', role)
                            if field == 'port':
                                require('port' in selected and 'protocol' in selected and
                                        ('udp' if selected['protocol'] == 'udp' else 'tcp') == row['proto'])
                                row[field] = str(selected['port'])
                            else:
                                types.ip(selected.get('address'))
                                row[field] = selected['address'] + '/32'
                        else:
                            require(field != 'port')
                            selected = resolve('networks' if ref_kind == 'network' else 'interfaces', role)
                            require(selected is not None)
                            row[field] = selected if ref_kind == 'network' else selected + '/32'
                source_values = expansion.get('source', [row.get('source')])
                destination_values = expansion.get('destination', [row.get('destination')])
                require(len(source_values) * len(destination_values)
                        <= component_addresses.MAX_MEMBERS - len(result), 'component.address-group-size')
                for source, destination in itertools.product(source_values, destination_values):
                    selected = copy.deepcopy(row)
                    for field, value in (('source', source), ('destination', destination)):
                        if field in expansion:
                            selected[field] = value
                    types.rule_family(selected)
                    result.append(selected)
            require(all(set(binding.get(kind, {})) == refs for kind, refs in used.items()))
        return result

    def execution_values(self, images):
        """Resolve declared software/security; never merge arbitrary Compose bags."""
        software, runtime = self.library['software'], self.library['runtime_profiles']
        used_images = set()

        def runtime_values(refs, guest):
            result, package_refs, native = {}, [], None
            minimums = {}
            reserve = guest['resources']['os_reserve_mib']
            for name in refs:
                require(name in runtime, 'component.reference')
                row = runtime[name]
                for service, limits in row.get('minimums', {}).get('containers', {}).items():
                    selected = minimums.setdefault(service, {})
                    for key, value in limits.items():
                        selected[key] = max(selected.get(key, value), value)
                if 'native' in row:
                    require(native is None or native == row['native'], 'component.runtime-conflict')
                    native = copy.deepcopy(row['native'])
                package_refs.extend(row.get('packages', []))
                for key, required in row.get('requirements', {}).items():
                    if key == 'os_reserve_mib':
                        reserve = max(reserve, required)
                    else:
                        require(not required or guest['security'][key], 'component.runtime-requirement')
                for service, settings in row.get('containers', {}).items():
                    target = result.setdefault(service, {})
                    require(all(key not in target or target[key] == item for key, item in settings.items()),
                            'component.runtime-conflict')
                    target.update(copy.deepcopy(settings))
            return result, package_refs, native, reserve, minimums

        def software_values(refs, *, include_images=True):
            packages, versions, selected_images, repositories = [], {}, {}, {}
            for name in refs:
                require(name in software, 'component.reference')
                row = software[name]
                for package in row.get('packages', []):
                    key, version = package.split('=', 1)
                    require(key not in versions or versions[key] == version, 'component.software-conflict')
                    if key not in versions:
                        packages.append(package)
                        versions[key] = version
                for role, image_id in row.get('images', {}).items():
                    require(image_id in images, 'component.reference')
                    if include_images:
                        used_images.add(image_id)
                        require(role not in selected_images or selected_images[role] == images[image_id],
                                'component.software-conflict')
                        selected_images[role] = copy.deepcopy(images[image_id])
                for repository in row.get('repositories', []):
                    require(repository['key_asset'] in self.library['assets'], 'component.reference')
                    key = repository['name']
                    require(key not in repositories or repositories[key] == repository, 'component.software-conflict')
                    repositories[key] = copy.deepcopy(repository)
            return {'packages': packages, 'images': selected_images, 'repositories': list(repositories.values())}

        for guest_id, guest in self.guests.items():
            guest_containers, package_refs, guest_native, reserve, guest_minimums = runtime_values(guest['runtime'], guest)
            require(not guest_containers and guest_native is None and not guest_minimums, 'component.runtime-scope')
            guest_software = guest['software'] + package_refs + component_backup.software(self, guest)
            total = 0
            for app in self.apps.values():
                if app['guest'] != guest_id:
                    continue
                profile = self.library['app_profiles'][app['profile']]
                containers, additions, native, app_reserve, minimums = runtime_values(profile.get('runtime', []) + app.get('runtime', []), guest)
                reserve = max(reserve, app_reserve)
                selected = software_values(profile.get('software', []) + app.get('software', []) + additions)
                owner = adapter(app['adapter'])
                require(bool(owner['native']) == (native is not None), 'component.native-budget')
                if native is not None:
                    total += native['memory_mib']
                    app['native_requirements'] = native
                require(set(containers) <= set(owner['services']) and set(selected['images']) <= set(owner['services']),
                        'component.runtime-scope')
                overrides = app.get('resources', {}).get('containers', {})
                require(set(overrides) <= set(containers) and set(minimums) <= set(containers),
                        'component.resource-service')
                for service, fields in overrides.items():
                    containers[service].update(fields)
                for service, fields in minimums.items():
                    require(all(key in containers[service] and containers[service][key] >= value
                                for key, value in fields.items()), 'component.resource-minimum')
                for service, settings in containers.items():
                    require({'memory_mib', 'cpu_limit', 'pids_limit'} <= set(settings), 'component.runtime-incomplete')
                    total += settings['memory_mib']
                    if settings.get('cap_add'):
                        require(app['adapter'] == 'homeassistant' and service == 'homeassistant'
                                and 'mdns' in app['properties'], 'component.runtime-capability')
                if app['adapter'] == 'homeassistant' and 'mdns' in app['properties']:
                    mdns = sources.closed(app['properties']['mdns'], ('interface', 'startup'))
                    require(mdns['interface'] in app['interfaces'] and
                            'interface' in app['interfaces'][mdns['interface']] and
                            mdns['startup'] in app.get('storage', {}) and
                            profile['storage'][mdns['startup']]['target'] == '/startup' and
                            profile['storage'][mdns['startup']]['read_only'] is True and
                            containers.get('homeassistant', {}).get('cap_add') == ['NET_ADMIN'],
                            'component.runtime-capability')
                app['containers'] = containers
                app['software_selection'] = selected
                guest_software += profile.get('software', []) + app.get('software', []) + additions
            guest['software_selection'] = software_values(guest_software, include_images=False)
            # Images are app-scoped: two different apps may deliberately use the
            # same local service role in distinct projects. Guest packages/repos
            # aggregate, while their image-role keys never become one namespace.
            guest['software_selection'].pop('images')
            guest['effective_os_reserve_mib'] = max(256, reserve)
            require(total == 0 or total + guest['effective_os_reserve_mib']
                    <= guest['resources']['memory_mib'], 'component.memory-budget')

        return used_images

    def resolve(self, disabled=None, *, admit=False):
        self.validate()
        self.address_groups = component_addresses.resolve(self.site.get('address_groups', {}), self.site['networks'])
        images = self.image_values()
        self.external_values()
        self.guest_values()
        self.app_values()
        component_secrets.bind(self)
        self.endpoint_values()
        exposure = component_exposures.Exposures(self)
        exposures = exposure.bind()
        authentication = component_auth.bind(self, exposure)
        self.exposure_values = exposures
        self.authentication_values = authentication
        for app_id, value in authentication['authentication'].items():
            self.apps[app_id]['authentication_resolved'] = value
        dependencies = component_connections.bind(self, exposure)
        contexts = self.context_values()
        for guest in self.guests.values():
            guest['rules'] = self.policy_values(guest)
        used_images = self.execution_values(images)
        require(set(self.site['images']) <= used_images, 'component.image-binding-unused')
        component_foundations.bind(self)
        for app_id, settings in component_properties.bind(self).items():
            self.apps[app_id]['settings'] = settings
        canonical_accounts = component_accounts.bind(self, dependencies['accounts'])
        component_identity.bind(self)
        monitoring = component_monitoring.bind(self, exposure)
        backup = component_backup.bind(self)
        component_traffic.bind(self, exposure)
        require(disabled is None or isinstance(disabled, list), 'component.disabled')
        disabled = [] if disabled is None else disabled
        require(all(isinstance(key, str) and key in self.guests for key in disabled)
                and len(set(disabled)) == len(disabled), 'component.disabled')
        enabled = [key for key in self.guests if key not in disabled]
        require(all(target in enabled for key in enabled
                    for target in dependencies['guest_dependencies'][key]), 'component.disabled-dependency')
        require(monitoring is None or not enabled or monitoring['guest'] in enabled,
                'component.monitoring-selection')
        require(type(admit) is bool, 'component.admission')
        if admit:
            component_admission.admit(self, enabled)
        resolved = {'contexts': contexts, 'guests': self.guests, 'apps': self.apps,
                    'endpoints': {'/'.join(key): value for key, value in self.endpoints.items()},
                    'images': images}
        resolved.update(enabled=enabled)
        if self.address_groups:
            resolved['address_groups'] = copy.deepcopy(self.address_groups)
        if monitoring is not None:
            resolved['monitoring'] = monitoring
        if backup is not None:
            resolved['backup'] = backup
        resolved.update(exposures)
        resolved.update(dependencies)
        resolved['accounts'] = canonical_accounts
        resolved.update(authentication)
        return Plan(self.library, self.site, resolved,
                    {'library': self.library_sources.pins, 'site': self.site_sources.pins})


def resolve(stack_root, site_path, disabled=None, *, admit=False):
    return Resolver(Path(stack_root), Path(site_path)).resolve(disabled, admit=admit)
