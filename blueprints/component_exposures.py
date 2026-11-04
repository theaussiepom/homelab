"""Resolve authored DNS/HTTPS exposure facts without inventing access or waits."""
import copy
import ipaddress
import re
from component_errors import at
from component_sources import closed, named, require, identifier
import component_types as types


def host(value):
    require(isinstance(value, str) and 0 < len(value) <= 253 and
            all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in value.split('.')), 'component.hostname')
    return value


def alias_host(value):
    """Docker-local alias metadata; this is not a DNS/URL publication."""
    require(isinstance(value, str) and 0 < len(value) <= 253 and
            all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?', label)
                for label in value.split('.')), 'component.hostname')
    return value


def origin_reference(value):
    closed(value, ('exposure',), ('domain',))
    require(all(identifier(item) for item in value.values()), 'component.reference')


class Exposures:
    def __init__(self, resolver):
        self.resolver = resolver
        self.domains = resolver.site['domains']
        self.records, self.routes, self.resolved, self.middlewares = {}, {}, {}, {}

    def validate_policies(self):
        for name, value in self.domains.items():
            with at('domains', name):
                host(value)
        for name, value in self.resolver.site.get('host_aliases', {}).items():
            with at('host_aliases', name):
                closed(value, ('hostname',))
                alias_host(value['hostname'])
        for name, value in self.resolver.policy['tls'].items():
            with at('policies', 'tls', name):
                closed(value, ('type', 'resolver'))
                require(value['type'] == 'acme' and identifier(value['resolver']))
        for name, value in self.resolver.policy['middlewares'].items():
            with at('policies', 'middlewares', name):
                require(isinstance(value, dict))
                if value.get('type') == 'forward-auth':
                    closed(value, ('type', 'endpoint'))
                    endpoint = self.resolver.endpoint(value['endpoint'])
                    require(endpoint.get('protocol') in ('http', 'https') and 'address' in endpoint,
                            'component.authentication')
                    self.middlewares[name] = dict(value, target=copy.deepcopy(endpoint))
                elif value.get('type') == 'default-headers':
                    closed(value, ('type',))
                    self.middlewares[name] = copy.deepcopy(value)
                elif value.get('type') == 'ip-allow-list':
                    closed(value, ('type', 'ranges'))
                    require(isinstance(value['ranges'], list) and bool(value['ranges']))
                    ranges = []
                    for row in value['ranges']:
                        types.rule_address(row)
                        if isinstance(row, dict):
                            closed(row, ('network',))
                            require(row['network'] in self.resolver.site['networks'], 'component.reference')
                            row = self.resolver.site['networks'][row['network']]['cidr']
                        ranges.append(row)
                    self.middlewares[name] = dict(value, ranges=ranges)
                elif value.get('type') == 'canonical-home-redirect':
                    closed(value, ('type', 'app'))
                    require(value['app'] in self.resolver.apps, 'component.reference')
                    self.middlewares[name] = copy.deepcopy(value)
                else:
                    require(False, 'component.middleware')

    def bind(self):
        self.validate_policies()
        used_hosts = set()
        for name, value in self.resolver.site['exposures'].items():
            with at('exposures', name):
                require(isinstance(value, dict) and value.get('type') in ('http', 'dns'))
                http = value['type'] == 'http'
                closed(value, ('type', 'endpoint', 'domain', 'ingress', 'tls') if http else
                       ('type', 'endpoint', 'domain', 'resolver'),
                       ('aliases', 'middlewares', 'resolver', 'transport') if http else ('aliases',))
                types.endpoint(value['endpoint'])
                endpoint = self.resolver.endpoint(value['endpoint'])
                types.strings(value.get('aliases', []), ids=True)
                names = [value['domain'], *value.get('aliases', [])]
                require(all(item in self.domains for item in names) and len(set(names)) == len(names),
                        'component.reference')
                hosts = [self.domains[item] for item in names]
                for hostname in hosts:
                    host(hostname)
                folded = {item.lower() for item in hosts}
                require(len(folded) == len(hosts) and not folded & used_hosts, 'component.hostname-conflict')
                used_hosts.update(folded)
                selected = dict(value, hosts=hosts, target=copy.deepcopy(endpoint))
                if http:
                    ingress = self.resolver.endpoint(value['ingress'])
                    require(ingress.get('protocol') == 'https' and ingress.get('app') in self.resolver.apps
                            and self.resolver.apps[ingress['app']]['adapter'] == 'traefik', 'component.ingress')
                    if 'app' in endpoint and 'internal' not in endpoint:
                        try:
                            address = ipaddress.IPv4Address(endpoint['address'])
                        except ipaddress.AddressValueError:
                            require(False, 'component.exposure-target-scope')
                        require(not address.is_loopback, 'component.exposure-target-scope')
                    require(value['tls'] in self.resolver.policy['tls'], 'component.reference')
                    require('transport' not in value or (value['transport'] in self.resolver.policy['transport']
                            and endpoint.get('protocol') == 'https'), 'component.transport')
                    types.strings(value.get('middlewares', []), ids=True)
                    require(set(value.get('middlewares', [])) <= set(self.middlewares), 'component.reference')
                    require(endpoint.get('internal') == 'dashboard' or endpoint.get('protocol') in ('http', 'https'),
                            'component.exposure')
                    if endpoint.get('internal'):
                        require(endpoint['app'] == ingress['app'] and
                                self.resolver.apps[endpoint['app']]['properties'].get('dashboard') is True and
                                any(self.middlewares[key]['type'] == 'forward-auth'
                                    for key in value.get('middlewares', [])), 'component.authentication')
                    selected['ingress_target'] = copy.deepcopy(ingress)
                    self.routes.setdefault(ingress['app'], {})[name] = selected
                    address = ingress['address']
                else:
                    require('address' in endpoint and 'internal' not in endpoint, 'component.exposure')
                    address = endpoint['address']
                if 'resolver' in value:
                    resolver = value['resolver']
                    require(resolver in self.resolver.apps and self.resolver.apps[resolver]['adapter'] == 'pihole',
                            'component.reference')
                    types.ip(address)
                    records = self.records.setdefault(resolver, {})
                    records.update({selected_host: address for selected_host in hosts})
                self.resolved[name] = selected
        # Enabling the static API does not by itself create an authenticated
        # endpoint. An unexposed internal service cannot be used as a socket ref.
        internal = {row['target']['app'] for row in self.resolved.values() if row['target'].get('internal')}
        for key, endpoint in list(self.resolver.endpoints.items()):
            if endpoint.get('internal') and endpoint['app'] not in internal:
                del self.resolver.endpoints[key]
        for app in self.resolver.apps.values():
            if 'origin' in app:
                value = app['origin']
                origin_reference(value)
                require(value['exposure'] in self.resolved, 'component.reference')
                selected = self.resolved[value['exposure']]
                require(selected['type'] == 'http' and selected['target'].get('app') == app['id'], 'component.origin')
                domain = value.get('domain', selected['domain'])
                require(domain in [selected['domain'], *selected.get('aliases', [])], 'component.origin')
                ingress = selected['ingress_target']
                app['origin_url'] = ('https://' + self.domains[domain]
                                     + (':' + str(ingress['port']) if ingress['port'] != 443 else ''))
        return {'exposures': self.resolved, 'dns_records': self.records,
                'routes': self.routes, 'middlewares': self.middlewares}

    def hostname(self, reference, target):
        if isinstance(reference, dict) and set(reference) == {'alias'}:
            aliases = self.resolver.site.get('host_aliases', {})
            require(identifier(reference['alias']) and reference['alias'] in aliases,
                    'component.reference')
            return alias_host(closed(aliases[reference['alias']], ('hostname',))['hostname'])
        if isinstance(reference, dict) and set(reference) == {'domain'}:
            require(identifier(reference['domain']) and reference['domain'] in self.domains,
                    'component.reference')
            return host(self.domains[reference['domain']])
        origin_reference(reference)
        require(reference['exposure'] in self.resolved, 'component.reference')
        selected = self.resolved[reference['exposure']]
        owner = selected['target']
        require('internal' not in owner and (owner.get('app') == target.get('app') if 'app' in target
                else owner.get('address') == target.get('address')), 'component.origin')
        domain = reference.get('domain', selected['domain'])
        require(domain in [selected['domain'], *selected.get('aliases', [])], 'component.origin')
        return self.domains[domain]
