"""Bind the explicitly selected container DNS capability and its port-53 grants.

Host DNS and deployment dependencies remain separate. Only selected Compose
applications receive these resolvers; native services retain guest OS DNS.
"""
import ipaddress

from component_errors import at
from component_sources import require
from component_traffic import source_address, nic, check


def bind(resolver):
    for app_id, app in resolver.apps.items():
        profile = resolver.library['app_profiles'][app['profile']]
        mode = app.get('runtime_dns', profile.get('runtime_dns', 'context'))
        guest_id = app['guest']
        guest = resolver.guests[guest_id]
        references = resolver.site['contexts'][guest['context']].get('runtime_dns_servers', [])
        if mode == 'host' or not references or not app['containers']:
            continue
        with at('apps', app_id, 'runtime_dns'):
            addresses = []
            for reference in references:
                target = resolver.endpoint(reference)
                require(target['port'] == 53 and target['protocol'] in ('udp', 'tcp'),
                        'component.runtime-dns-endpoint')
                try:
                    address = ipaddress.IPv4Address(target['address'])
                except ipaddress.AddressValueError:
                    require(False, 'component.runtime-dns-address')
                require(not (address.is_loopback or address.is_unspecified or
                             address.is_multicast or address.is_link_local),
                        'component.runtime-dns-address')
                address = str(address)
                if address in addresses:
                    continue
                addresses.append(address)
                owner = target.get('guest')
                if owner == guest_id:
                    continue
                source = source_address(guest, address)
                for protocol in ('udp', 'tcp'):
                    common = {'comment': 'Application runtime DNS', 'proto': protocol,
                              'port': '53', 'source': source + '/32',
                              'destination': address + '/32'}
                    rules = [(guest_id, 'out', source)]
                    if owner is not None:
                        rules.append((owner, 'in', address))
                    for selected, direction, interface_address in rules:
                        peer = resolver.guests[selected]
                        rule = dict(common, direction=direction,
                                    interface=nic(peer, interface_address))
                        if rule not in peer['rules']:
                            peer['rules'].append(rule)
                    check(resolver.guests, guest_id, owner, source, address, protocol, 53)
            app['runtime_dns_servers'] = addresses
