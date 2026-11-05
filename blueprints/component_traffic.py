"""Admit selected communication against explicit guest ACCEPT rules, without I/O.

References never add rules or waits. Unmanaged peers have no guest firewall owned
by this compiler. Hostname peers require an explicitly unrestricted destination
rule; this module does not resolve DNS or infer an address allocation.
"""
from dataclasses import dataclass
import ipaddress

from component_errors import at
from component_sources import require
from component_monitoring import source_address
import component_types as types


@dataclass(frozen=True)
class Flow:
    source_address: str
    target_address: str
    protocol: str
    port: int | None


def permits(rules, direction, flow, interface):
    """The existing finite network/port matcher, using validated ACCEPT rows."""
    def network(value,address):
        if value is None:
            return True
        selected=ipaddress.ip_network(value,strict=False)
        try:
            target=ipaddress.ip_address(address)
        except ValueError:
            return selected.prefixlen==0 and selected.version==ipaddress.ip_address(flow.source_address).version
        return target.version==selected.version and target in selected

    def port(value):
        if value is None:
            return True
        require(flow.protocol != 'igmp', 'component.traffic-rule')
        types.rule_port(value, icmp=flow.protocol in ('icmp', 'icmpv6'))
        bounds=[tuple(map(int,item.split(':')))for item in value.split(',')]
        return flow.port is not None and any(row[0]<=flow.port<=row[-1]for row in bounds)

    return any(row['direction']==direction and row['proto']==flow.protocol
        and row.get('interface')in(None,interface)
        and network(row.get('source'),flow.source_address)
        and network(row.get('destination'),flow.target_address)
        and port(row.get('port'))for row in rules)


def nic(guest,address):
    choices=[]
    for index,row in enumerate(guest['provider_interfaces']):
        value=row.get('ipv4_endpoint')if row['ipv4']=='dhcp'else row['ipv4']
        if value!='manual'and str(ipaddress.IPv4Interface(value).ip)==address:
            choices.append('net'+str(index))
    require(len(choices)==1,'component.traffic-interface')
    return choices[0]


def check(guests,source,target,source_ip,target_ip,protocol,port):
    if source==target:
        return # An intra-guest value relationship does not invent guest grants.
    flow=Flow(source_ip,target_ip,protocol,port)
    require(permits(guests[source]['rules'],'out',flow,nic(guests[source],source_ip)),
            'component.traffic-egress')
    if target is not None:
        require(permits(guests[target]['rules'],'in',flow,nic(guests[target],target_ip)),
                'component.traffic-ingress')


def default_source(guest):
    choices=[]
    for row in guest['provider_interfaces']:
        if row['ipv4']=='dhcp' or row.get('gateway'):
            value=row.get('ipv4_endpoint')if row['ipv4']=='dhcp'else row['ipv4']
            choices.append(str(ipaddress.IPv4Interface(value).ip))
    require(len(choices)==1,'component.traffic-source')
    return choices[0]


def bind(resolver,exposures):
    """Project required traffic from selected typed connections and publications."""
    guests,apps=resolver.guests,resolver.apps
    def connection(source,target,source_ip=None,*,dns=False):
        owning=target.get('guest')
        if owning is None and 'app'in target:
            owning=apps[target['app']]['guest']
        if source==owning:return
        require('internal'not in target and 'address'in target and 'port'in target,
                'component.traffic-target')
        address=target['address']
        if source_ip is None:
            try:
                ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError:
                require(owning is None,'component.traffic-target-address')
                source_ip=default_source(guests[source])
            else:
                source_ip=source_address(guests[source],address)
        protocols=('tcp','udp')if dns else ('udp',)if target['protocol']=='udp'else ('tcp',)
        for protocol in protocols:
            check(guests,source,owning,source_ip,address,protocol,target['port'])

    for app_id,app in apps.items():
        for role,row in app['resolved_connections'].items():
            with at('apps',app_id,'connections',role):
                connection(app['guest'],row['target'],row['source_address'],dns=row['type']=='dns')
    for guest_id,guest in guests.items():
        for requirement in guest.get('readiness',[]):
            with at('guests',guest_id,'readiness'):
                target=resolver.endpoint(requirement['target'])
                connection(guest_id,target,guest['control']['address'],
                    dns=apps[target['app']]['adapter']in('pihole','unbound'))
        references=resolver.site['guests'][guest_id].get('dns_servers',
            resolver.site['contexts'][guest['context']]['dns_servers'])
        for reference in references:
            target=resolver.endpoint(reference)
            if 'app'in target:
                with at('guests',guest_id,'dns_servers'):
                    connection(guest_id,target,dns=True)
    for ingress_id,routes in exposures.routes.items():
        guest=apps[ingress_id]['guest']
        for key,row in routes.items():
            with at('exposures',key):
                if not row['target'].get('internal'):
                    connection(guest,row['target'])
                for name in row.get('middlewares',[]):
                    middleware=exposures.middlewares[name]
                    if middleware['type']=='forward-auth':
                        connection(guest,middleware['target'])
