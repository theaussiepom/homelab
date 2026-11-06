"""Bounded ordered address values; references never create grants or waits."""
from component_errors import at
from component_sources import closed, identifier, named, require
import component_types as types

MAX_MEMBERS = 4096


def group(value):
    closed(value, ('members',))
    members = value['members']
    require(isinstance(members, list) and 0 < len(members) <= 256,
            'component.address-group-size')
    for member in members:
        if isinstance(member, str):
            types.rule_address(member, ipv6=True)
        else:
            require(isinstance(member, dict) and len(member) == 1
                    and set(member) <= {'network', 'address_group'}
                    and all(identifier(item) for item in member.values()), 'component.reference')


def selected(name, groups):
    require(identifier(name) and name in groups, 'component.reference')
    return list(groups[name])


def resolve(groups, networks):
    """Flatten explicit ordered members without union, sorting or deduplication."""
    named(groups)
    for name, value in groups.items():
        with at('address_groups', name):
            group(value)
    result, active, depths = {}, set(), {}
    total = 0

    def visit(name):
        nonlocal total
        require(name in groups, 'component.reference')
        require(name not in active, 'component.address-group-cycle')
        if name in result:
            return result[name]
        require(len(active) < 64, 'component.address-group-size')
        active.add(name)
        ranges, depth = [], 1
        with at('address_groups', name):
            for member in groups[name]['members']:
                if isinstance(member, str):
                    values = [member]
                elif 'network' in member:
                    require(member['network'] in networks, 'component.reference')
                    network = networks[member['network']]
                    require(isinstance(network, dict) and isinstance(network.get('cidr'), str),
                            'component.reference')
                    value = network['cidr']
                    types.rule_address(value)
                    values = [value]
                else:
                    values = visit(member['address_group'])
                    depth = max(depth, 1 + depths[member['address_group']])
                    require(depth <= 64, 'component.address-group-size')
                require(len(ranges) + len(values) <= MAX_MEMBERS, 'component.address-group-size')
                ranges.extend(values)
        active.remove(name)
        total += len(ranges)
        require(total <= 65536, 'component.address-group-size')
        result[name] = ranges
        depths[name] = depth
        return ranges

    for name in groups:
        visit(name)
    return result
