"""Pure endpoint patch for a commissioned Authentik Compose document.

The common maintenance caller derives `after` with database_networks.endpoint
from the SHA256-bound private catalogue. It owns guest identity/receipt checks,
NIC/firewall application, startup and holds. This module performs no I/O and
must never be used to regenerate installed foundation inputs or restore data.
"""
import copy
import ipaddress
import json
import re

HOST = 'AUTHENTIK_POSTGRESQL__HOST'
PORT = 'AUTHENTIK_POSTGRESQL__PORT'
DEFAULT_PORT = 5432


def require(value, message):
    if not value:
        raise ValueError(message)


def endpoint(value, private=True):
    require(isinstance(value, dict) and set(value) == {'address', 'port'},
            'Bind only the selected PostgreSQL endpoint')
    require(isinstance(value['address'], str) and value['address']
            and all(c.isprintable() and not c.isspace() for c in value['address']),
            'Bind a non-empty PostgreSQL host without control characters or whitespace')
    if private:
        try:
            address = ipaddress.IPv4Address(value['address'])
        except (ValueError, TypeError):
            raise ValueError('Select a literal private PostgreSQL IPv4 address') from None
        require(address.is_private
                and not (address.is_loopback or address.is_link_local or address.is_unspecified
                         or address.is_multicast or address.is_reserved),
                'Select a literal private PostgreSQL IPv4 address')
    require(type(value['port']) is int and 1 <= value['port'] <= 65535,
            'Select the PostgreSQL numeric port')
    return value


def candidate(original, before, after):
    """Change both modes together; every field outside HOST/PORT stays intact.

    `before` binds the commissioned runtime, including its implicit default
    PostgreSQL port where no port was rendered. `after` comes from the shared
    network contract, not an independently maintained Authentik address.
    A partial or repeated mutation holds for the common caller to investigate.
    """
    endpoint(before, private=False)
    endpoint(after)
    require(before != after, 'Select a reviewed PostgreSQL endpoint change')
    try:
        value = json.loads(original)
    except (ValueError, TypeError):
        raise ValueError('Read the original commissioned Compose document') from None
    require(isinstance(value, dict) and value.get('name') == 'homelab-identity'
            and isinstance(value.get('services'), dict)
            and set(value['services']) == {'server', 'worker', 'redis'},
            'Select only the commissioned identity stack')
    for name in ('server', 'worker'):
        service = value['services'][name]
        require(isinstance(service, dict) and service.get('command') == name
                and isinstance(service.get('environment'), dict),
                'Select the original Authentik server and worker modes')
        env = service['environment']
        require(env.get('AUTHENTIK_REDIS__HOST') == 'redis', 'Preserve local Redis')
        require(env.get(HOST) == before['address']
                and env.get(PORT, str(DEFAULT_PORT)) == str(before['port']),
                'The commissioned Authentik endpoint differs')
    for name in ('server', 'worker'):
        value['services'][name]['environment'].update({HOST: after['address'], PORT: str(after['port'])})
    return (json.dumps(value, indent=2) + '\n').encode()


def sql_egress(rule, port):
    """Hold unmodelled TCP allowances rather than retaining a SQL fallback."""
    require(isinstance(rule, dict) and rule.get('direction') in {'in', 'out'}
            and rule.get('proto') in {'tcp', 'udp', 'icmp', 'icmpv6'},
            'Review the existing firewall rules')
    if rule.get('direction') != 'out' or rule.get('proto') != 'tcp':
        return False
    ports = rule.get('port')
    require(isinstance(ports, str) and ports, 'Review unbounded TCP egress before the SQL cutover')
    allows = False
    for part in ports.split(','):
        require(re.fullmatch(r'[0-9]+(?:[:-][0-9]+)?', part), 'Review unmodelled TCP egress')
        limits = re.split('[:-]', part)
        low, high = int(limits[0]), int(limits[-1])
        require(1 <= low <= high <= 65535, 'Review invalid TCP egress')
        allows = allows or low <= port <= high
    return allows


def rules_candidate(original, before, after):
    """Replace the sole old SQL allowance with one contract-derived client rule.

    `after` is database_networks.rules(contract, 'postgresql', vmid)[0].
    The common caller appends the contract NIC with database_networks.attach,
    then uses this result for the guest rules, preserving HTTP and all other
    non-SQL allowances. Both helpers are pure; neither applies guest state.
    """
    endpoint(before)
    require(isinstance(original, list) and isinstance(after, dict)
            and set(after) == {'direction', 'proto', 'port', 'source', 'destination', 'comment'}
            and after['direction'] == 'out' and after['proto'] == 'tcp'
            and isinstance(after['port'], str) and re.fullmatch(r'[1-9][0-9]{0,4}', after['port'])
            and int(after['port']) <= 65535
            and isinstance(after['comment'], str)
            and re.fullmatch(r'postgresql approved client [a-z][a-z0-9-]{0,62}', after['comment']),
            'Select one exact contract-derived PostgreSQL client rule')
    for key in ('source', 'destination'):
        try:
            subnet = ipaddress.IPv4Network(after[key], strict=True)
        except (ValueError, TypeError):
            raise ValueError('Select literal PostgreSQL client/server host rules') from None
        require(isinstance(after[key], str) and subnet.prefixlen == 32,
                'Select literal PostgreSQL client/server host rules')
        endpoint({'address': str(subnet.network_address), 'port': before['port']})
    legacy = {'direction': 'out', 'proto': 'tcp', 'port': str(before['port']),
              'destination': before['address'] + '/32', 'comment': 'Restored Authentik database only'}
    require(after['destination'] != legacy['destination'], 'Retire the old PostgreSQL network')
    ports = {before['port'], int(after['port'])}
    matches = [index for index, rule in enumerate(original)
               if any(sql_egress(rule, port) for port in ports)]
    require(len(matches) == 1 and original[matches[0]] == legacy,
            'The original SQL rule differs or another SQL allowance remains')
    result = copy.deepcopy(original)
    result[matches[0]] = copy.deepcopy(after)
    return result
