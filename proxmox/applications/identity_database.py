"""Pure endpoint patch for a commissioned Authentik Compose document.

The common maintenance caller derives `after` with database_networks.endpoint
from the SHA256-bound private catalogue. It owns guest identity/receipt checks,
NIC/firewall application, startup and holds. This module performs no I/O and
must never be used to regenerate installed foundation inputs or restore data.
"""
import ipaddress
import json

HOST = 'AUTHENTIK_POSTGRESQL__HOST'
PORT = 'AUTHENTIK_POSTGRESQL__PORT'
DEFAULT_PORT = 5432


def require(value, message):
    if not value:
        raise ValueError(message)


def endpoint(value):
    require(isinstance(value, dict) and set(value) == {'address', 'port'},
            'Bind only the selected PostgreSQL endpoint')
    try:
        address = ipaddress.IPv4Address(value['address'])
    except (ValueError, TypeError):
        raise ValueError('Select a literal private PostgreSQL IPv4 address') from None
    require(isinstance(value['address'], str) and address.is_private
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
    endpoint(before); endpoint(after)
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
