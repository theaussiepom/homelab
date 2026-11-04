"""Shared known-example admission guard for typed allocation/traffic fields."""
import ipaddress
import re


def synthetic_binding(key, value):
    """Reject known examples only in declared address/network/domain inputs."""
    network = key.startswith(('addresses.', 'gateways.', 'networks.')) or re.fullmatch(r'interfaces\..+\.ipv4(?:_endpoint)?', key)
    domain = key.startswith(('domains.', 'hostnames.'))
    if not network and not domain:
        return False
    for item in value if isinstance(value, list) else [value]:
        if not isinstance(item, str) or item in {'manual', 'dhcp'}:
            continue
        if domain:
            name = item.lower().rstrip('.')
            if any(name == suffix or name.endswith('.' + suffix)
                   for suffix in ('example.com', 'example.net', 'example.org', 'example', 'invalid', 'test', 'localhost')):
                return True
        else:
            try:
                candidate = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue  # The existing receiver validates its complete semantic contract.
            examples = ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '198.18.0.0/15', '2001:db8::/32')
            if any(candidate.version == example.version and candidate.subnet_of(example)
                   for example in map(ipaddress.ip_network, examples)):
                return True
    return False
