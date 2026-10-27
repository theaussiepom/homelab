"""Pure additive listener candidates for the existing database-network catalogue.

No files are read/written and no service, network or authentication operation is
performed. Keep commissioned inputs/receipts unchanged: a separately reviewed
maintenance operation must bind these candidates to actual installed files.
Legacy listeners and HBA records are retained. Client transition and removal of
old access are later steps, never an effect of this renderer.
"""
import configparser
import ipaddress
import re
import tomllib

import database_networks as networks

FILES = {'postgresql': {'homelab.conf', 'pg_hba.conf'},
         'mariadb': {'homelab.cnf'}, 'influxdb': {'config.toml'}}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def postgres(sources, address, clients):
    config, hba = sources['homelab.conf'], sources['pg_hba.conf']
    matches = list(re.finditer(r"(?m)^([ \t]*listen_addresses[ \t]*=[ \t]*)'([^'\r\n]*)'([ \t]*(?:#[^\r\n]*)?)$", config))
    require(len(matches) == len(re.findall(r'(?m)^[ \t]*listen_addresses[ \t]*=', config)) == 1,
            'Review the missing, ambiguous or unsupported PostgreSQL listener')
    match = matches[0]
    addresses = [part.strip() for part in match[2].split(',')]
    require(all(addresses), 'Keep the existing TCP listener during the additive stage')
    for item in addresses:
        if item not in {'*', 'localhost'}:
            ipaddress.ip_address(item)
    ports = re.findall(r'(?m)^[ \t]*port[ \t]*=([^\n]*)$', config)
    require(not ports or (len(ports) == 1 and ports[0].split('#')[0].strip() == str(networks.PORTS['postgresql'])),
            'Review a nonstandard or ambiguous PostgreSQL port')
    rows = set()
    remote_policy = False
    for line in hba.splitlines():
        fields = tuple(line.split('#', 1)[0].split())
        if not fields:
            continue
        if fields[0] == 'local':
            require(len(fields) == 4 and fields[3] == 'peer', 'Review the existing PostgreSQL local authentication policy')
        else:
            require(len(fields) == 5 and fields[:3] == ('host', 'all', 'all') and fields[4] == 'scram-sha-256',
                    'Review other PostgreSQL authentication policy before adding clients')
            subnet = ipaddress.ip_network(fields[3], strict=True)
            remote_policy = remote_policy or not subnet.is_loopback
        rows.add(fields)
    require(remote_policy, 'Require the existing remote SCRAM policy before extending it')
    additions = ['host all all ' + client + '/32 scram-sha-256' for client in clients
                 if ('host', 'all', 'all', client + '/32', 'scram-sha-256') not in rows]
    files = dict(sources)
    if address not in addresses and not {'*', '0.0.0.0'} & set(addresses):
        files['homelab.conf'] = config[:match.start(2)] + match[2] + ',' + address + config[match.end(2):]
    if additions:
        files['pg_hba.conf'] = hba + ('' if hba.endswith('\n') else '\n') + '\n'.join(additions) + '\n'
    activation = 'restart' if files['homelab.conf'] != config else 'reload' if additions else 'none'
    return files, activation


def render(value, engine, sources):
    """Return candidate text plus required activation, never target readiness.

    The supported HBA baseline is the commissioned local-peer/host-all-all-SCRAM
    policy. Hold includes, TLS-specific, role-specific or other auth policies for
    explicit review rather than accidentally weakening them. Existing wildcard
    MariaDB/Influx listeners remain byte-for-byte unchanged; do not broaden a
    specific listener to work around a transition problem.
    """
    net = networks.selected(value, engine)
    require(isinstance(sources, dict) and set(sources) == FILES[engine]
            and all(isinstance(text, str) and len(text.encode()) <= 131072 and '\x00' not in text
                    for text in sources.values()), 'Supply only the existing bounded server configuration texts')
    clients = [client['address'] for client in net['clients']]
    files, activation = dict(sources), 'none'
    if engine == 'postgresql':
        files, activation = postgres(sources, net['server']['address'], clients)
    elif engine == 'mariadb':
        config = configparser.ConfigParser(interpolation=None, allow_no_value=True)
        try:
            config.read_string(sources['homelab.cnf'])
            compatible = (config.get('mysqld', 'bind-address', raw=True) == '0.0.0.0'
                          and not config.has_option('mysqld', 'bind_address')
                          and not config.has_option('mysqld', 'skip-networking')
                          and config.get('mysqld', 'port', fallback=str(networks.PORTS[engine])) == str(networks.PORTS[engine]))
        except configparser.Error:
            compatible = False
        require(compatible, 'Preserve the existing wildcard MariaDB listener; review other listener changes separately')
    else:
        require(tomllib.loads(sources['config.toml']).get('http-bind-address') == ':' + str(networks.PORTS[engine]),
                'Preserve the existing wildcard Influx listener; review other listener changes separately')
    return {'files': files, 'activation': activation, 'endpoint': networks.endpoint(value, engine)}
