"""Pure listener candidates for the existing database-network catalogue.

No files are read/written and no service, network or authentication operation is
performed. Keep commissioned inputs/receipts unchanged: a separately reviewed
maintenance operation must bind these candidates to actual installed files.
PostgreSQL has an explicit cutover phase, removing its previous remote listener
and HBA paths. Only the operation's selected clients receive access. MariaDB and
InfluxDB also support explicit server-only cutovers to one private address.
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


def clients(value, engine, client_vmids):
    """Select a finite operation subset without changing the full catalogue."""
    net = networks.selected(value, engine)
    require(isinstance(client_vmids, list) and client_vmids
            and all(type(vmid) is int for vmid in client_vmids)
            and len(client_vmids) == len(set(client_vmids)), 'Select explicit unique database clients')
    members = {client['vmid']: client for client in net['clients']}
    require(set(client_vmids) <= set(members), 'A selected client is absent from the database catalogue')
    return [dict(members[vmid]) for vmid in sorted(client_vmids)]


def postgres(sources, address, selected):
    config, hba = sources['homelab.conf'], sources['pg_hba.conf']
    matches = list(re.finditer(r"(?m)^([ \t]*listen_addresses[ \t]*=[ \t]*)'([^'\r\n]*)'([ \t]*(?:#[^\r\n]*)?)$", config))
    require(len(matches) == len(re.findall(r'(?m)^[ \t]*listen_addresses[ \t]*=', config)) == 1,
            'Review the missing, ambiguous or unsupported PostgreSQL listener')
    match = matches[0]
    addresses = [part.strip() for part in match[2].split(',')]
    require(all(addresses), 'Review the empty existing PostgreSQL TCP listener')
    for item in addresses:
        if item not in {'*', 'localhost'}:
            ipaddress.ip_address(item)
    ports = re.findall(r'(?m)^[ \t]*port[ \t]*=([^\n]*)$', config)
    require(not ports or (len(ports) == 1 and ports[0].split('#')[0].strip() == str(networks.PORTS['postgresql'])),
            'Review a nonstandard or ambiguous PostgreSQL port')
    retained = []
    remote_policy = False
    for line in hba.splitlines():
        fields = tuple(line.split('#', 1)[0].split())
        if not fields:
            retained.append(line)
            continue
        if fields[0] == 'local':
            require(len(fields) == 4 and fields[3] == 'peer', 'Review the existing PostgreSQL local authentication policy')
            retained.append(line)
        else:
            require(len(fields) == 5 and fields[:3] == ('host', 'all', 'all') and fields[4] == 'scram-sha-256',
                    'Review other PostgreSQL authentication policy before replacing remote clients')
            subnet = ipaddress.ip_network(fields[3], strict=True)
            remote_policy = remote_policy or not subnet.is_loopback
            if subnet.is_loopback:
                retained.append(line)
    require(remote_policy, 'Require the existing remote SCRAM policy before the cutover')
    additions = ['host all all ' + client['address'] + '/32 scram-sha-256' for client in selected]
    files = dict(sources)
    files['homelab.conf'] = config[:match.start(2)] + '127.0.0.1,' + address + config[match.end(2):]
    files['pg_hba.conf'] = '\n'.join([*retained, *additions]) + '\n'
    activation = ('restart' if files['homelab.conf'] != config else
                  'reload' if files['pg_hba.conf'] != hba else 'none')
    return files, activation


def render(value, engine, sources, *, phase='additive', client_vmids=None):
    """Return candidate text plus required activation, never target readiness.

    The supported HBA baseline is the commissioned local-peer/host-all-all-SCRAM
    policy. Hold includes, TLS-specific, role-specific or other auth policies for
    explicit review rather than accidentally weakening them. Existing wildcard
    MariaDB/Influx listeners remain byte-for-byte unchanged; do not broaden a
    specific listener to work around a transition problem.
    """
    net = networks.selected(value, engine)
    require(phase == 'cutover' or (phase == 'additive' and engine != 'postgresql'),
            'Select explicit cutover; PostgreSQL cannot be additive')
    require(isinstance(sources, dict) and set(sources) == FILES[engine]
            and all(isinstance(text, str) and len(text.encode()) <= 131072 and '\x00' not in text
                    for text in sources.values()), 'Supply only the existing bounded server configuration texts')
    files, activation = dict(sources), 'none'
    selected = clients(value, engine, client_vmids) if client_vmids is not None else None
    require(phase != 'cutover' or selected is not None,
            'Cutover requires explicit selected catalogue client IDs')
    if engine == 'postgresql':
        require(selected is not None, 'PostgreSQL cutover requires explicit selected client IDs')
        files, activation = postgres(sources, net['server']['address'], selected)
    elif engine == 'mariadb':
        config = configparser.ConfigParser(interpolation=None, allow_no_value=True)
        try:
            config.read_string(sources['homelab.cnf'])
            address = config.get('mysqld', 'bind-address', raw=True)
            compatible = (address in ({'0.0.0.0', net['server']['address']} if phase == 'cutover' else {'0.0.0.0'})
                          and not config.has_option('mysqld', 'bind_address')
                          and not config.has_option('mysqld', 'skip-networking')
                          and not config.has_option('mysqld', 'skip_networking')
                          and config.get('mysqld', 'port', fallback=str(networks.PORTS[engine])) == str(networks.PORTS[engine]))
        except configparser.Error:
            compatible = False
        require(compatible, 'Preserve the existing wildcard MariaDB listener; review other listener changes separately')
        if phase == 'cutover':
            matches = list(re.finditer(r'(?m)^([ \t]*bind-address[ \t]*=[ \t]*)([0-9.]+)([ \t]*)$', sources['homelab.cnf']))
            require(config.sections() == ['mysqld'] and len(matches) == 1,
                    'Review unsupported MariaDB sections or listener syntax')
            match = matches[0]
            files['homelab.cnf'] = sources['homelab.cnf'][:match.start(2)] + net['server']['address'] + sources['homelab.cnf'][match.end(2):]
            activation = 'restart' if files != sources else 'none'
    else:
        address = tomllib.loads(sources['config.toml']).get('http-bind-address')
        new = net['server']['address'] + ':' + str(networks.PORTS[engine])
        require(address in ({':' + str(networks.PORTS[engine]), new} if phase == 'cutover' else {':' + str(networks.PORTS[engine])}),
                'Preserve the existing wildcard Influx listener; review other listener changes separately')
        if phase == 'cutover':
            matches = list(re.finditer(r'(?m)^([ \t]*http-bind-address[ \t]*=[ \t]*)"([^"\r\n]+)"([ \t]*)$', sources['config.toml']))
            require(len(matches) == 1, 'Review unsupported Influx listener syntax')
            match = matches[0]
            files['config.toml'] = sources['config.toml'][:match.start(2)] + new + sources['config.toml'][match.end(2):]
            activation = 'restart' if files != sources else 'none'
    return {'files': files, 'activation': activation, 'endpoint': networks.endpoint(value, engine),
            'phase': phase, 'client_vmids': [client['vmid'] for client in selected] if selected else None}
