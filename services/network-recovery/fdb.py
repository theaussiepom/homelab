"""Narrow Docker overlay repair: add missing, proven VXLAN self mappings only.

No endpoint IP or MAC is cached or inferred. Docker's live task/peer metadata,
the existing permanent neighbour, and the bridge-master FDB must agree. The
caller owns locking, link stability, candidate ageing, rate limits and journaling.
"""
import contextlib
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess

TIMEOUT = 10
NETNS_ROOT = Path('/var/run/docker/netns')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z')


class GuardError(RuntimeError):
    pass


class PeerUnavailable(GuardError):
    """A bounded network probe failed before any mutation was attempted."""


def require(ok, reason):
    if not ok:
        raise GuardError(reason)


def _run(argv, fd=None):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT,
                            env=dict(os.environ, LC_ALL='C'),
                            pass_fds=() if fd is None else (fd,))
    require(len(result.stdout) <= 4 * 1024 * 1024 and len(result.stderr) <= 65536,
            'command_output_limit')
    return result


def _json(argv, fd=None):
    result = _run(argv, fd)
    require(result.returncode == 0, 'read_command_failed:' + argv[0])
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError):
        raise GuardError('invalid_command_json') from None


def _config(config):
    value = config.get('overlay', config)
    require(isinstance(value, dict), 'overlay_config_missing')
    require(isinstance(value.get('network'), str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['network']),
            'invalid_network_name')
    local = ipaddress.IPv4Address(value['local_ip'])
    peers = ipaddress.IPv4Network(value['peer_subnet'])
    require(local in peers, 'local_ip_outside_peer_subnet')
    require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value['route_interface']) is not None,
            'invalid_route_interface')
    port = value.get('peer_probe_port', 22)
    require(type(port) is int and 1 <= port <= 65535, 'invalid_peer_probe_port')
    return value


def _network(config):
    rows = _json(['docker', 'network', 'inspect', '--verbose', config['network']])
    require(isinstance(rows, list) and len(rows) == 1, 'network_not_unique')
    network = rows[0]
    require(network.get('Name') == config['network'] and
            network.get('Driver') == 'overlay' and network.get('Scope') == 'swarm' and
            network.get('Ingress') is False and network.get('ConfigOnly', False) is False,
            'unsupported_network_kind')
    require(re.fullmatch(r'[a-z0-9]{12,64}', network.get('Id', '')) is not None and
            isinstance(network.get('Created'), str), 'network_identity_missing')
    options = network.get('Options') or {}
    require('encrypted' not in options, 'encrypted_overlay_requires_separate_review')
    vni_text = options.get('com.docker.network.driver.overlay.vxlanid_list', '')
    require(isinstance(vni_text, str) and vni_text.isdigit() and
            1 <= int(vni_text) <= 16777215, 'single_vni_required')
    subnets = (network.get('IPAM') or {}).get('Config') or []
    require(len(subnets) == 1 and subnets[0].get('Subnet'), 'single_ipv4_subnet_required')
    subnet = ipaddress.IPv4Network(subnets[0]['Subnet'])
    return network, int(vni_text), subnet


@contextlib.contextmanager
def _namespace(network):
    # Docker's numbered sandbox prefix can change. A substring match could select
    # another sandbox; uniqueness and the namespace inode are part of identity.
    pattern = re.compile(r'\d+-' + re.escape(network['Id'][:10]) + r'\Z')
    paths = [p for p in NETNS_ROOT.iterdir() if pattern.fullmatch(p.name)]
    require(len(paths) == 1, 'network_namespace_not_unique')
    fd = os.open(paths[0], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        stat = os.fstat(fd)
        yield fd, {'path': str(paths[0]), 'device': stat.st_dev, 'inode': stat.st_ino}
    finally:
        os.close(fd)


def _ns(fd, argv):
    return ['nsenter', '--net=/proc/self/fd/' + str(fd), '--', *argv]


def _read_kernel(fd):
    return (_json(_ns(fd, ['ip', '-j', '-d', 'link', 'show']), fd),
            _json(_ns(fd, ['ip', '-j', 'neigh', 'show']), fd),
            _json(_ns(fd, ['bridge', '-j', 'fdb', 'show']), fd))


def _valid_mac(value):
    return isinstance(value, str) and MAC.fullmatch(value) and value != '00:00:00:00:00:00' and not (int(value[:2], 16) & 1)


def _plan(config, network, vni, subnet, namespace, links, neighbours, fdb, routes):
    """Pure evidence reconciliation, also used by the synthetic guard tests."""
    issues, candidates, entries = [], [], []
    vx = [x for x in links if (x.get('linkinfo') or {}).get('info_kind') == 'vxlan' and
          (x.get('linkinfo') or {}).get('info_data', {}).get('id') == vni]
    require(len(vx) == 1, 'vxlan_vni_not_unique')
    vx = vx[0]
    require(isinstance(vx.get('ifindex'), int) and vx['ifindex'] > 0 and
            re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', vx.get('ifname', '')) is not None and
            'UP' in vx.get('flags', []), 'vxlan_interface_not_ready')
    bridge = [x for x in links if x.get('ifname') == vx.get('master') and
              (x.get('linkinfo') or {}).get('info_kind') == 'bridge']
    require(len(bridge) == 1 and 'UP' in bridge[0].get('flags', []) and
            isinstance(bridge[0].get('ifindex'), int) and bridge[0]['ifindex'] > 0,
            'vxlan_bridge_not_ready')
    require(vx['linkinfo']['info_data'].get('port') == 4789, 'unexpected_vxlan_port')
    peer_subnet = ipaddress.IPv4Network(config['peer_subnet'])
    peer_rows = network.get('Peers')
    require(isinstance(peer_rows, list) and peer_rows, 'docker_peer_metadata_missing')
    peers = [str(ipaddress.IPv4Address(x['IP'])) for x in peer_rows]
    require(len(peers) == len(set(peers)) and config['local_ip'] in peers and
            all(ipaddress.IPv4Address(x) in peer_subnet for x in peers), 'docker_peer_metadata_conflict')
    services = network.get('Services')
    require(isinstance(services, dict), 'docker_task_metadata_missing')
    tasks = []
    for service in services.values():
        require(isinstance(service, dict) and isinstance(service.get('Tasks'), list), 'invalid_docker_tasks')
        tasks.extend(service['Tasks'])
    require(len(tasks) <= 1024, 'endpoint_count_limit')
    for task in tasks:
        ip = task.get('EndpointIP', '')
        name = task.get('Name') or ip
        key = config['network'] + ':' + name
        try:
            address = ipaddress.IPv4Address(ip)
            peer = str(ipaddress.IPv4Address((task.get('Info') or {}).get('Host IP', '')))
            require(address in subnet and address not in (subnet.network_address, subnet.broadcast_address), 'endpoint_outside_subnet')
            require(re.fullmatch(r'[a-f0-9]{64}', task.get('EndpointID', '')) is not None,
                    'endpoint_id_invalid')
            require(peer in peers, 'endpoint_peer_unknown')
            same_ip = [x for x in tasks if x.get('EndpointIP') == ip]
            require(len(same_ip) == 1, 'endpoint_ip_conflict')
            require(sum(1 for x in tasks if x.get('EndpointID') == task['EndpointID']) == 1,
                    'endpoint_id_conflict')
            if peer == config['local_ip']:
                continue
            route = routes.get(peer)
            require(isinstance(route, list) and len(route) == 1 and
                    route[0].get('dev') == config['route_interface'] and
                    route[0].get('prefsrc') == config['local_ip'] and
                    not route[0].get('gateway') and route[0].get('type', 'unicast') == 'unicast',
                    'underlay_route_not_ready')
            ns = [n for n in neighbours if n.get('dst') == ip]
            require(len(ns) == 1 and ns[0].get('dev') == vx['ifname'] and
                    'PERMANENT' in ns[0].get('state', []) and _valid_mac(ns[0].get('lladdr')),
                    'permanent_neighbour_missing_or_conflicting')
            mac = ns[0]['lladdr']
            require(len([n for n in neighbours if n.get('lladdr') == mac and
                         n.get('dev') == vx['ifname'] and ':' not in n.get('dst', '')]) == 1,
                    'neighbour_mac_conflict')
            masters = [x for x in fdb if x.get('mac') == mac and x.get('master') and
                       'self' not in x.get('flags', [])]
            own = [x for x in fdb if x.get('mac') == mac and 'self' in x.get('flags', [])]
            require(len(own) <= 1 and (not own or
                    (own[0].get('ifname') == vx['ifname'] and own[0].get('dst') == peer)),
                    'tunnel_fdb_conflict')
            # Learned bridge-master records can age away while a valid tunnel
            # mapping remains. They are a mandatory repair prerequisite, not a
            # reason to rewrite an already correct VXLAN self entry.
            require((own and not masters) or
                    (len(masters) == 1 and masters[0].get('ifname') == vx['ifname'] and
                     masters[0].get('master') == bridge[0]['ifname']),
                    'bridge_fdb_missing_or_conflicting')
            identity = {'network_id': network['Id'], 'network_created': network['Created'],
                        'endpoint_id': task['EndpointID'], 'ip': ip, 'mac': mac, 'peer': peer,
                        'namespace': namespace, 'interface': vx['ifname'], 'ifindex': vx['ifindex'],
                        'vni': vni, 'bridge': bridge[0]['ifname'], 'bridge_ifindex': bridge[0]['ifindex']}
            item = {'kind': 'fdb', 'key': key, 'identity': identity,
                    'state': 'present' if own else 'missing'}
            entries.append(item)
            if not own:
                candidates.append(item)
        except (GuardError, ValueError, KeyError, TypeError) as exc:
            issues.append({'key': key, 'reason': str(exc) if isinstance(exc, GuardError) else 'invalid_endpoint_metadata'})
    # A duplicated task name must not collide in the caller's ageing/rate-limit key.
    keys = [x['key'] for x in entries]
    duplicate = {key for key in keys if keys.count(key) > 1}
    if duplicate:
        issues.extend({'key': key, 'reason': 'logical_key_conflict'} for key in sorted(duplicate))
        entries = [x for x in entries if x['key'] not in duplicate]
        candidates = [x for x in candidates if x['key'] not in duplicate]
    return {'healthy': not candidates and not issues, 'candidates': candidates,
            'issues': issues, 'entries': entries, 'network_id': network['Id']}


def _snapshot(config, network, vni, subnet, fd, namespace):
    links, neighbours, fdb = _read_kernel(fd)
    peers = {(task.get('Info') or {}).get('Host IP')
             for service in (network.get('Services') or {}).values()
             for task in service.get('Tasks', [])}
    require(len(peers) <= 64, 'peer_count_limit')
    routes = {}
    for peer in sorted(p for p in peers if isinstance(p, str) and p != config['local_ip']):
        address = ipaddress.IPv4Address(peer)
        require(address in ipaddress.IPv4Network(config['peer_subnet']), 'peer_outside_configured_subnet')
        routes[peer] = _json(['ip', '-j', 'route', 'get', str(address)])
    return _plan(config, network, vni, subnet, namespace, links, neighbours, fdb, routes)


def observe(config):
    config = _config(config)
    network, vni, subnet = _network(config)
    with _namespace(network) as (fd, namespace):
        return _snapshot(config, network, vni, subnet, fd, namespace)


def _match(snapshot, candidate):
    matches = [x for x in snapshot['entries'] if x['key'] == candidate['key']]
    require(len(matches) == 1 and matches[0]['identity'] == candidate['identity'],
            'candidate_identity_changed_or_unproven')
    return matches[0]


def _probe_peer(peer, config):
    """Bounded TCP handshake only: no SSH login, payload, or remote command."""
    try:
        with socket.create_connection((peer, config.get('peer_probe_port', 22)), timeout=3,
                                      source_address=(config['local_ip'], 0)):
            pass
    except OSError as exc:
        if isinstance(exc, (TimeoutError, ConnectionRefusedError, ConnectionResetError)) or exc.errno in {
                errno.ETIMEDOUT, errno.ECONNREFUSED, errno.ECONNRESET,
                errno.EHOSTUNREACH, errno.ENETUNREACH, getattr(errno, 'EHOSTDOWN', -1)}:
            raise PeerUnavailable('underlay_peer_probe_failed') from None
        # Local permissions, invalid source binding, descriptor exhaustion, and
        # other unexpected errors are not evidence that the peer is merely off.
        raise


def repair(candidate, config, record):
    """Revalidate, journal intent, add exactly one missing mapping, then verify.

    A concurrent daemon add is accepted only after an exact post-read. Never
    replace or delete entries, including following a lifecycle race. The parent
    must report failures; an add receipt alone is not end-to-end connectivity.
    """
    config = _config(config)
    require(candidate.get('kind') == 'fdb', 'wrong_candidate_kind')
    network, vni, subnet = _network(config)
    with _namespace(network) as (fd, namespace):
        current = _snapshot(config, network, vni, subnet, fd, namespace)
        selected = _match(current, candidate)
        if selected['state'] == 'present':
            result = {'success': True, 'status': 'already_resolved', 'changed': False, 'key': candidate['key']}
            record('after', result)
            return result
        identity = selected['identity']
        try:
            _probe_peer(identity['peer'], config)
        except PeerUnavailable:
            result = {'deferred': True, 'success': False, 'changed': False,
                      'mutation_attempted': False, 'reason': 'peer_unreachable',
                      'key': candidate['key'], 'kind': 'fdb'}
            record('deferred', result)
            return result
        record('before', {'kind': 'fdb', 'key': candidate['key'], 'identity': identity,
                          'operation': 'add_missing_self_fdb'})
        # The durable journal may take time. Re-read all evidence after it and
        # compare namespace identity rather than trusting the old path name.
        latest, latest_vni, latest_subnet = _network(config)
        with _namespace(latest) as (check_fd, check_namespace):
            require(check_namespace == namespace, 'namespace_changed_before_add')
            selected = _match(_snapshot(config, latest, latest_vni, latest_subnet,
                                       check_fd, check_namespace), candidate)
        if selected['state'] == 'present':
            result = {'success': True, 'status': 'already_resolved', 'changed': False, 'key': candidate['key']}
            record('after', result)
            return result
        command = _ns(fd, ['bridge', 'fdb', 'add', identity['mac'], 'dev', identity['interface'],
                           'dst', identity['peer'], 'self', 'permanent'])
        result = _run(command, fd)
        # Always capture a post-write result, including command failures. Do not
        # convert an arbitrary nonzero command into success just because an entry
        # happens to appear; only EEXIST is an expected concurrent-add condition.
        exists = result.returncode != 0 and 'File exists' in result.stderr
        attempt = {'key': candidate['key'], 'kind': 'fdb', 'identity': identity,
                   'command_returncode': result.returncode,
                   'concurrent_exists': exists, 'changed': result.returncode == 0}
        record('attempted', attempt)
        require(result.returncode == 0 or exists, 'fdb_add_failed')
        after = observe(config)
        selected = _match(after, candidate)
        require(selected['state'] == 'present', 'fdb_add_not_confirmed')
        outcome = {'success': True, 'status': 'repaired' if result.returncode == 0 else 'concurrently_resolved',
                   'changed': result.returncode == 0, 'key': candidate['key'],
                   'identity': identity, 'mapping_verified': True,
                   'connectivity_verified': False}
        record('after', outcome)
        return outcome
