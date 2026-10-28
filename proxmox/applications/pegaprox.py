#!/usr/bin/env python3
"""Render a PegaProx Compose preview; no target, credential reads or deployment."""
import argparse
import ipaddress
import json
from pathlib import Path

from render import positive

IMAGE = 'ghcr.io/pegaprox/pegaprox@sha256:8d295a524a52f0b923616a3eb415ff6422fe62beba5bb441f35c75d8985f1add'
KEY_SOURCE = '/opt/homelab-app/runtime/pegaprox-db-key'
FIELDS = {'kind', 'enabled', 'deployable', 'image', 'bind_address',
          'guest_memory_mib', 'container_memory_mib', 'cpus', 'pids_limit'}


def compose_preview(cfg):
    """Keep the original disabled preview interface separate from CD admission."""
    if (set(cfg) != FIELDS or cfg.get('kind') != 'pegaprox'
            or cfg.get('enabled') is not False or cfg.get('deployable') is not False):
        raise ValueError('Use exactly the disabled PegaProx preparation fields')
    return compose({key: value for key, value in cfg.items() if key not in {'enabled', 'deployable'}})


def compose(cfg):
    """Render a stack; only the independent CD selection admits deployment."""
    if set(cfg) != FIELDS - {'enabled', 'deployable'} or cfg.get('kind') != 'pegaprox':
        raise ValueError('Use the closed PegaProx runtime stack fields')
    if cfg['image'] != IMAGE:
        raise ValueError('Use the reviewed official 1.4.1 image digest')
    address = ipaddress.IPv4Address(cfg['bind_address'])
    if (address.is_unspecified or address.is_loopback or address.is_multicast
            or address.is_link_local or address.is_reserved
            or not (address.is_private or address in ipaddress.IPv4Network('198.18.0.0/15'))):
        raise ValueError('Select a management IPv4 address, never a wildcard or public listener')
    memory = positive(cfg['container_memory_mib'], 'container_memory_mib', 1024)
    budget = positive(cfg['guest_memory_mib'], 'guest_memory_mib', 2048)
    if memory + 512 > budget:
        raise ValueError('Reserve at least 512 MiB for Debian and Docker outside the container')
    cpus = positive(cfg['cpus'], 'cpus')
    pids = positive(cfg['pids_limit'], 'pids_limit')
    if cpus > 2 or pids > 512 or type(pids) is not int or type(memory) is not int or type(budget) is not int:
        raise ValueError('Review a larger resource allocation separately')
    root = '/srv/homelab/data/pegaprox'
    mounts = [{'type': 'bind', 'source': f'{root}/{name}', 'target': f'/app/{name}',
               'bind': {'create_host_path': False}} for name in ('config', 'logs')]
    mounts.append({'type': 'bind', 'source': KEY_SOURCE, 'target': '/run/secrets/pegaprox-db-key',
                   'read_only': True, 'bind': {'create_host_path': False}})
    return {'name': 'homelab-pegaprox', 'services': {'pegaprox': {
        'image': IMAGE, 'platform': 'linux/amd64', 'pull_policy': 'missing',
        'restart': 'no', 'read_only': True, 'cap_drop': ['ALL'],
        'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp:rw,nosuid,nodev,size=64m'],
        'mem_limit': f'{memory}m', 'cpus': cpus, 'pids_limit': pids,
        'stop_grace_period': '60s',
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
        'ports': [f'{address}:5000:5000/tcp'], 'volumes': mounts,
        'environment': {'PEGAPROX_KEY_FILE': '/run/secrets/pegaprox-db-key',
                        'PEGAPROX_SUPERVISED': '1', 'PEGAPROX_SSH_STRICT_HOST_KEYS': '1',
                        'PEGAPROX_PW_HASH_CONCURRENCY': '2', 'TZ': 'Etc/UTC'}
    }}}


def bootstrap_compose(cfg):
    """Create the initial account with no published host port."""
    document = compose(cfg)
    document['services']['pegaprox'].pop('ports')
    return document


def main():
    """Print only the non-secret preview from an explicitly selected JSON file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    print(json.dumps(compose_preview(json.loads(args.config.read_text())), indent=2))


def health_checks():
    return [{'name': 'PegaProx health and closed initial setup',
             'argv': ['python3', '/opt/homelab-app/pegaprox-setup.py', 'verify'],
             'expect': 'PegaProx verification passed'}]


def validate_deployment(cfg, stack=None):
    """Admit only a clean new installation with fixed secret/probe boundaries."""
    import re
    app = cfg.get('app', {})
    if app.get('clean_install_confirmed') is not True:
        raise ValueError('PegaProx is source preparation until a clean install is explicitly admitted')
    if ('capture' in app or app.get('discovery_routes') or cfg['guest'].get('volumes')
            or app.get('exclusive_writer_confirmed') is not True):
        raise ValueError('PegaProx clean CD has no capture, shared volumes or discovery routes')
    selected = app.get('pegaprox', {})
    if (set(selected) != {'key_source', 'admin_username'}
            or not Path(selected['key_source']).is_absolute()
            or not re.fullmatch(r'[a-z][a-z0-9_-]{1,31}', selected['admin_username'])
            or selected['admin_username'] == 'pegaprox'):
        raise ValueError('Select the database-key file and initial local account')
    stack = json.loads(Path(app['stack_config']).read_text()) if stack is None else stack
    compose(stack)
    guest = cfg['guest']
    nics = guest['interfaces']
    if (len(nics) != 1 or not re.fullmatch(r'02(?::[0-9a-fA-F]{2}){5}', str(nics[0].get('mac')))
            or nics[0].get('ipv6') != 'manual' or guest.get('keyctl') is not False
            or guest.get('nesting') is not True):
        raise ValueError('Select one admitted management NIC, MAC and unprivileged Docker compatibility settings')
    client_rules = []
    for rule in guest['rules']:
        if rule.get('direction') != 'in':
            continue
        if rule.get('proto') != 'tcp' or rule.get('port') not in {'22', '5000'}:
            raise ValueError('Initial PegaProx ingress admits only runner SSH and management HTTPS')
        source = ipaddress.IPv4Network(rule.get('source', ''), strict=True)
        if rule['port'] == '22' and source.prefixlen != 32:
            raise ValueError('Name the individual deployment SSH client')
        if rule['port'] == '5000' and (source.prefixlen < 24 or not (source.is_private or source.subnet_of(ipaddress.IPv4Network('198.18.0.0/15')))):
            raise ValueError('Use an explicit private management client subnet between /24 and /32')
        if rule['port'] == '5000':
            if rule.get('destination') != stack['bind_address'] + '/32':
                raise ValueError('Bind client allowances to this management listener')
            client_rules.append(rule)
    if not 1 <= len(client_rules) <= 8:
        raise ValueError('Select the finite management client allowance before deployment')
    if (stack['guest_memory_mib'] != app['memory_mib']
            or stack['bind_address'] != app['address']
            or app.get('health_checks') != health_checks()):
        raise ValueError('PegaProx listener, budget and fixed verification must match the guest')


if __name__ == '__main__':
    main()
