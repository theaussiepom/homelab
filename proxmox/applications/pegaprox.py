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
    """Keep an initial inventory-only proposal finite and deliberately inert."""
    if (set(cfg) != FIELDS or cfg.get('kind') != 'pegaprox'
            or cfg.get('enabled') is not False or cfg.get('deployable') is not False):
        raise ValueError('Use exactly the disabled PegaProx preparation fields')
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
    return {'name': 'homelab-pegaprox-preview', 'services': {'pegaprox': {
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


def main():
    """Print only the non-secret preview from an explicitly selected JSON file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    print(json.dumps(compose_preview(json.loads(args.config.read_text())), indent=2))


if __name__ == '__main__':
    main()
