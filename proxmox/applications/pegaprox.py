#!/usr/bin/env python3
"""Owned pure PegaProx service configuration and fixed health primitives."""

from resources import positive
from discovery import PRIVATE_BACKENDS



def service_configuration(service, *, trusted_proxy, mount, data_sources, ports):
    """Pure PegaProx protocol and storage settings; no key contents are read."""
    service.update(platform='linux/amd64', read_only=True, cap_drop=['ALL'],
        security_opt=['no-new-privileges:true'], tmpfs=['/tmp:rw,nosuid,nodev,size=64m'], ports=ports)
    service['volumes'] = [{'type': 'bind', 'source': data_sources[name], 'target': '/app/' + name,
        'bind': {'create_host_path': False}} for name in ('config', 'logs')]
    service['volumes'].append(mount('pegaprox-db-key', '/run/secrets/pegaprox-db-key'))
    service['environment'] = {
        'PEGAPROX_BEHIND_PROXY': 'true', 'PEGAPROX_HOST': '0.0.0.0',
        'PEGAPROX_TRUSTED_PROXIES': trusted_proxy, 'PEGAPROX_KEY_FILE': '/run/secrets/pegaprox-db-key',
        'PEGAPROX_SUPERVISED': '1', 'PEGAPROX_SSH_STRICT_HOST_KEYS': '1',
        'PEGAPROX_PW_HASH_CONCURRENCY': '2', 'TZ': 'Etc/UTC'}
    return service




def health_checks():
    return [
        {
            "name": "PegaProx health and closed initial setup",
            "argv": ["python3", "/opt/homelab-app/pegaprox-health.py"],
            "expect": "PegaProx verification passed",
        }
    ]
