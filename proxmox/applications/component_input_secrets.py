"""Finite scalar app inputs; stdlib only and never a workflow secret container.

Only the final selected Deploy process receives these slots. File references
remain protected controller inputs, interpreted by their adapter-owned parser.
"""
import os
from pathlib import Path
import re

from private_io import regular, require

ROLES = {
    'renovate': {'accept_terms', 'license_key', 'github_app_id', 'github_app_key', 'database_password'},
    'postgresql': {'application_database_password'},
    'authentik': {'secret_key', 'postgresql_password', 'smtp_password'},
    'traefik': {'cloudflare_dns_token', 'proxmox_token', 'cloudflare_origin_token'},
    'zabbix': {'database_password'}, 'node_red': {'api_token'},
    'bitwarden': {'runtime_environment'}, 'pegaprox': {'database_key'},
    'winet': {'options'}, 'mqtt': {'probe'}, 'cloudbeaver': {'client_secret'},
    'mqtt_explorer': {'broker_password'},
}
SLOTS = {adapter: {role: adapter + '_' + role for role in roles} for adapter, roles in ROLES.items()}
PREFIX = 'HOMELAB_APP_SECRET_'


def slots(adapter, sources):
    require(isinstance(adapter, str) and isinstance(sources, dict) and
            set(sources) <= ROLES.get(adapter, set()), 'Use only selected adapter secret roles')
    result = {}
    for role, source in sources.items():
        require(isinstance(source, dict) and source.get('type') in ('environment', 'file'),
                'Use only explicit selected app secret sources')
        if source['type'] == 'environment':
            require(set(source) <= {'type', 'name', 'workflow_secret', 'source_id'} and
                    isinstance(source.get('name'), str) and
                    re.fullmatch('[A-Z][A-Z0-9_]{0,127}', source['name']),
                    'Preserve declared scalar secret source metadata')
            result[role] = PREFIX + SLOTS[adapter][role].upper()
        else:
            require(set(source) <= {'type', 'path', 'source_id'} and
                    isinstance(source.get('path'), str) and source['path'].startswith('/') and not source['path'].startswith('//') and
                    str(Path(source['path'])) == source['path'] and
                    not any(part in ('.', '..') for part in source['path'].split('/')),
                    'Preserve explicit private controller file references')
    return result


def selected(adapter, sources, environment=None):
    """Read only this app's named inputs, with no value transformation for CI."""
    environment = os.environ if environment is None else environment
    expected = slots(adapter, sources)
    supplied = {key for key in environment if key.startswith(PREFIX)}
    require(supplied == set(expected.values()), 'Supply exactly the selected scalar app secret slots')
    result = {}
    for role, source in sources.items():
        if source['type'] == 'environment':
            raw = environment[expected[role]]
            require(isinstance(raw, str) and 0 < len(raw.encode()) <= 65536 and raw.strip()
                    and not any(char in raw for char in '\r\n\x00'),
                    'A selected scalar app secret is missing or invalid')
            result[role] = raw.encode()
        else:
            raw = regular(Path(source['path']), private=True, limit=1024*1024)
            require(bool(raw), 'A selected private app input is empty or invalid')
            result[role] = raw
    return result
