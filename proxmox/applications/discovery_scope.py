"""Read-only adoption checks for retained, mirrored Traefik discovery access.

Only bootstrap CD manages grants. This reader never creates credentials or writes
Proxmox configuration, and never turns a missing grant into an automatic repair.
"""
import importlib
import hmac
import json
from pathlib import Path
import re
import ssl
import sys
import urllib.request
from urllib.parse import urlsplit
from urllib.parse import quote

from private_io import require
import network_endpoints

BOOTSTRAP = Path(__file__).resolve().parents[1] / 'bootstrap'


def selected(stack):
    value = stack.get('foundation', {}).get('discovery_scope')
    if value is None:
        return None
    require(stack.get('kind') == 'ingress' and isinstance(value, dict)
            and set(value) == {'local_directory', 'mirror_directory', 'owner_sha256', 'guests'},
            'Discovery verification belongs only to the ingress foundation')
    for name in ('local_directory', 'mirror_directory'):
        path = value[name]
        require(isinstance(path, str) and Path(path).is_absolute() and '..' not in Path(path).parts
                and Path(path).name == 'service-discovery', 'Bind existing discovery custody directories')
    require(value['local_directory'] != value['mirror_directory']
            and isinstance(value['owner_sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['owner_sha256'])
            and isinstance(value['guests'], list) and 1 <= len(value['guests']) <= 32
            and all(type(v) is int and v >= 100 and v not in {900, 4914, 4915, 4920} for v in value['guests'])
            and len(set(value['guests'])) == len(value['guests']), 'Bind one exact finite owned discovery scope')
    return value


def origin(value):
    """Accept only the already owned HTTPS origin, ignoring its trailing slash."""
    require(isinstance(value, str) and len(value) <= 2048 and not any(c.isspace() for c in value)
            and '\\' not in value, 'Use the existing HTTPS discovery origin')
    url = urlsplit(value)
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and url.path in {'', '/'} and not url.query and not url.fragment,
            'Use the existing HTTPS discovery origin')
    try:
        require(url.port is None or 1 <= url.port <= 65535, 'Use the existing HTTPS discovery origin')
    except ValueError:
        raise ValueError('Use the existing HTTPS discovery origin') from None
    return value.rstrip('/')


def provider():
    """Load the same pinned bootstrap read helpers without invoking its executor."""
    sys.path.insert(0, str(BOOTSTRAP))
    try:
        module = importlib.import_module('provider_access')
    finally:
        sys.path.pop(0)
    require(Path(module.__file__).resolve() == BOOTSTRAP / 'provider_access.py',
            'Use only the current published discovery ownership reader')
    return module


def source_files(stack):
    value = selected(stack)
    if value is None:
        return []
    result = []
    for key in ('local_directory', 'mirror_directory'):
        root = Path(value[key])
        result += [str(root / name) for name in ('owner.json', 'token.json', 'READY.json')]
        extensions = root / 'scope-extensions'
        if extensions.exists() or extensions.is_symlink():
            require(extensions.is_dir() and not extensions.is_symlink(), 'Preserve real discovery extension directories')
            names = sorted(extensions.iterdir())
            require(len(names) <= 31 and all(re.fullmatch('[0-9]{4}\\.json', p.name) for p in names),
                    'Preserve the bounded discovery extension chain')
            result += [str(p) for p in names]
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Discovery verification never follows redirects')


class Reader:
    """GET-only TLS client; the retained credential remains inside this process."""
    def __init__(self, endpoint, ca_file, token=None):
        self.endpoint, self.ca_file, self.token = endpoint, ca_file, token

    def discovery(self, token):
        return Reader(self.endpoint, self.ca_file, token)

    def call(self, path):
        require(self.token is not None and (path == '/access/permissions'
                or re.fullmatch('/nodes/[A-Za-z0-9-]+/lxc/[1-9][0-9]*/config', path)),
                'Use only read-only discovery permission and guest-config endpoints')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=self.ca_file)))
        request = urllib.request.Request(self.endpoint.rstrip('/') + '/api2/json' + path,
                    headers={'Authorization': 'PVEAPIToken=' + self.token})
        with opener.open(request, timeout=15) as response:
            raw = response.read(2 * 1024**2 + 1)
        require(len(raw) <= 2 * 1024**2, 'Bound discovery verification responses')
        value = json.loads(raw)
        require(isinstance(value, dict) and 'data' in value, 'Require the native discovery response envelope')
        return value


def verify(cfg, stack, api=None):
    value = selected(stack)
    if value is None:
        return {'status': 'not_selected', 'writes': False}
    access = provider()
    local, mirror = Path(value['local_directory']), Path(value['mirror_directory'])
    owner = access.scope_owner(local, mirror)
    require(access.owner_sha256(owner) == value['owner_sha256']
            and owner['configuration']['guests'] == value['guests']
            and owner['configuration']['vmid'] == cfg['guest']['vmid']
            and owner['configuration']['address'] in network_endpoints.addresses(cfg['guest'])
            and owner['node'] == cfg['site']['node']
            and origin(owner['endpoint']) == origin(stack['foundation']['proxmox_url']),
            'Discovery desired scope is not owned; complete reviewed privileged bootstrap CD')
    selected_config = {'node': owner['node'], 'endpoint': owner['endpoint'],
        'service_discovery': owner['configuration'], 'applications': [{'vmid': v} for v in value['guests']]}
    access.validate(selected_config)
    require(access.identity(selected_config)[1] == stack['foundation']['proxmox_token_id'],
            'Preserve the retained discovery identity')
    secret = access.retained(selected_config, local.parent, mirror.parent)
    require(secret is not None, 'Discovery access is missing; complete reviewed privileged bootstrap CD')
    from foundation import read_private
    configured = stack['foundation']['proxmox_token_id'] + '=' + read_private(stack['foundation']['secret_files']['proxmox_token'])
    require(hmac.compare_digest(configured, secret),
            'Configured discovery credential differs from its retained owner')
    api = Reader(owner['endpoint'], stack['foundation']['pve_ca_file']) if api is None else api
    # Effective privilege values are non-propagation flags: zero means a present
    # non-propagating grant, NOT an absent privilege. Reuse the exact owner check.
    try:
        access.verify_secret(api, selected_config, configured)
    except (OSError, ValueError):
        raise ValueError('Discovery read access is not verified; complete reviewed privileged bootstrap CD') from None
    reader = api.discovery(configured)
    for vmid in value['guests']:
        try:
            config = reader.call('/nodes/' + quote(owner['node'], safe='') + '/lxc/' + str(vmid) + '/config')['data']
        except (OSError, ValueError):
            raise ValueError('A declared guest is not visible; complete reviewed privileged bootstrap CD') from None
        require(isinstance(config, dict) and isinstance(config.get('hostname'), str) and config['hostname'],
                'A declared guest is not visible; complete reviewed privileged bootstrap CD')
    return {'status': 'verified', 'owned_scope': True, 'effective_permissions': True,
            'visible_guests': len(value['guests']), 'writes': False}
