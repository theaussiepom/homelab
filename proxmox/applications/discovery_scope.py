"""Read-only adoption checks for retained, mirrored Traefik discovery access.

Only bootstrap CD manages grants. This reader never creates credentials or writes
Proxmox configuration, and never turns a missing grant into an automatic repair.
"""
import importlib
import hmac
import json
from http.client import HTTPException
from pathlib import Path
import re
import ssl
import sys
import urllib.request
from urllib.parse import urlsplit

from private_io import require
import network_endpoints

BOOTSTRAP = Path(__file__).resolve().parents[1] / 'bootstrap'


def selected_scope(value):
    """Select read-only discovery for all guests without a permission inventory."""
    require(isinstance(value, dict) and set(value) ==
            {'local_directory', 'mirror_directory', 'scope'} and value['scope'] == 'all-guests',
            'Bind the owned all-guest read-only discovery scope')
    for name in ('local_directory', 'mirror_directory'):
        path = value[name]
        require(isinstance(path, str) and Path(path).is_absolute() and '..' not in Path(path).parts
                and Path(path).name == 'service-discovery', 'Bind existing discovery custody directories')
    require(value['local_directory'] != value['mirror_directory'], 'Keep discovery custody independent')
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




def scope_source_files(value):
    value=selected_scope(value)
    result = []
    for key in ('local_directory', 'mirror_directory'):
        root = Path(value[key])
        result += [str(root / name) for name in ('owner.json', 'token.json', 'READY.json')]
        policy = root/'read-scope.json'
        if policy.exists() or policy.is_symlink():
            result.append(str(policy))
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
        require(self.token is not None and path in ('/access/permissions', '/cluster/resources?type=vm'),
                'Use only read-only discovery permission and guest-list endpoints')
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


def verify_selection(cfg, value, *, endpoint, token_id, ca_file, read_configured, api=None):
    """Verify existing owned scope, mirrored READY/token and exact effective GETs."""
    value = selected_scope(value)
    access = provider()
    local, mirror = Path(value['local_directory']), Path(value['mirror_directory'])
    owner = access.scope_owner(local, mirror)
    require(owner['schema'] == access.OWNER_SCHEMA and owner['configuration']['scope'] == 'all-guests'
            and owner['configuration']['vmid'] == cfg['guest']['vmid']
            and owner['configuration']['address'] in network_endpoints.addresses(cfg['guest'])
            and owner['node'] == cfg['site']['node']
            and origin(owner['endpoint']) == origin(endpoint),
            'Discovery desired scope is not owned; complete reviewed privileged bootstrap CD')
    selected_config = {'node': owner['node'], 'endpoint': owner['endpoint'],
        'service_discovery': owner['configuration'], 'applications': [{'vmid': cfg['guest']['vmid']}]}
    access.validate(selected_config)
    require(access.identity(selected_config)[1] == token_id,
            'Preserve the retained discovery identity')
    secret = access.retained(selected_config, local.parent, mirror.parent)
    require(secret is not None, 'Discovery access is missing; complete reviewed privileged bootstrap CD')
    configured = read_configured()
    require(hmac.compare_digest(configured, secret),
            'Configured discovery credential differs from its retained owner')
    api = Reader(owner['endpoint'], ca_file) if api is None else api
    # Effective privilege values are non-propagation flags: zero means a present
    # non-propagating grant, NOT an absent privilege. Reuse the exact owner check.
    try:
        access.verify_secret(api, selected_config, configured)
    except (OSError, ValueError, TypeError, AttributeError, HTTPException):
        raise ValueError('Discovery read access is not verified; complete reviewed privileged bootstrap CD') from None
    reader = api.discovery(configured)
    try:
        guests = reader.call('/cluster/resources?type=vm')['data']
    except (OSError, ValueError, HTTPException):
        raise ValueError('Guest discovery is not visible; complete reviewed privileged bootstrap CD') from None
    require(isinstance(guests, list) and all(isinstance(row, dict) for row in guests)
            and sum(row.get('vmid') == cfg['guest']['vmid'] and row.get('node') == owner['node'] for row in guests) == 1,
            'The owned discovery guest is not visible')
    return {'status': 'verified', 'owned_scope': True, 'effective_permissions': True,
            'visible_guests': len(guests), 'scope': 'all-guests', 'writes': False}
