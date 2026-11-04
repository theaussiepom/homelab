"""Private role continuity from validated immutable input proofs, never a store.

Only a selected app phase calls this module. Public configuration and evolving
provider permission metadata are outside its credential material comparison.
"""
import copy
import os
import re
from pathlib import Path
from contextlib import contextmanager

import component_input_secrets
import component_payload
import coordinated_generation
from private_io import decode_json, digest, encoded, read_json, regular, require

SCHEMA = 'homelab-component-private-material-v1'
FILE = 'private-material.json'


def document(app, roles):
    value = {'schema': SCHEMA, 'app': app['id'], 'roles': roles}
    validate(app, value)
    return value


def validate(app, value):
    require(isinstance(value, dict) and set(value) == {'schema', 'app', 'roles'}
            and value['schema'] == SCHEMA and value['app'] == app['id']
            and isinstance(value['roles'], dict)
            and set(value['roles']) == set(app.get('input_sources', {})),
            'Preserve the selected app private role proof')
    component_input_secrets.slots(app['adapter'], app.get('input_sources', {}))
    for role, row in value['roles'].items():
        require(isinstance(row, dict) and set(row) == {'source', 'material_sha256'}
                and row['source'] == app['input_sources'][role]
                and isinstance(row['material_sha256'], str)
                and re.fullmatch('[0-9a-f]{64}', row['material_sha256']),
                'Preserve each selected private role material proof')
    return value['roles']


@contextmanager
def _parent(path):
    require(isinstance(path,str) and path.startswith('/') and not path.startswith('//')
            and str(Path(path))==path and not any(part in ('.','..')for part in path.split('/')),
            'Preserve an absolute canonical legacy input path')
    descriptor=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            os.close(descriptor);descriptor=child
        yield descriptor
    finally:
        os.close(descriptor)


def _read(path):
    with _parent(path) as directory:
        before=os.fstat(directory)
        raw=regular(Path(path).name,private=True,modes=(0o400,0o600),dir_fd=directory)
        with _parent(path) as current:
            after=os.fstat(current)
            require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),
                    'Legacy input parent changed while reading its immutable proof')
        return raw


def _bound(path, binding):
    require(isinstance(path, str) and path in binding['input_hashes'],
            'A legacy private role has no immutable source proof')
    raw = _read(path)
    require(digest(raw) == binding['input_hashes'][path],
            'A legacy private role source changed after its successful binding')
    return raw


def _legacy_site(attempt, receipt):
    """Locate the old compiled site by its genuine receipt hash, never recompile."""
    binding = receipt['binding']
    candidates = {str(Path(path).parent / 'site.json') for path in binding['input_hashes']
                  if Path(path).name == 'stack.json'}
    selection = getattr(attempt, 'initial_selection', None)
    if selection is not None:
        candidates.add(attempt.cfg['initial_ordinary']['installed_site'])
    custody = getattr(attempt, 'custody', None)
    if custody is not None:
        candidates.add(custody['members'][attempt.cfg['app']['kind']]['installed_site'])
    found = []
    for path in sorted(candidates):
        raw = _read(path)
        if digest(raw) == binding['site_sha256']:
            found.append(decode_json(raw))
    require(len(found) == 1, 'Legacy private role continuity requires its hash-bound compiled site')
    cfg = found[0]
    require(isinstance(cfg, dict) and cfg['site']['node'] == attempt.cfg['site']['node']
            and all(cfg['guest'][key] == attempt.cfg['guest'][key] for key in ('vmid', 'hostname')),
            'Preserve the legacy private role guest owner')
    return cfg


def legacy(attempt, receipt, app):
    """Read only finite old compiled input slots; old authored APIs stay retired."""
    from component_private_material import project
    binding = receipt.get('binding')
    required = {'vmid', 'site_sha256', 'source_sha256', 'blueprint_sha256', 'input_hashes'}
    optional = {'coordinated_custody_sha256', 'initial_ordinary_sha256'}
    require(isinstance(binding, dict) and required <= set(binding) <= required | optional
            and len(set(binding) & optional) <= 1 and binding['vmid'] == attempt.cfg['guest']['vmid']
            and isinstance(binding['input_hashes'], dict)
            and receipt.get('status') == 'passed', 'Preserve the closed legacy private input binding')
    for value in [binding[key] for key in required - {'vmid', 'input_hashes'}] + list(binding['input_hashes'].values()):
        require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
                'Preserve legacy private input fingerprints')
    old_cfg = _legacy_site(attempt, receipt)
    old = old_cfg['app']
    stack = decode_json(_bound(old['stack_config'], binding)) if 'stack_config' in old else {}
    adapter, sources, values = app['adapter'], {}, {}
    previous = copy.deepcopy(app)
    def bound(role,path):
        sources[role]={'type':'file','path':path}
        return _bound(path,binding)
    if adapter == 'node_red':
        service=stack.get('services',{}).get('node_red')
        require(isinstance(service,dict) and isinstance(service.get('environment'),dict),
                'Legacy Node-RED selection has no immutable role-presence proof')
        if 'NODE_RED_API_TOKEN' in service['environment']:
            token=service['environment']['NODE_RED_API_TOKEN']
            require(isinstance(token,str) and bool(token),'Legacy Node-RED token has no immutable material proof')
            values['api_token'] = token.encode()
            sources['api_token']={'type':'environment','name':'NODE_RED_API_TOKEN'}
    elif adapter in ('authentik', 'cloudbeaver', 'traefik'):
        foundation = stack.get('foundation', {})
        require(isinstance(foundation,dict) and isinstance(foundation.get('secret_files'),dict),
                'Legacy foundation selection has no immutable role-presence proof')
        names = {'authentik': {'secret_key': 'secret_key', 'postgresql_password': 'postgresql_password',
                              'smtp_password': 'smtp_password'},
                 'cloudbeaver': {'client_secret': 'oauth_client_secret'},
                 'traefik': {'cloudflare_dns_token': 'cloudflare_dns_token', 'proxmox_token': 'proxmox_token'}}[adapter]
        for role, name in names.items():
            if name in foundation.get('secret_files', {}):
                raw = bound(role,foundation['secret_files'][name])
                if role == 'proxmox_token':
                    identity = foundation['proxmox_token_id']
                    raw = encoded({'schema': 'homelab-service-discovery-v1', 'identity': identity,
                                   'token': identity + '=' + raw.decode()})
                    previous['settings']['provider']['token_id'] = identity
                values[role] = raw
    elif adapter == 'winet':
        selected = stack.get('winet', {})
        values['options'] = bound('options',selected.get('configuration_file'))
        previous['settings'] = selected
    elif adapter == 'mqtt':
        values['probe'] = bound('probe',stack.get('mqtt', {}).get('credential_file'))
    elif adapter == 'bitwarden':
        values['runtime_environment'] = bound('runtime_environment',old.get('bitwarden', {}).get('runtime_env_file'))
    elif adapter == 'pegaprox':
        values['database_key'] = bound('database_key',old.get('pegaprox', {}).get('key_source'))
    else:
        require(not app.get('input_sources'), 'This private role has no genuine legacy material proof')
    previous['input_sources'] = sources
    return project(previous, values)


def verify(attempt, app, current):
    """Refuse drift before this app publishes inputs or creates credential records."""
    validate(app, current)
    receipt_path = attempt.receipt
    if not receipt_path.exists() and not receipt_path.is_symlink():
        require(not current['roles'] or app['lifecycle'] == 'fresh',
                'Retained private roles require a genuine prior successful input proof')
        return
    receipt = read_json(receipt_path, private=True)
    operation = Path(receipt['operation']) if isinstance(receipt.get('operation'), str) else None
    if operation is not None and coordinated_generation.component_success(receipt, operation):
        proofs = [row for row in receipt['phase_inputs'].values()
                  if row is not None and row['app'] == app['id']]
        require(len(proofs) <= 1, 'Preserve one prior private role owner per app')
        if not proofs:
            return
        selected = component_payload.AppPayload.load(
            Path(receipt['binding']['app_inputs_directory']) / app['id'], proofs[0])
        old_app = read_json(selected.directory / 'application.json', private=True)
        old = validate(old_app, read_json(selected.directory / FILE, private=True))
    else:
        if not current['roles'] and (app.get('lifecycle')!='retained' or app['adapter'] not in {
                'node_red','authentik','cloudbeaver','traefik','winet','mqtt','bitwarden','pegaprox'}):
            return
        old = legacy(attempt, receipt, app)
    require(set(old) <= set(current['roles']),
            'An ordinary update cannot remove a sealed private role or erase its continuity')
    require(all(row['material_sha256'] == current['roles'][role]['material_sha256']
                for role, row in old.items()),
            'Private role material changed; ordinary deployment cannot rotate credentials')
