"""Static component inputs under existing attempt locks; no app secret reads."""
import json
import os
from pathlib import Path

import component_guest
import component_payload
import coordinated_contract
import coordinated_evidence
import initial_ordinary
import monitoring_inputs
import discovery_scope
from private_io import encoded, digest, read_json, regular, require, sha, write_new

SCHEMA = 'homelab-component-static-inputs-v1'
MANIFEST = 'component-prepared.json'


def _folder(parent, name, create):
    with component_payload._directory(parent) as directory:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            require(create, 'A held or later phase may only verify existing static inputs')
            os.mkdir(name, 0o700, dir_fd=directory)
            os.fsync(directory)
    with component_payload._directory(Path(parent)/name):
        pass


def inspect(cfg, site):
    component_guest.validate(cfg)
    directory = Path(cfg['deployment']['input_directory'])
    require(Path(site) == directory/'site.json', 'Bind the immutable component configuration file')
    with component_payload._directory(directory) as descriptor:
        manifest = component_payload._read(descriptor, MANIFEST)
        value = json.loads(manifest)
        require(isinstance(value, dict) and set(value) == {'schema', 'packet_sha256', 'identity', 'files'}
                and value['schema'] == SCHEMA and value['identity'] == cfg['deployment']['input_identity']
                and isinstance(value['files'], dict) and {'site.json', 'component-runtime.json'} <= set(value['files'])
                and set(os.listdir(descriptor)) in (set(value['files']) | {MANIFEST},
                    set(value['files']) | {MANIFEST, 'applications'}),
                'Preserve the complete static component input publication')
        actual = {}
        for name, expected in value['files'].items():
            component_payload._files({name: b''})
            require(name != MANIFEST, 'Static inputs cannot replace their manifest')
            raw = component_payload._read(descriptor, name)
            require(digest(raw) == expected, 'Static component inputs changed')
            actual[str(directory/name)] = expected
        require(component_payload._read(descriptor, 'site.json') == encoded(cfg),
                'Preserve the exact static component configuration')
    applications = directory/'applications'
    if applications.exists() or applications.is_symlink():
        with component_payload._directory(applications):
            pass
    return actual


def prepare(packet_path, inputs, *, create):
    """Publish only static source bytes, or verify a prior complete publication."""
    value = read_json(packet_path, private=True)
    cfg, directory = component_guest.packet(value, inputs)
    require(type(create) is bool, 'Select explicit static create or verify behavior')
    payload = {name: raw.encode() for name, raw in value['files'].items()}
    hashes = component_payload._files(payload)
    require(MANIFEST not in hashes, 'Static inputs cannot replace their manifest')
    manifest = encoded({'schema': SCHEMA, 'packet_sha256': sha(packet_path),
                        'identity': value['identity'], 'files': hashes})
    root = Path(inputs)
    # The existing bootstrap owns the private input root. No system-directory
    # creation, permission repair or new input store is introduced here.
    _folder(root.parent, root.name, create)
    _folder(root, value['guest'], create)
    with component_payload._directory(root/value['guest']) as parent:
        try:
            os.stat(value['identity'], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            require(create, 'A held or later phase may only verify existing static inputs')
            os.mkdir(value['identity'], 0o700, dir_fd=parent)
            os.fsync(parent)
            with component_payload._directory(directory) as descriptor:
                for name, raw in sorted(payload.items()):
                    write_new(name, raw, dir_fd=descriptor)
                write_new(MANIFEST, manifest, dir_fd=descriptor)
    with component_payload._directory(directory) as descriptor:
        require(component_payload._read(descriptor, MANIFEST) == manifest,
                'Static component preparation differs or was interrupted; never adopt or resume')
    inspect(cfg, directory/'site.json')
    return cfg, directory/'site.json'


def binding(cfg, site):
    """Immutable common/source binding, excluding every selected-app payload."""
    hashes = inspect(cfg, site)
    external = [cfg['paths']['ca_file']]
    if 'monitoring' in cfg['app']:
        external += monitoring_inputs.source_files()
    runtime=read_json(Path(cfg['deployment']['runtime_file']),private=True)
    for app in runtime['applications'].values():
        if app['adapter']=='traefik':
            external += [row['source'] for row in app['settings'].get('route_ca_files',{}).values()]
            scope=app['settings']['provider'].get('discovery')
            if scope is not None:
                external += discovery_scope.scope_source_files(scope,cfg['deployment']['protected_guests'])
    if cfg['guest'].get('serial_device'):
        external += [cfg['paths']['host_device_key'], cfg['paths']['host_known_hosts']]
    hashes.update({path: sha(path) for path in external})
    proofs, _, _ = coordinated_evidence.inspect(cfg)
    hashes.update(proofs)
    proofs, _, _ = initial_ordinary.inspect(cfg)
    hashes.update(proofs)
    from deployment_inputs import source_hash
    result = {'schema': component_payload.BINDING_SCHEMA, 'vmid': cfg['guest']['vmid'],
        'site_sha256': sha(site), 'source_sha256': source_hash(),
        'input_identity': cfg['deployment']['input_identity'],
        'app_inputs_directory': str(Path(cfg['deployment']['input_directory'])/'applications'),
        'input_hashes': hashes}
    if coordinated_contract.selection(cfg) is not None:
        result['coordinated_custody_sha256'] = coordinated_contract.selection_digest(cfg)
    if initial_ordinary.selection(cfg) is not None:
        result[initial_ordinary.BINDING] = initial_ordinary.selection_digest(cfg)
    require(not {'coordinated_custody_sha256', initial_ordinary.BINDING} <= set(result),
            'Select one historical component admission contract')
    return result


def app_directory(cfg, *, create):
    directory = Path(cfg['deployment']['input_directory'])
    _folder(directory, 'applications', create)
    return directory/'applications'
