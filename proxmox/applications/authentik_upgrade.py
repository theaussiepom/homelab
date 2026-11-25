"""Compile the supported retained Authentik release sequence from sealed site inputs."""
import copy
from pathlib import Path
import re

import component_runtime
import component_recovery
from private_io import read_json, require

FAMILIES = ('2025.4', '2025.6', '2025.8', '2025.10', '2025.12', '2026.2', '2026.5', '2026.8')
IMAGE = re.compile(r'ghcr\.io/goauthentik/server:([0-9]{4}\.[1-9][0-9]?)\.(?:0|[1-9][0-9]*)@sha256:[0-9a-f]{64}')


def validate(images):
    require(isinstance(images, list) and len(images) == len(FAMILIES), 'Select one image per Authentik release series')
    for family, image in zip(FAMILIES, images, strict=True):
        match = IMAGE.fullmatch(image) if isinstance(image, str) else None
        require(match and match[1] == family, 'Use consecutive Authentik series and immutable official images')


def images(app):
    selection = app['software_selection']['images']
    require(selection['worker'] == selection['server'], 'Use matching Authentik server and worker images')
    return selection['server']['image']


def transition(old, new):
    """Permit precisely the Redis retirement and media relocation in this path."""
    before = copy.deepcopy(old)
    after = copy.deepcopy(new)
    require('redis' in before['services'] and 'redis' not in after['services'], 'Require the declared Redis predecessor')
    del before['services']['redis']
    require(before['storage'].pop('redis')['target'] == '/data', 'Retain the old Redis bind data')
    media = before['storage']['media']
    require(media['target'] == '/media', 'Require the original Authentik media layout')
    media['target'] = '/data/media'
    data = after['storage'].pop('data')
    require(data['target'] == '/data' and data['kind'] == 'directory' and data['read_only'] is False,
            'Select a writable Authentik data directory')
    require(before == after, 'Preserve the remaining retained Authentik identity, services and storage')


def plan(previous, current, app_id):
    """Render every stage with the same component renderer used in ordinary CD."""
    new = current['applications'][app_id]
    path = new['properties']['upgrade_path']
    validate(path)
    require(new['adapter'] == 'authentik' and new['lifecycle'] == 'retained',
            'Bind the ordered upgrade to the selected retained target')
    old = previous['applications'][app_id]
    old_ref, new_ref = images(old), images(new)
    old_tag, new_tag = IMAGE.fullmatch(old_ref), IMAGE.fullmatch(new_ref)
    if old_tag and new_tag and old_tag[1] == new_tag[1] == FAMILIES[-1]:
        return None
    require(new_ref == path[-1], 'Bind the reviewed target image to the maintenance path')
    require(old['adapter'] == 'authentik' and images(old) == path[0], 'Require the accepted Authentik source image')
    require(not new['settings'].get('oidc_blueprints'), 'Adopt blueprints after the server upgrade')
    for field in ('settings', 'secrets', 'input_sources', 'secret_bindings'):
        require(new.get(field) == old.get(field), 'Preserve Authentik settings and credentials during maintenance')
    project = new['project_name']
    initial = component_runtime.compositions(previous)[project]
    final = component_runtime.compositions(current)[project]
    services = new['identity']['services']
    owned = set(services.values())
    require(set(services) == {'server', 'worker'} and new['project_file'] == old['project_file']
            and old['project_name'] == project, 'Maintain the same owned Authentik project')
    old_peers = {k:v for k,v in initial['services'].items() if k not in old['identity']['services'].values()}
    new_peers = {k:v for k,v in final['services'].items() if k not in owned}
    require(old_peers == new_peers, 'Preserve all shared project peers')
    release_documents = []
    for family, ref in zip(FAMILIES[1:-1], path[1:-1], strict=True):
        runtime = copy.deepcopy(previous if family in ('2025.6', '2025.8') else current)
        app = runtime['applications'][app_id]
        if family == '2025.10':
            del app['storage_paths']['data']
            app['storage_paths']['media']['target'] = '/media'
        for role in ('server', 'worker'):
            app['software_selection']['images'][role] = {'image': ref}
        release_documents.append(component_runtime.compositions(runtime)[project])
    return dict(initial=initial, final=final, stages=release_documents, images=path, project=project,
                roles=[services['server'], services['worker']], redis=old['identity']['services']['redis'],
                peers=sorted(new_peers))


def prepare(attempt, app_id):
    require(attempt.previous_configuration is not None, 'Require an accepted deployment before Authentik maintenance')
    previous = read_json(Path(attempt.previous_configuration['deployment']['runtime_file']), private=True)
    current = read_json(Path(attempt.cfg['deployment']['runtime_file']), private=True)
    return plan(previous, current, app_id)


def phase_options(attempt, phase, app):
    if app is None or app['adapter'] != 'authentik' or 'upgrade_path' not in app.get('properties', {}):
        return {}
    selection = prepare(attempt, app['id'])
    if selection is None:
        return {}
    require(component_recovery.enabled(), 'Use protected CD recovery for Authentik maintenance')
    component_recovery.once(attempt.operation/(phase+'-schema-rollback-limit.json'), {
        'schema': 'homelab-authentik-schema-transition-v1', 'images': selection['images']})
    return {'upgrade': selection}
