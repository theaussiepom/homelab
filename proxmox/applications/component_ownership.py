"""App identity continuity from existing immutable ordinary receipts, no new store."""
import json
from pathlib import Path,PurePosixPath

import component_generation
import component_current
import renovate
from component_payload import AppPayload
from private_io import read_json, require, sha
from application_contract import adapter, runtime_files


def identity(cfg, app):
    return {'node': cfg['site']['node'], 'vmid': cfg['guest']['vmid'],
        'hostname': cfg['guest']['hostname'], 'app': app['id'],
        'runtime_id': app['identity']['runtime_id'],
        'project': app.get('project_name'), 'services': app['identity']['services'],
        'networks': app['identity']['networks'],
        'runtime_directory': app['identity'].get('runtime_directory'),
        'custody_directory': app['identity'].get('custody_directory'),
        'storage': {key: {field: row[field] for field in ('source', 'target', 'kind', 'read_only', 'initialize')
                         if field in row}
                    for key, row in app['storage_paths'].items()}}


def conflicts(first,second):
    """Concrete persistent namespaces cannot transfer to a different app ID."""
    if first.get('project_name')==second.get('project_name') and set(
            first['identity']['services'].values()) & set(second['identity']['services'].values()):
        return True
    if set(adapter(first['adapter'])['native']) & set(adapter(second['adapter'])['native']):
        return True
    one,two=first['identity'].get('custody_directory'),second['identity'].get('custody_directory')
    if one is not None and one==two:return True
    def leaves(app):
        result={row['destination']for row in app.get('sidecar_files',{}).values()}
        runtime=app.get('runtime_files')
        if runtime:
            result.update(runtime['directory']+'/'+name for name in runtime['files'])
        return result
    if leaves(first)&leaves(second):return True
    for a in first['storage_paths'].values():
        for b in second['storage_paths'].values():
            x,y=PurePosixPath(a['source']),PurePosixPath(b['source'])
            if not a['read_only'] and not b['read_only'] and (x==y or x in y.parents or y in x.parents):
                return True
    return False


def prior(attempt, app):
    """Return application ownership independently of its generated namespace."""
    return namespaces(attempt, app)[0]


def replaces_cloudbeaver_gateway(old_app, app, before, current):
    return (old_app['adapter'] == app['adapter'] == 'cloudbeaver'
            and old_app.get('authentication_resolved', {}).get('version') == 1
            and app.get('authentication_resolved') == {'type': 'forward-auth'}
            and old_app['project_file'] == app['project_file']
            and set(before['services']) == {'cloudbeaver', 'auth_gateway'}
            and current['services'] == {'cloudbeaver': before['services']['cloudbeaver']}
            and dict(before, services=current['services']) == current)


def namespaces(attempt, app):
    """A fresh declaration cannot adopt an existing foreign namespace.

    A successful owned fresh app keeps the same lifecycle on ordinary repeats.
    Genuine prior component receipts and sealed payloads own continuation;
    historical authored source is never parsed as active configuration here.
    """
    if not attempt.receipt.exists() and not attempt.receipt.is_symlink():
        require(app['lifecycle'] == 'fresh', 'Retained apps require a genuine prior component owner')
        return False, False
    receipt = read_json(attempt.receipt, private=True)
    operation = Path(receipt['operation']) if isinstance(receipt.get('operation'), str) else None
    if operation is None or not component_current.owned(receipt, operation):
        return False, False
    proofs=[proof for proof in receipt['phase_inputs'].values()
            if proof is not None and proof['app'] not in ('agent', 'backup-agent')]
    selected = [proof for proof in proofs if proof['app'] == app['id']]
    require(len(selected) <= 1, 'Preserve one prior app identity per completed ordinary run')
    previous = Path(receipt['binding']['app_inputs_directory'])
    site = previous.parent/'site.json'
    require(sha(site) == receipt['binding']['site_sha256'], 'Preserve the prior component static source identity')
    old_cfg = read_json(site, private=True)
    for proof in proofs:
        if proof['app']==app['id']:continue
        peer=AppPayload.load(previous/proof['app'],proof)
        old=read_json(peer.directory/'application.json',private=True)
        require(not conflicts(old,app),'A prior app owns the selected persistent namespace')
    if not selected:
        require(app['lifecycle'] == 'fresh', 'Retained apps require their prior sealed application')
        return False, False
    payload = AppPayload.load(previous/app['id'], selected[0])
    old_app = read_json(payload.directory/'application.json', private=True)
    before, current = identity(old_cfg, old_app), identity(attempt.cfg, app)
    if before['runtime_directory'] is None and current['runtime_directory'] is not None:
        files = runtime_files(app)
        require(old_app['adapter'] == app['adapter'] and not old_app.get('runtime_files') and files
                and app.get('runtime_files') == {'app': app['id'], 'guest': app['guest'],
                    'directory': current['runtime_directory'], 'files': sorted(files), 'directory_mounts': []},
                'A first runtime namespace must contain only this adapter owned leaves')
        current['runtime_directory'] = None
    if before != current and app['adapter'] == 'authentik' and 'upgrade_path' in app.get('properties', {}):
        import authentik_upgrade
        path = app['properties']['upgrade_path']
        authentik_upgrade.validate(path)
        require(old_app['adapter'] == 'authentik' and app['lifecycle'] == 'retained'
                and authentik_upgrade.images(old_app) == path[0] and authentik_upgrade.images(app) == path[-1]
                and authentik_upgrade.version(path[0])[:2] < (2025, 10)
                and authentik_upgrade.version(path[-1])[:2] >= (2025, 12),
                'Require the selected Authentik release transition')
        authentik_upgrade.transition(before, current)
        return True, before['runtime_directory'] is not None
    require(before == current or replaces_cloudbeaver_gateway(old_app, app, before, current),
            'App storage or runtime ownership changed; no automatic relocation or adoption')
    renovate.preserve_storage(old_app, app)
    return True, before['runtime_directory'] is not None
