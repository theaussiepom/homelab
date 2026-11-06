"""App identity continuity from existing immutable ordinary receipts, no new store."""
import json
from pathlib import Path,PurePosixPath

import component_generation
from component_payload import AppPayload
from private_io import read_json, require, sha
from application_contract import adapter


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
    """A fresh declaration cannot adopt an existing foreign namespace.

    A successful owned fresh app keeps the same lifecycle on ordinary repeats.
    Genuine prior component receipts and sealed payloads own continuation;
    historical authored source is never parsed as active configuration here.
    """
    if not attempt.receipt.exists() and not attempt.receipt.is_symlink():
        require(app['lifecycle'] == 'fresh', 'Retained apps require a genuine prior component owner')
        return False
    receipt = read_json(attempt.receipt, private=True)
    operation = Path(receipt['operation']) if isinstance(receipt.get('operation'), str) else None
    if operation is None or not component_generation.component_success(receipt, operation):
        return False
    proofs=[proof for proof in receipt['phase_inputs'].values()if proof is not None and proof['app']!='agent']
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
        return False
    payload = AppPayload.load(previous/app['id'], selected[0])
    old_app = read_json(payload.directory/'application.json', private=True)
    require(identity(old_cfg, old_app) == identity(attempt.cfg, app),
            'App storage or runtime ownership changed; no automatic relocation or adoption')
    return True
