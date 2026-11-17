"""Verified effective guest state, separate from immutable deployment history.

The caller owns the existing guest locks. A recovery receipt never masquerades
as an ordinary phase completion and never replaces an OpenTofu backend.
"""
from pathlib import Path
import re

from custody_records import Snapshot, decode, no_markers
from private_io import digest, encoded, private_directory, regular, require, replace_receipt, sha

SCHEMA = 'homelab-component-current-v1'
OWNER = 'homelab-component-reconciled-owner-v1'
VERIFIED = 'homelab-component-recovery-verified-v1'
NAME = 'current-state.json'


def exists(path):
    return path.exists() or path.is_symlink()


def reference(path):
    return {'path': str(path), 'sha256': sha(path)}


def read_reference(value, work, snapshot):
    require(isinstance(value, dict) and set(value) == {'path', 'sha256'}
            and isinstance(value['path'], str) and isinstance(value['sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', value['sha256']),
            'Use an immutable current-state reference')
    path = Path(value['path'])
    require(path.is_absolute() and path.parent.parent == work
            and re.fullmatch(r'(ordinary|recovery)-[1-9][0-9]*-[1-9][0-9]*', path.parent.name),
            'Current state must reference this guest operation')
    raw = snapshot.read(path)
    require(digest(raw) == value['sha256'], 'Current-state evidence changed')
    return path, decode(raw)


def markers(operation):
    """Pin logical custody, retaining all private logs and scratch in place."""
    private_directory(operation)
    no_markers(operation)
    names = [p for p in operation.iterdir() if p.name == 'complete.json'
             or re.fullmatch(r'[a-z][a-z0-9_-]{0,62}-(started|complete)\.json', p.name)]
    require(len(names) <= 258, 'Bound resolved operation phase evidence')
    snapshot = Snapshot()
    result = {p.name: digest(snapshot.read(p)) for p in sorted(names)}
    snapshot.finish()
    return result


def reconciled_owner(value, operation):
    """Validate an explicit engineering reconciliation, never ordinary success."""
    from component_generation import shape, component_binding, fingerprint
    shape(value, {'schema', 'status', 'binding', 'phase_inputs', 'state_sha256',
                  'state_identity', 'workflow', 'run_number', 'site_revision', 'operation'})
    require(value['schema'] == OWNER and value['status'] == 'reconciled'
            and value['operation'] == str(operation)
            and re.fullmatch(r'recovery-[1-9][0-9]*-[1-9][0-9]*', operation.name),
            'Use an explicitly verified reconciled owner')
    component_binding(value['binding'])
    fingerprint(value['state_sha256']); fingerprint(value['site_revision'], 40)
    workflow = value['workflow']
    require(type(value['run_number']) is int and value['run_number'] > 0
            and isinstance(workflow, list) and len(workflow) == 2
            and all(isinstance(part, str) for part in workflow)
            and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', workflow[0])
            and re.fullmatch(re.escape(workflow[0])+r'/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', workflow[1])
            and isinstance(value['phase_inputs'], dict) and isinstance(value['state_identity'], dict),
            'Preserve reconciled workflow, payload and backend ownership')
    from component_generation import sealed_inputs
    from component_payload import AppPayload
    cfg, _ = sealed_inputs(value['binding'])
    require(set(value['phase_inputs']) == set(cfg['deployment']['phases'])
            and value['phase_inputs'].get('preparation') is None,
            'Preserve every reconciled selected phase')
    for phase, proof in value['phase_inputs'].items():
        if phase != 'preparation':
            require(proof['app'] == cfg['deployment']['payload_phases'][phase],
                    'Preserve the reconciled app phase identity')
            AppPayload.load(Path(value['binding']['app_inputs_directory'])/proof['app'], proof)
    require(regular(operation/'owner.json', private=True) == encoded(value),
            'Preserve the immutable reconciled owner')
    return True


def read(work):
    work = Path(work)
    path = work/NAME
    if not exists(path):
        return None
    snapshot = Snapshot()
    value = decode(snapshot.read(path))
    return validate(value, work, snapshot)


def validate(value, work, snapshot):
    from component_generation import shape, fingerprint, component_success
    shape(value, {'schema', 'kind', 'owner', 'verification', 'state_sha256',
                  'state_identity', 'resolved'})
    require(value['schema'] == SCHEMA and value['kind'] in ('ordinary', 'rollback', 'reconciled'),
            'Use the versioned effective current state')
    fingerprint(value['state_sha256'])
    require(isinstance(value['state_identity'], dict)
            and isinstance(value['resolved'], dict) and len(value['resolved']) <= 64,
            'Bound current-state ownership and resolved history')
    owner_path, owner = read_reference(value['owner'], work, snapshot)
    if owner.get('schema') == OWNER:
        require(owner_path.name == 'owner.json' and value['kind'] != 'ordinary',
                'Reconciled ownership cannot become an ordinary phase success')
        reconciled_owner(owner, owner_path.parent)
    else:
        require(owner_path.name == 'complete.json' and component_success(owner, owner_path.parent),
                'Rollback requires genuine prior deployment ownership')
    require(str(owner['binding']['vmid']) == work.name,
            'Current-state owner must belong to this guest')
    proof_path, proof = read_reference(value['verification'], work, snapshot)
    shape(proof, {'schema', 'status', 'kind', 'owner_sha256', 'state_sha256',
                  'state_identity', 'resolved', 'actor', 'reason', 'source_revision'})
    require(proof_path.name == 'verified.json' and proof['schema'] == VERIFIED
            and proof['status'] == 'passed' and proof['kind'] == value['kind']
            and proof['owner_sha256'] == value['owner']['sha256']
            and all(proof[k] == value[k] for k in ('state_sha256', 'state_identity', 'resolved')),
            'Current state requires immutable verification of this exact result')
    fingerprint(proof['source_revision'], 40)
    require(isinstance(proof['actor'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}(?:\[bot\])?', proof['actor'])
            and isinstance(proof['reason'], str) and 0 < len(proof['reason'].strip().encode()) <= 1024,
            'Preserve the identified verification actor and reason')
    for name, entry in value['resolved'].items():
        require(re.fullmatch(r'ordinary-[1-9][0-9]*-[1-9][0-9]*', name)
                and isinstance(entry, dict) and set(entry) == {'hold_sha256', 'markers'},
                'Resolve only identified ordinary operations')
        fingerprint(entry['hold_sha256'])
        require(entry['markers'] == markers(work/name), 'Resolved failure evidence changed')
    snapshot.finish()
    return value, owner


def owner_path(work):
    selected = read(work)
    return Path(selected[0]['owner']['path']) if selected else Path(work)/'ordinary-complete.json'


def owned(value, operation):
    if value.get('schema') == OWNER:
        return reconciled_owner(value, operation)
    from component_generation import component_success
    return component_success(value, operation)


def epoch(state):
    return max(tuple(map(int, Path(state[key]['path']).parent.name.partition('-')[2].split('-')))
               for key in ('owner', 'verification'))


def backend(work, owner):
    selected = read(work)
    if selected:
        state, recorded = selected
        require(recorded == owner, 'Use the selected effective guest owner')
        return state['state_sha256'], state['state_identity']
    return owner['state_sha256'], owner.get('state_identity')


def publish(work, kind, owner, verification):
    """The immutable verification is durable before the atomic pointer changes."""
    value = {'schema': SCHEMA, 'kind': kind, 'owner': reference(owner),
             'verification': reference(verification)}
    proof = decode(regular(verification, private=True))
    value.update({k: proof[k] for k in ('state_sha256', 'state_identity', 'resolved')})
    # Validate using an operation-local candidate before moving the pointer.
    require(proof['schema'] == VERIFIED and proof['status'] == 'passed'
            and proof['kind'] == kind and proof['owner_sha256'] == value['owner']['sha256'],
            'Publish only the verified current owner')
    snapshot = Snapshot()
    validate(value, Path(work), snapshot)
    previous = read(work)
    require(previous is None or epoch(value) >= epoch(previous[0]),
            'Never replace a newer effective guest state with old recovery')
    replace_receipt(Path(work)/NAME, value)


def generation_hash(work):
    path = Path(work)/NAME
    read(work)
    return sha(path if exists(path) else Path(work)/'ordinary-complete.json')
