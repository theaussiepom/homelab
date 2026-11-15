"""Explicit one-use infrastructure admission; ordinary success still owns apps."""
from pathlib import Path
import re

import commands
import component_generation as generation
from component_payload import AppPayload, SCHEMA as APP_SCHEMA
from custody_records import Snapshot, decode, no_markers
from private_io import encoded, digest, private_directory, regular, require, write_new

SCHEMA = 'homelab-component-infrastructure-admission-v1'
REQUEST = 'infrastructure-admission.json'
CLAIM = 'infrastructure-admission-claim.json'


def absent(path):
    return not (path.exists() or path.is_symlink())


def archived(snapshot, path, inventory):
    """Bind preserved checkpoint/phase bytes and inode to the original inventory."""
    raw = snapshot.read(path)
    row = inventory[path.name]
    generation.shape(row, {'identity', 'sha256'})
    info = path.lstat()
    identity = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns]
    require(row['identity'] == identity and row['sha256'] == digest(raw),
            'Preserve the original archived infrastructure evidence')
    return decode(raw)


def phases(snapshot, operation, inventory, hold, cfg):
    """Verify partial phase provenance without interpreting it as app success."""
    require(absent(operation/'complete.json'), 'A failed checkpoint cannot be ordinary success')
    no_markers(operation)
    names = {p.name for p in operation.iterdir() if
             re.fullmatch('[a-z][a-z0-9_-]{0,62}-(started|complete)\\.json', p.name)
             and p.name != 'infrastructure-complete.json'}
    require(names == {name for name in inventory if
            re.fullmatch('[a-z][a-z0-9_-]{0,62}-(started|complete)\\.json', name)
            and name != 'infrastructure-complete.json'}, 'Preserve the complete archived phase inventory')
    expected = set()
    unfinished = False
    for phase in cfg['deployment']['phases']:
        start, complete = phase+'-started.json', phase+'-complete.json'
        if start not in names:
            unfinished = True
            continue
        require(not unfinished, 'Preserve ordered archived phase provenance')
        started = archived(snapshot, operation/start, inventory)
        proof = started.get('phase_inputs') if isinstance(started, dict) else None
        marker = dict(hold)
        if phase != 'preparation':
            generation.shape(proof, {'schema', 'identity', 'app', 'payload_sha256'})
            require(proof['schema'] == APP_SCHEMA and proof['identity'] == hold['binding']['input_identity']
                    and proof['app'] == cfg['deployment']['payload_phases'][phase],
                    'Preserve the archived selected-app input identity')
            AppPayload.load(Path(hold['binding']['app_inputs_directory'])/proof['app'], proof)
            marker['phase_inputs'] = proof
        require(started == marker, 'Preserve the archived phase start owner')
        expected.add(start)
        if complete in names:
            done = archived(snapshot, operation/complete, inventory)
            generation.shape(done, {'binding', 'result'} | ({'phase_inputs'} if proof is not None else set()))
            require(done['binding'] == hold['binding'] and isinstance(done['result'], dict)
                    and done.get('phase_inputs') == proof, 'Preserve the archived phase completion binding')
            expected.add(complete)
        else:
            unfinished = True
    require(names == expected, 'Preserve every archived phase marker')


def admission(attempt, previous, state_hash, identity):
    """Verify one reviewed archive for the next fresh successor, under existing locks."""
    request = attempt.work/REQUEST
    require(not absent(request), 'Current backend changed outside its ordinary success')
    snapshot = Snapshot()
    raw = snapshot.read(request); value = decode(raw)
    generation.shape(value, {'schema', 'archive_directory', 'archive_inventory_sha256',
                            'hold_sha256', 'checkpoint_sha256', 'previous_ordinary_sha256', 'successor'})
    require(value['schema'] == SCHEMA, 'Use the explicit infrastructure admission schema')
    for field in ('archive_inventory_sha256', 'hold_sha256', 'checkpoint_sha256', 'previous_ordinary_sha256'):
        generation.fingerprint(value[field])
    successor = value['successor']
    generation.shape(successor, {'after_run_id', 'source_ancestor', 'input_identity'})
    generation.fingerprint(successor['source_ancestor'], 40); generation.fingerprint(successor['input_identity'])
    run, retry = map(int, attempt.operation.name.removeprefix('ordinary-').split('-'))
    require(type(successor['after_run_id']) is int and successor['after_run_id'] > 0
            and run > successor['after_run_id'] and retry == 1
            and successor['input_identity'] == attempt.binding['input_identity']
            and commands.is_ancestor(attempt.workspace, successor['source_ancestor'], attempt.site_revision),
            'Admit only the reviewed new successor inputs and source')
    require(absent(attempt.work/CLAIM), 'The infrastructure admission is already consumed')
    previous_raw = snapshot.read(attempt.receipt)
    require(value['previous_ordinary_sha256'] == digest(previous_raw) == digest(encoded(previous))
            and previous.get('state_identity') == identity,
            'Preserve the genuine prior success and every existing backend identity')
    generation.absolute(value['archive_directory']); archive = Path(value['archive_directory'])
    match = re.fullmatch('operator-recovery-([1-9][0-9]*)-([1-9][0-9]*)', archive.name)
    require(archive.parent == attempt.work and match is not None,
            'Select one exact preserved failed-operation archive')
    old_run, old_retry = map(int, match.groups())
    require(old_run <= successor['after_run_id'], 'The successor must follow the reviewed failed operation')
    private_directory(archive); no_markers(archive, own_ordinary=True)
    original = attempt.work/f'ordinary-{old_run}-{old_retry}'
    operation = archive/original.name
    private_directory(operation)
    require(absent(original) and set(p.name for p in archive.iterdir()) ==
            {'original-evidence-inventory.json', 'ORDINARY-HOLD.json', original.name},
            'Preserve the exact archive without replaying its old operation')
    inventory_raw = snapshot.read(archive/'original-evidence-inventory.json')
    require(digest(inventory_raw) == value['archive_inventory_sha256'], 'Preserve the reviewed archive inventory')
    inventory = decode(inventory_raw)
    generation.shape(inventory, {'hold', 'evidence', 'guest_entries', 'operation', 'archive'})
    require(inventory['operation'] == str(original) and inventory['archive'] == str(archive)
            and isinstance(inventory['evidence'], dict) and 1 <= len(inventory['evidence']) <= 10000,
            'Preserve the archived original operation identity')
    hold_raw = snapshot.read(archive/'ORDINARY-HOLD.json')
    require(digest(hold_raw) == value['hold_sha256'], 'Preserve the reviewed failed hold')
    hold = archived(snapshot, archive/'ORDINARY-HOLD.json', {'ORDINARY-HOLD.json': inventory['hold']})
    generation.shape(hold, {'binding', 'operation', 'automatic_retry', 'workflow', 'run_number',
                            'site_revision', 'previous_ordinary_sha256'})
    generation.component_binding(hold['binding']); generation.fingerprint(hold['site_revision'], 40)
    require(hold['operation'] == str(original) and hold['automatic_retry'] is False
            and hold['workflow'] == previous['workflow'] == attempt.workflow
            and type(hold['run_number']) is int and previous['run_number'] < hold['run_number'] < attempt.run_number
            and hold['binding']['vmid'] == attempt.vmid
            and hold['previous_ordinary_sha256'] == value['previous_ordinary_sha256']
            and commands.is_ancestor(attempt.workspace, previous['site_revision'], hold['site_revision'])
            and commands.is_ancestor(attempt.workspace, hold['site_revision'], attempt.site_revision),
            'Preserve the genuine failed hold and source lineage')
    checkpoint_raw = snapshot.read(operation/'infrastructure-complete.json')
    require(digest(checkpoint_raw) == value['checkpoint_sha256'], 'Preserve the reviewed infrastructure checkpoint')
    checkpoint = archived(snapshot, operation/'infrastructure-complete.json', inventory['evidence'])
    generation.shape(checkpoint, {'binding', 'changed', 'created', 'state_sha256', 'state_identity'})
    require(checkpoint['binding'] == hold['binding'] and checkpoint['state_sha256'] == state_hash
            and checkpoint['state_identity'] == identity and checkpoint['created'] is False
            and type(checkpoint['changed']) is bool,
            'The current backend must exactly match the completed owned infrastructure checkpoint')
    cfg, _ = generation.sealed_inputs(hold['binding'])
    require(cfg['site']['node'] == attempt.cfg['site']['node']
            and cfg['site']['api_endpoint'] == attempt.cfg['site']['api_endpoint']
            and all(cfg['guest'][field] == attempt.cfg['guest'][field] for field in ('vmid', 'hostname')),
            'Preserve the checkpoint provider and guest identity')
    # Reuse the exact static-input verifier, then retain its files in the same
    # bounded snapshot that is rechecked immediately before the one-use claim.
    from component_inputs import static, MANIFEST
    directory = Path(hold['binding']['app_inputs_directory']).parent
    for path in [*static(cfg, directory/'site.json'), str(directory/MANIFEST)]:
        snapshot.read(Path(path))
    phases(snapshot, operation, inventory['evidence'], hold, cfg)
    snapshot.finish()
    attempt.infrastructure_admission = (raw, snapshot, state_hash, identity)
    return cfg


def claim(attempt):
    """Consume before native execution; partial claim failure retains the normal hold."""
    selected = getattr(attempt, 'infrastructure_admission', None)
    if selected is None:
        return
    raw, snapshot, state_hash, identity = selected
    snapshot.finish()
    require(generation.backend(attempt.work, {'vmid': attempt.vmid, 'node': attempt.cfg['site']['node']}) ==
            (state_hash, identity), 'Infrastructure admission backend changed before claim')
    write_new(attempt.operation/REQUEST, raw)
    write_new(attempt.work/CLAIM, encoded({'schema': SCHEMA, 'admission_sha256': digest(raw),
                                         'operation': str(attempt.operation)}))
