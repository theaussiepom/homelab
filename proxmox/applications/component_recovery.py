"""Ordinary deployment rollback and explicit engineer reconciliation.

All entry points retain existing guest locks. Failure history is immutable;
only a verified effective-state pointer and its exact hold may be advanced.
"""
from contextlib import contextmanager, ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import component_current as current
import component_generation as generation
import component_restore
from private_io import (digest, encoded, private_directory, read_json, regular,
                        require, sha, sync, write_new, replace_receipt)

SCHEMA = 'homelab-component-rollback-baseline-v1'
RESULT = 'homelab-component-recovery-result-v1'


def record_failure(attempt, error):
    """Called before releasing the existing attempt locks; never logs error values."""
    from component_ansible import CompletedTaskFailure
    operation = getattr(attempt, 'operation', None)
    if error is not None and enabled() and operation is not None and (operation/'rollback-baseline.json').exists():
        once(operation/'forward-failure.json', {
            'schema': 'homelab-component-forward-failure-v1',
            'marker_sha256': sha(attempt.hold),
            'command_returned': isinstance(error, Exception)
                and (not isinstance(error, (subprocess.CalledProcessError, subprocess.TimeoutExpired))
                     or isinstance(error, CompletedTaskFailure))})


def enabled():
    value = os.environ.get('HOMELAB_CD_RECOVERY', '')
    require(value in ('', 'v1'), 'Use the supported CD recovery protocol')
    return value == 'v1'


def once(path, value):
    """An interrupted publication is inspected; immutable evidence is not replaced."""
    raw = encoded(value)
    if current.exists(path):
        require(regular(path, private=True) == raw, 'Recovery evidence already differs')
    else:
        write_new(path, raw)


def attempt_directory(parent, label):
    """Keep interrupted native logs/plans; replan from reality in a new folder."""
    require(re.fullmatch('[a-z][a-z-]{0,40}', label), 'Use a fixed recovery phase name')
    for number in range(1, 9):
        path = parent/(label+'-'+str(number))
        if not current.exists(path):
            private_directory(path, create=True)
            return path
        private_directory(path)
    raise ValueError('Recovery interruption limit reached; reconcile after engineering review')


@contextmanager
def locked(cfg):
    from deployment_state import custody_paths, custody_markers, bootstrap_closed
    bootstrap_closed()
    root = Path(cfg['paths']['state_root']); work = root/str(cfg['guest']['vmid'])
    private_directory(root); private_directory(work)
    with ExitStack() as opened:
        for path, shared in custody_paths(root, work):
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stream = opened.enter_context(os.fdopen(fd, 'a+'))
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        custody_markers(root, work)
        yield work


def credentials(cfg):
    names = ('api_token', 'private_key', 'known_hosts', 'ca_file')
    return {cfg['paths'][key]: digest(regular(Path(cfg['paths'][key]),
                private=key in ('api_token', 'private_key'))) for key in names}


def monitoring_ownership(cfg):
    """Prepared payload locations follow sealed inputs, not agent ownership."""
    value = cfg['app'].get('monitoring')
    if value is None:
        return None
    expected = Path(cfg['deployment']['input_directory'])/'applications/agent/monitoring-agent.json'
    require(isinstance(value, dict) and value.get('credential_file') == str(expected),
            'Bind monitoring credentials to their exact sealed prepared input')
    return {key: selected for key, selected in value.items() if key != 'credential_file'}


def begin(attempt):
    if not enabled():
        return
    previous = generation.previous(attempt)
    selected = current.read(attempt.work)
    baseline = {'schema': SCHEMA, 'marker': attempt.marker,
                'owner': current.reference(Path(previous[0]['operation'])/(
                    'owner.json' if previous[0]['schema'] == current.OWNER else 'complete.json')) if previous else None,
                'current': selected[0] if selected else None,
                'state_sha256': sha(attempt.work/'terraform.tfstate') if previous else None,
                'state_identity': attempt.custody_identity,
                'credentials': credentials(attempt.cfg),
                'dependencies': json.loads(os.environ.get('HOMELAB_CD_DEPENDENCIES', '{}'))}
    once(attempt.operation/'rollback-baseline.json', baseline)
    if previous:
        owner, cfg, _ = previous
        require(all(cfg['paths'][key] == attempt.cfg['paths'][key]
                    for key in ('api_token', 'private_key', 'known_hosts', 'ca_file')),
                'Rollback preserves existing credential and trust paths')
        selection = component_restore.descriptor(owner, cfg)
        captured = component_restore.execute(cfg, attempt.operation, selection, mode='capture')
        once(attempt.operation/'controls-before.json', captured)
        once(attempt.operation/'rollback-ready.json', {
            'baseline_sha256': sha(attempt.operation/'rollback-baseline.json'),
            'controls_sha256': sha(attempt.operation/'controls-before.json')})


def baseline(operation, cfg):
    private_directory(operation)
    value = read_json(operation/'rollback-baseline.json', private=True)
    generation.shape(value, {'schema', 'marker', 'owner', 'current', 'state_sha256', 'state_identity',
                             'credentials', 'dependencies'})
    require(value['schema'] == SCHEMA and value['marker']['operation'] == str(operation)
            and value['marker']['binding']['vmid'] == cfg['guest']['vmid']
            and isinstance(value['dependencies'], dict), 'Bind this exact failed guest operation')
    workflow = value['marker'].get('workflow')
    require(isinstance(workflow, list) and len(workflow) == 2
            and workflow[0] == os.environ.get('GITHUB_REPOSITORY')
            and isinstance(workflow[1], str) and workflow[1].startswith(workflow[0]+'/.github/workflows/'),
            'Preserve another repository or workflow owner; recovery cannot adopt its hold')
    require(value['credentials'] == credentials(cfg), 'Recovery credentials or pinned trust changed')
    return value


def owner(value, work):
    require(value['owner'] is not None, 'New installations have no previous deployment to roll back')
    from custody_records import Snapshot
    snapshot = Snapshot()
    path, selected = current.read_reference(value['owner'], work, snapshot)
    require(current.owned(selected, path.parent), 'Preserve the genuine previous guest owner')
    snapshot.finish()
    cfg, _ = generation.sealed_inputs(selected['binding'])
    return path, selected, cfg


def release(work, marker):
    hold = work/'ORDINARY-HOLD.json'
    if current.exists(hold):
        require(regular(hold, private=True) == encoded(marker), 'Recovery hold ownership changed')
        hold.unlink(); sync(work)


def close_published(cfg):
    """Finish only a verified pointer-before-unlink interruption; no native work."""
    with locked(cfg) as work:
        selected = current.read(work)
        hold_path = work/'ORDINARY-HOLD.json'
        if selected is None or not current.exists(hold_path):
            return False
        state, owner_record = selected
        marker = read_json(hold_path, private=True)
        operation = Path(marker.get('operation', ''))
        require(operation.parent == work, 'Preserve foreign hold paths')
        if operation.name in state['resolved']:
            require(sha(hold_path) == state['resolved'][operation.name]['hold_sha256'],
                    'Published recovery does not own this hold')
        elif state['kind'] == 'ordinary' and owner_record['operation'] == str(operation):
            expected = baseline(operation, cfg)['marker']
            require(marker == expected, 'Published acceptance does not own this hold')
        else:
            return False
        actual = generation.backend(work, {'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']})
        require(actual == (state['state_sha256'], state['state_identity']),
                'Published state changed before completing hold release')
        if state['kind'] == 'ordinary':
            replace_receipt(work/'ordinary-complete.json', owner_record)
        release(work, marker)
        return True


def verified(work, recovery, kind, selected, state_hash, identity, resolved, *, reason):
    private_directory(recovery, create=not recovery.exists())
    source = os.environ.get('GITHUB_SHA', '')
    actor = os.environ.get('GITHUB_ACTOR', '')
    require(re.fullmatch('[0-9a-f]{40}', source) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}(?:\[bot\])?', actor),
            'Identify the protected recovery source and actor')
    proof = {'schema': current.VERIFIED, 'status': 'passed', 'kind': kind,
             'owner_sha256': sha(selected), 'state_sha256': state_hash,
             'state_identity': identity, 'resolved': resolved, 'actor': actor,
             'reason': reason, 'source_revision': source}
    if current.exists(recovery/'verified.json'):
        old = read_json(recovery/'verified.json', private=True)
        require(all(old.get(key) == proof[key] for key in proof if key not in ('actor', 'reason', 'source_revision')),
                'Preserve the original completed recovery verification')
    else:
        once(recovery/'verified.json', proof)
    current.publish(work, kind, selected, recovery/'verified.json')


def resolved(work, operation, marker):
    selected = current.read(work)
    result = dict(selected[0]['resolved']) if selected else {}
    result[operation.name] = {'hold_sha256': digest(encoded(marker)),
                              'markers': current.markers(operation)}
    return result


def configured(attempt):
    """Current-run checks may inspect an owned candidate before final acceptance."""
    attempt._select_run()
    record = read_json(attempt.operation/'complete.json', private=True)
    require(generation.component_success(record, attempt.operation)
            and record['binding'] == attempt.binding
            and record['state_sha256'] == sha(attempt.work/'terraform.tfstate')
            and regular(attempt.hold, private=True) == encoded(attempt.marker),
            'Verify only the exact configured candidate under its pending hold')
    return record


def phase_controls(attempt, phase, payload):
    """Keep supported installation behavior; record an incomplete rollback scope."""
    if not enabled() or payload is None or phase in ('zabbix-agent', 'pbs-agent'):
        return
    saved = read_json(attempt.operation/'rollback-baseline.json', private=True)
    if saved['owner'] is None:
        return
    captured = read_json(attempt.operation/'controls-before.json', private=True)
    selection = component_restore.descriptor({'binding': attempt.binding,
        'phase_inputs': {phase: payload.check()}}, attempt.cfg)
    additions = sorted(set(selection['files']) - set(captured['files']))
    if additions:
        once(attempt.operation/(phase+'-rollback-limit.json'), {
            'schema': 'homelab-component-rollback-limit-v1', 'phase': phase, 'new_control_paths': additions})


def forward_settled(operation, marker):
    """A killed or timed-out writer is not proof of a completed native outcome."""
    incomplete = [p for p in operation.glob('*-started.json')
                  if not current.exists(operation/(p.name.removesuffix('-started.json')+'-complete.json'))]
    if incomplete:
        failure = read_json(operation/'forward-failure.json', private=True)
        require(failure == {'schema': 'homelab-component-forward-failure-v1',
                            'marker_sha256': digest(encoded(marker)), 'command_returned': True},
                'An uncertain forward outcome requires engineer reconciliation')
    window = operation/'apply-window.json'
    require(not current.exists(window) or 'finished_at_ns' in read_json(window, private=True),
            'An unfinished infrastructure apply requires engineer reconciliation')


def reverse_settled(recovery, phase):
    """Resume completed checkpoints; never replay an interrupted native writer."""
    for folder in recovery.glob(phase+'-[1-8]'):
        private_directory(folder)
        if phase == 'infrastructure':
            window = folder/'apply-window.json'
            require(not current.exists(window) or 'finished_at_ns' in read_json(window, private=True),
                    'An interrupted reverse apply requires engineer reconciliation')
        else:
            require(current.exists(folder/'result.json'),
                    'An interrupted configuration restore requires engineer reconciliation')


def accept(cfg, operation):
    work = operation.parent
    value = baseline(operation, cfg)
    candidate = read_json(operation/'complete.json', private=True)
    require(generation.component_success(candidate, operation)
            and candidate['binding'] == value['marker']['binding']
            and candidate['workflow'] == value['marker']['workflow'], 'Require genuine complete guest phases')
    state_hash, identity = generation.backend(work, {'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']})
    require(candidate['state_sha256'] == state_hash and candidate['state_identity'] == identity,
            'Candidate backend changed before final acceptance')
    require(regular(work/'ORDINARY-HOLD.json', private=True) == encoded(value['marker']),
            'Preserve the exact final acceptance hold')
    recovery = work/operation.name.replace('ordinary-', 'recovery-', 1)
    verified(work, recovery, 'ordinary', operation/'complete.json', state_hash, identity, {},
             reason='Ordinary deployment and final acceptance passed')
    replace_receipt(work/'ordinary-complete.json', candidate)
    release(work, value['marker'])
    return {'status': 'accepted', 'vmid': cfg['guest']['vmid']}


def restore(cfg, operation, *, finalize=True):
    """One logical reversal; durable checkpoints bound interruption recovery."""
    import proxmox_guest
    work = operation.parent
    value = baseline(operation, cfg)
    require(regular(work/'ORDINARY-HOLD.json', private=True) == encoded(value['marker']),
            'Rollback requires this exact unresolved deployment hold')
    published = current.read(work)
    if published and operation.name in published[0]['resolved']:
        state_hash, identity = generation.backend(work, {'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']})
        require((state_hash, identity) == (published[0]['state_sha256'], published[0]['state_identity']),
                'Published recovered state changed before hold release')
        release(work, value['marker'])
        return {'status': 'failed_rolled_back', 'vmid': cfg['guest']['vmid']}
    selected_path, selected, old = owner(value, work)
    require(selected['workflow'] == value['marker']['workflow'],
            'Rollback cannot transfer ownership between deployment workflows')
    require(all(old['guest'].get(key) == cfg['guest'].get(key)
                for key in ('vmid', 'hostname', 'volumes', 'recording_mount', 'serial_device'))
            and old['site']['node'] == cfg['site']['node'],
            'Rollback preserves guest storage, hardware and application ownership')
    require(old['app'].get('backup') == cfg['app'].get('backup')
            and monitoring_ownership(old) == monitoring_ownership(cfg),
            'Changed backup or monitoring ownership needs engineer reconciliation')
    recovery = work/operation.name.replace('ordinary-', 'recovery-', 1)
    private_directory(recovery, create=not recovery.exists())
    if not current.exists(recovery/'started.json'):
        component_restore.verify_agents(selected, old, recovery)
    once(recovery/'started.json', {'schema': RESULT, 'operation': str(operation),
                                  'baseline_sha256': sha(operation/'rollback-baseline.json')})
    if not current.exists(operation/'infrastructure-invocation.json'):
        require(sha(work/'terraform.tfstate') == value['state_sha256'],
                'A pre-mutation failure changed its backend')
        return finish_restore(cfg, operation) if finalize else {'status': 'rollback_prepared', 'vmid': old['guest']['vmid']}
    ready = read_json(operation/'rollback-ready.json', private=True)
    require(ready == {'baseline_sha256': sha(operation/'rollback-baseline.json'),
                      'controls_sha256': sha(operation/'controls-before.json')},
            'Preserve the prepared previous managed configuration')
    forward_settled(operation, value['marker'])
    require(not list(operation.glob('*-rollback-limit.json')),
            'A newly installed control namespace requires engineer reconciliation')
    state_hash, identity = generation.backend(work, {'vmid': old['guest']['vmid'], 'node': old['site']['node']})
    original_identity = value['state_identity']
    require(identity == original_identity, 'Recovery cannot adopt changed backend resources')
    if not current.exists(recovery/'infrastructure-restored.json'):
        reverse_settled(recovery, 'infrastructure')
        infra = attempt_directory(recovery, 'infrastructure')
        result = proxmox_guest.infrastructure(old, Path(old['deployment']['input_directory'])/'site.json',
            work, infra, selected['binding'], state_identity=identity,
            previous_configuration=cfg, recovery=True)
        once(recovery/'infrastructure-restored.json', result)
    require(read_json(recovery/'infrastructure-restored.json', private=True)['state_sha256'] == sha(work/'terraform.tfstate'),
            'The restored infrastructure checkpoint changed before configuration recovery')
    selection = component_restore.descriptor(selected, old)
    captured = read_json(operation/'controls-before.json', private=True)
    if not current.exists(recovery/'controls-restored.json'):
        reverse_settled(recovery, 'controls-restore')
        # Only old controls or this source's exact declared replacement bytes
        # may be overwritten. Foreign/manual edits require reconciliation.
        started = {}
        for phase in cfg['deployment']['phases']:
            path = operation/(phase+'-started.json')
            if current.exists(path):
                started[phase] = read_json(path, private=True).get('phase_inputs')
        changed_selection = component_restore.descriptor(
            {'binding': value['marker']['binding'], 'phase_inputs': started}, cfg)
        replacement = {**selection['expected'], **changed_selection['expected']}
        allowed = {path: list(dict.fromkeys([*( [row['sha256']] if row['exists'] else []),
                       *([replacement[path]] if path in replacement else [])]))
                   for path, row in captured['files'].items()}
        result = component_restore.execute(old, recovery, selection, mode='restore',
                                           captured=captured, allowed=allowed)
        once(recovery/'controls-restored.json', result)
    return finish_restore(cfg, operation) if finalize else {'status': 'rollback_prepared', 'vmid': old['guest']['vmid']}


def verify_restore(cfg, operation):
    work = operation.parent
    value = baseline(operation, cfg)
    selected_path, selected, old = owner(value, work)
    recovery = work/operation.name.replace('ordinary-', 'recovery-', 1)
    unchanged = not current.exists(operation/'infrastructure-invocation.json')
    if unchanged:
        require(sha(work/'terraform.tfstate') == value['state_sha256'], 'Unchanged baseline moved')
    else:
        require(read_json(recovery/'infrastructure-restored.json', private=True)['state_sha256'] == sha(work/'terraform.tfstate'),
                'The restored infrastructure checkpoint changed before verification')
        selection = component_restore.descriptor(selected, old)
        captured = read_json(operation/'controls-before.json', private=True)
        component_restore.execute(old, recovery, selection, mode='verify', captured=captured)
        component_restore.verify_agents(selected, old, recovery)
        if 'route_checks' in old['app']:
            import component_routed
            routes = attempt_directory(recovery, 'routes')
            component_routed.run(old, Path(old['deployment']['input_directory'])/'site.json',
                                 work, routes, selected['binding'], historical=True)
    state_hash, identity = generation.backend(work, {'vmid': old['guest']['vmid'], 'node': old['site']['node']})
    proof = {'state_sha256': state_hash, 'state_identity': identity, 'unchanged': unchanged}
    once(recovery/'native-verified.json', proof)
    return proof


def finish_restore(cfg, operation, proof=None):
    work = operation.parent
    value = baseline(operation, cfg)
    selected_path, selected, old = owner(value, work)
    recovery = work/operation.name.replace('ordinary-', 'recovery-', 1)
    proof = verify_restore(cfg, operation) if proof is None else proof
    require(read_json(recovery/'native-verified.json', private=True) == proof,
            'Publish only the completed recovery verification')
    state_hash, identity = generation.backend(work, {'vmid': old['guest']['vmid'], 'node': old['site']['node']})
    require((state_hash, identity) == (proof['state_sha256'], proof['state_identity']),
            'Recovered state changed before publication')
    verified(work, recovery, 'rollback', selected_path, state_hash, identity,
             resolved(work, operation, value['marker']), reason='Failed ordinary deployment rolled back and verified')
    release(work, value['marker'])
    status = 'failed_no_change' if proof['unchanged'] else 'failed_rolled_back'
    once(recovery/'result.json', {'schema': RESULT, 'status': status, 'failed_operation': str(operation)})
    return {'status': status, 'vmid': old['guest']['vmid']}


def order(dependencies, names):
    require(isinstance(dependencies, dict) and set(names) <= set(dependencies),
            'Use the actual selected guest dependency graph')
    pending, done = list(names), []
    while pending:
        ready = [name for name in pending if not set(dependencies[name]) & set(pending)]
        require(bool(ready), 'Recovery dependency graph must be acyclic')
        for name in ready:
            pending.remove(name); done.append(name)
    return list(reversed(done))


def reconcile(cfg, operation, selected_path, selected, *, reason, actor_context, expected_controls=None):
    """Verify engineer repair; no configuration apply, restart or data operation."""
    import proxmox_guest
    work = operation.parent
    require(isinstance(reason, str) and 0 < len(reason.strip().encode()) <= 1024
            and actor_context == 'protected-main-reconciliation', 'Require an identified engineering reconciliation')
    hold = read_json(work/'ORDINARY-HOLD.json', private=True)
    require(hold['operation'] == str(operation) and hold['binding']['vmid'] == cfg['guest']['vmid'],
            'Reconcile exactly the selected guest ordinary hold')
    prior = generation.previous(SimpleNamespace(cfg=cfg, work=work, vmid=cfg['guest']['vmid'],
                                               receipt=current.owner_path(work)))
    require(prior is not None, 'Reconciliation requires genuine immutable prior ownership')
    original, original_cfg, _ = prior
    require(hold['workflow'] == original['workflow']
            and original['workflow'][0] == os.environ.get('GITHUB_REPOSITORY'),
            'Reconciliation cannot transfer a foreign workflow hold or owner')
    require(all(original_cfg['guest'].get(key) == cfg['guest'].get(key)
                for key in ('vmid', 'hostname', 'volumes', 'recording_mount', 'serial_device'))
            and all(original_cfg['site'][key] == cfg['site'][key] for key in ('node', 'api_endpoint'))
            and all(original_cfg['paths'][key] == cfg['paths'][key]
                    for key in ('api_token', 'private_key', 'known_hosts', 'ca_file')),
            'Reconciliation cannot import or relocate persistent ownership')
    identity = generation.backend(work, {'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']})[1]
    expected_identity = current.backend(work, original)[1]
    if expected_identity is None:
        expected_identity = read_json(Path(original['operation'])/'infrastructure-complete.json', private=True)['state_identity']
    require(identity == expected_identity, 'Reconciliation preserves backend resource ownership')
    recovery = work/('recovery-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'])
    private_directory(recovery, create=not recovery.exists())
    inspect = recovery/'infrastructure'; private_directory(inspect, create=not inspect.exists())
    proxmox_guest.infrastructure(cfg, Path(cfg['deployment']['input_directory'])/'site.json',
        work, inspect, selected['binding'], state_identity=identity,
        previous_configuration=original_cfg, recovery=True, verify_only=True)
    selection = component_restore.descriptor(selected, cfg)
    actual = component_restore.execute(cfg, recovery, selection, mode='capture')
    if expected_controls is None:
        component_restore.expected(selection, actual)
    else:
        require(actual == expected_controls, 'Installed controls differ from the recorded last-good deployment')
    component_restore.verify_agents(selected, cfg, recovery)
    if 'route_checks' in cfg['app']:
        import component_routed
        routes = attempt_directory(recovery, 'routes')
        component_routed.run(cfg, Path(cfg['deployment']['input_directory'])/'site.json',
                             work, routes, selected['binding'], historical=True)
    state_hash, identity = generation.backend(work, {'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']})
    record = {'schema': current.OWNER, 'status': 'reconciled', 'binding': selected['binding'],
              'phase_inputs': selected['phase_inputs'], 'state_sha256': state_hash,
              'state_identity': identity, 'workflow': hold['workflow'],
              'run_number': hold['run_number'], 'site_revision': selected['site_revision'],
              'operation': str(recovery)}
    once(recovery/'owner.json', record)
    verified(work, recovery, 'reconciled', recovery/'owner.json', state_hash, identity,
             resolved(work, operation, hold), reason=reason)
    release(work, hold)
    return {'status': 'reconciled', 'vmid': cfg['guest']['vmid']}
