"""Guest-owned ordinary-CD recovery and completion, plus Reconcile guest."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compile as compiler
import component_current as current
import component_generation as generation
import component_recovery as recovery
import deploy
from private_io import encoded, private_directory, read_json, regular, require, sha, write_new


def context(mode, environment):
    require(environment.get('GITHUB_REF') == 'refs/heads/main', 'Use protected main recovery source')
    event = 'workflow_dispatch' if mode in ('reconcile', 'prepare') else 'push'
    require(environment.get('GITHUB_EVENT_NAME') == event, 'Use the identified recovery workflow event')
    repository = environment.get('GITHUB_REPOSITORY', '')
    workflow = environment.get('GITHUB_WORKFLOW_REF', '')
    require(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            and workflow.startswith(repository+'/.github/workflows/')
            and workflow.endswith('@refs/heads/main'), 'Identify the protected recovery workflow')
    if mode in ('reconcile', 'prepare'):
        require(workflow == repository+'/.github/workflows/reconcile-guest.yml@refs/heads/main',
                'Use only the Reconcile guest workflow')
    for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_RUN_NUMBER'):
        require(re.fullmatch('[1-9][0-9]*', environment.get(name, '')), 'Identify the exact recovery run')


def configuration(packet):
    return json.loads(packet['files']['site.json'])


def operations(packets, *, pending, environment):
    selected = {}
    run = int(environment['GITHUB_RUN_ID'])
    for guest, packet in packets.items():
        cfg = configuration(packet)
        work = Path(cfg['paths']['state_root'])/str(cfg['guest']['vmid'])
        if not work.exists():
            continue
        private_directory(work)
        if pending:
            recovery.close_published(cfg)
            hold_path = work/'ORDINARY-HOLD.json'
            if current.exists(hold_path):
                held_operation = Path(read_json(hold_path, private=True).get('operation', ''))
                require(held_operation.parent == work
                        and current.exists(held_operation/'rollback-baseline.json'),
                        'An earlier ordinary hold needs Reconcile guest after engineering repair')
        candidates = sorted(work.glob('ordinary-*-*/rollback-baseline.json')) if pending else [
            work/('ordinary-'+str(run)+'-'+environment['GITHUB_RUN_ATTEMPT'])/'rollback-baseline.json']
        for path in candidates:
            if not current.exists(path):
                continue
            operation = path.parent
            parts = re.fullmatch('ordinary-([1-9][0-9]*)-([1-9][0-9]*)', operation.name)
            require(parts is not None, 'Select a real ordinary operation')
            if pending and int(parts[1]) >= run:
                continue
            state = current.read(work)
            hold_path = work/'ORDINARY-HOLD.json'
            held = current.exists(hold_path) and read_json(hold_path, private=True).get('operation') == str(operation)
            if state and tuple(map(int, parts.groups())) <= current.epoch(state[0]):
                if not held:
                    continue
                require(operation.name in state[0]['resolved'] or
                        state[0]['kind'] == 'ordinary' and state[1]['operation'] == str(operation),
                        'The held operation conflicts with newer accepted current state')
            failure = work/operation.name.replace('ordinary-', 'recovery-', 1)/'result.json'
            if pending and current.exists(failure):
                require(read_json(failure, private=True).get('status') != 'recovery_required',
                        'Rollback failed; use Reconcile guest after engineering repair')
            value = recovery.baseline(operation, cfg)
            marker = value['marker']
            original_cfg, _ = generation.sealed_inputs(marker['binding'])
            require(all(original_cfg['guest'][key] == cfg['guest'][key] for key in ('vmid', 'hostname'))
                    and original_cfg['site']['node'] == cfg['site']['node'],
                    'Recover only this source-owned guest identity')
            require(guest not in selected, 'Preserve multiple unresolved operations for engineering review')
            selected[guest] = (original_cfg, operation, value)
    return selected


def decision(guest, cfg, operation, mode):
    """Keep an interrupted guest acceptance from becoming a rollback."""
    member = {'operation': str(operation), 'baseline_sha256': sha(operation/'rollback-baseline.json')}
    root = Path(cfg['paths']['state_root'])
    legacy = root/'deployments'/operation.name.removeprefix('ordinary-')/'decision.json'
    folder = operation.parent/operation.name.replace('ordinary-', 'recovery-', 1)
    private_directory(folder, create=not folder.exists())
    path = folder/'decision.json'
    proposed = {'schema': 'homelab-component-guest-decision-v1', 'mode': mode, 'member': member}
    # Preserve decisions from the former coordinator without scanning or
    # changing another guest. New decisions live under this guest's custody.
    if current.exists(legacy):
        private_directory(legacy.parent.parent)
        private_directory(legacy.parent)
        recorded = read_json(legacy, private=True)
        require(recorded.get('schema') == 'homelab-component-deployment-decision-v1'
                and recorded.get('mode') in ('accept', 'rollback')
                and isinstance(recorded.get('members'), dict)
                and recorded['members'].get(guest) == member,
                'Preserve the recorded legacy deployment decision')
        proposed['mode'] = recorded['mode']
    if current.exists(path):
        recorded = read_json(path, private=True)
        require(set(recorded) == set(proposed) and recorded['schema'] == proposed['schema']
                and recorded['member'] == member and recorded['mode'] in ('accept', 'rollback')
                and (not current.exists(legacy) or recorded['mode'] == proposed['mode']),
                'Preserve the exact guest deployment decision')
        return recorded['mode']
    recovery.once(path, proposed)
    return proposed['mode']


def recovery_required(cfg, operation):
    with recovery.locked(cfg):
        folder = operation.parent/operation.name.replace('ordinary-', 'recovery-', 1)
        private_directory(folder, create=not folder.exists())
        recovery.once(folder/'result.json', {'schema': recovery.RESULT, 'status': 'recovery_required',
                                            'failed_operation': str(operation)})


def settle(rows, mode):
    """One guest is the complete recovery unit; other guests are never inspected."""
    require(len(rows) <= 1, 'Settle only the selected guest')
    outcome = []
    for guest, (cfg, operation, _) in rows.items():
        try:
            with recovery.locked(cfg):
                selected = decision(guest, cfg, operation, mode)
                result = (recovery.accept(cfg, operation) if selected == 'accept'
                          else recovery.restore(cfg, operation))
            outcome.append({'guest': guest, **result})
        except Exception as error:
            recovery_required(cfg, operation)
            outcome.append({'guest': guest, 'status': 'recovery_required',
                            'diagnostic': deploy.failure_diagnostic(error)})
    return outcome


def target(packet, work, environment, *, phase=None):
    """Render selected main inputs without enrolling clients or changing a guest."""
    import component_inputs
    import component_guest
    import component_prepare
    import component_input_secrets
    import component_payload
    import component_ownership
    import backup_agent
    cfg = configuration(packet)
    require(phase is None or phase in cfg['deployment']['phases'], 'Select one existing expected-input phase')
    temporary = Path(environment['RUNNER_TEMP'])/('reconcile-'+environment['GITHUB_RUN_ID']+'-'+
        environment['GITHUB_RUN_ATTEMPT']+'-'+str(cfg['guest']['vmid'])+'.json')
    recovery.once(temporary, packet)
    cfg, site = component_inputs.prepare(temporary, Path(cfg['deployment']['input_directory']).parent.parent, create=True)
    previous = current.owner_path(work)
    old = read_json(previous, private=True)
    attempt = SimpleNamespace(receipt=previous, cfg=cfg, work=work, vmid=cfg['guest']['vmid'])
    prior = generation.previous(attempt)
    require(prior is not None, 'Reconciliation requires genuine existing guest ownership')
    _, old_cfg, apps = prior
    require(all(old_cfg['paths'][key] == cfg['paths'][key]
                for key in ('api_token', 'private_key', 'known_hosts', 'ca_file')),
            'Reconciliation preserves commissioned credential and trust paths')
    runtime = read_json(Path(cfg['deployment']['runtime_file']), private=True)['applications']
    require(set(runtime) == set(apps), 'Reconcile existing applications only; no adoption or first installation')
    generation.backup_continuity(old_cfg['app'], cfg['app'])
    proofs = {'preparation': None}
    for selected_phase in cfg['deployment']['phases']:
        if phase is not None and selected_phase != phase:
            continue
        if selected_phase == 'preparation':
            continue
        base_env = {key: value for key, value in environment.items()
                    if not key.startswith(component_input_secrets.PREFIX)}
        if phase is None:
            app_id = cfg['deployment']['payload_phases'][selected_phase]
            payload = component_payload.existing(Path(cfg['deployment']['input_directory'])/'applications',
                cfg['deployment']['input_identity'], app_id)
            require(payload is not None, 'Prepare every expected app input in its own scoped phase first')
        elif selected_phase == component_guest.AGENT_PHASE:
            payload = component_prepare.prepare_agent(cfg, base_env)
        elif selected_phase == component_guest.BACKUP_PHASE:
            parent = component_inputs.app_directory(cfg, create=True)
            payload = component_payload.prepare(parent, cfg['deployment']['input_identity'], 'backup-agent',
                {'application.json': encoded(cfg['app']['backup']), **backup_agent.inputs(cfg['app']['backup'])})
        else:
            app_id = cfg['deployment']['payload_phases'][selected_phase]
            app = runtime[app_id]
            require(component_ownership.prior(attempt, app), 'Reconciliation requires existing app ownership')
            slots = component_input_secrets.slots(app['adapter'], app.get('input_sources', {}))
            base_env.update({slot: environment[slot] for slot in slots.values() if slot in environment})
            payload = component_prepare.prepare(cfg, app_id, base_env, attempt=attempt)
        proofs[selected_phase] = payload.check()
    return cfg, {'binding': component_inputs.binding(cfg, site), 'phase_inputs': proofs,
                 'site_revision': environment['GITHUB_SHA']}


def run(stack, site, disabled, mode, *, guest=None, result=None, baseline='last_good',
        reason='', phase=None, environment=os.environ):
    context(mode, environment)
    require(mode in ('pending', 'finish', 'reconcile', 'prepare'), 'Select one fixed recovery operation')
    selected_disabled = [] if mode in ('reconcile', 'prepare') else compiler.parse_disabled(disabled)
    plan = compiler.resolve_plan(stack, compiler.site_path(site), selected_disabled, admit=True)
    packets = compiler.lower_plan(plan)
    if mode in ('reconcile', 'prepare'):
        require(guest in packets and baseline in ('last_good', 'current_main'), 'Select one known guest and baseline')
        require(isinstance(reason, str) and 0 < len(reason.strip().encode()) <= 1024,
                'Supply a bounded engineering recovery note')
        cfg = configuration(packets[guest])
        with recovery.locked(cfg) as work:
            hold = read_json(work/'ORDINARY-HOLD.json', private=True)
            operation = Path(hold['operation'])
            require(operation.parent == work and re.fullmatch('ordinary-[1-9][0-9]*-[1-9][0-9]*', operation.name),
                    'Select exactly the existing guest ordinary hold')
            if mode == 'prepare':
                require(baseline == 'current_main' and phase is not None, 'Prepare only a scoped current-main input phase')
                target(packets[guest], work, environment, phase=phase)
                return {'status': 'prepared', 'guest': guest, 'phase': phase, 'guest_changed': False}
            expected_controls = None
            selected_path = current.owner_path(work)
            selected = read_json(selected_path, private=True)
            if baseline == 'last_good':
                require(not list(operation.glob('*-rollback-limit.json')),
                        'New control paths have no complete last-good baseline; verify the repaired current_main installation')
                if current.exists(operation/'rollback-baseline.json'):
                    selected_path, selected, cfg = recovery.owner(recovery.baseline(operation, cfg), work)
                    if current.exists(operation/'rollback-ready.json'):
                        ready = read_json(operation/'rollback-ready.json', private=True)
                        require(ready['controls_sha256'] == sha(operation/'controls-before.json'), 'Previous controls changed')
                        expected_controls = read_json(operation/'controls-before.json', private=True)
                else:
                    require(current.owned(selected, Path(selected['operation'])), 'Require genuine prior ownership')
                    cfg, _ = generation.sealed_inputs(selected['binding'])
            else:
                cfg, selected = target(packets[guest], work, environment)
            value = recovery.reconcile(cfg, operation, selected_path, selected,
                reason=reason, actor_context='protected-main-reconciliation', expected_controls=expected_controls)
        return {'status': 'reconciled', 'guests': [{'guest': guest, **value}]}
    require(guest in packets, 'Select one enabled guest for recovery and completion')
    require(result in ('success', 'failure') if mode == 'finish' else result is None,
            'Use only this guest job success or failure result')
    rows = operations({guest: packets[guest]}, pending=mode == 'pending', environment=environment)
    passed = mode == 'finish' and result == 'success'
    require(not passed or bool(rows), 'Guest success requires its completed deployment candidate')
    outcome = settle(rows, 'accept' if passed else 'rollback')
    passed = passed and all(v['status'] == 'accepted' for v in outcome)
    status = ('recovery_required' if any(v['status'] == 'recovery_required' for v in outcome)
              else 'ready' if mode == 'pending' else 'passed' if passed else 'failed_rolled_back'
              if any(v['status'] == 'failed_rolled_back' for v in outcome) else 'failed_no_change')
    return {'status': status, 'guests': outcome, **({'deployment_passed': passed} if mode == 'finish' else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', type=Path, required=True)
    parser.add_argument('--site-root', type=Path, required=True)
    parser.add_argument('--disabled', default='[]')
    parser.add_argument('--mode', choices=['pending', 'finish', 'reconcile', 'prepare'], required=True)
    parser.add_argument('--result', choices=['success', 'failure'])
    parser.add_argument('--guest', required=True)
    parser.add_argument('--phase')
    parser.add_argument('--baseline', choices=['last_good', 'current_main'], default='last_good')
    parser.add_argument('--reason', default='')
    args = parser.parse_args()
    try:
        os.umask(0o077)
        value = run(args.stack, args.site_root, args.disabled, args.mode,
                    guest=args.guest, result=args.result, baseline=args.baseline, reason=args.reason, phase=args.phase)
        print(json.dumps(value, sort_keys=True))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as output:
                output.write('## Guest deployment recovery\n\n```json\n'+json.dumps(value, indent=2)+'\n```\n')
        return 0 if value['status'] in ('passed', 'ready', 'reconciled', 'prepared') else 1
    except Exception as error:
        print(json.dumps({'status': 'recovery_required', 'diagnostic': deploy.failure_diagnostic(error)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
