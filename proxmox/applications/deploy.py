#!/usr/bin/env python3
"""Reconcile one admitted component guest through the existing deployment engines."""
import argparse
import builtins
import json
import os
from pathlib import Path
import subprocess
import commands
from deployment_state import DeploymentAttempt,bootstrap_closed
import proxmox_guest
from private_io import require,read_json


def failure_diagnostic(error):
    """Bound public source locations; never format exception values or locals."""
    kind = type(error)
    known = (getattr(builtins, kind.__name__, None) is kind
             or kind in (subprocess.CalledProcessError, subprocess.TimeoutExpired))
    owned = {str(path): path.name for path in Path(__file__).resolve().parent.glob('*.py')}
    source = []
    current = error.__traceback__
    while current is not None:
        name = owned.get(current.tb_frame.f_code.co_filename)
        if name is not None:
            source = (source + [{'file': name, 'line': current.tb_lineno}])[-4:]
        current = current.tb_next
    return {'error_type': kind.__name__ if known else 'Exception', 'source': source}


def run(phase, packet, *, inputs=Path("/var/lib/homelab-inputs/ordinary"), environment=None, route_executor=None):
    """The same attempt/ToFu/Ansible engines, selected by real component phases."""
    import component_guest
    import component_inputs
    import component_prepare
    import component_ownership
    import component_ansible
    from private_io import encoded
    bootstrap_closed()
    cfg, directory = component_guest.packet(read_json(packet, private=True), inputs)
    phases = component_guest.phases(cfg)
    if (phase == component_guest.AGENT_PHASE and 'monitoring' not in cfg['app']
            or phase == component_guest.BACKUP_PHASE and 'backup' not in cfg['app']):
        return {'status':'not_selected','vmid':cfg['guest']['vmid'],
                'changed':False,'target_contacted':False}
    deferred = phase == 'http-checks'
    require(route_executor is None or deferred, 'A route executor cannot change deployment phases')
    require(phase == 'infrastructure' or phase in phases or deferred and
            cfg['app'].get('route_checks', {}).get('mode') == 'deferred', 'Select this component guest phase')
    site = directory/'site.json'
    def prepare(allow_create):
        prepared, selected = component_inputs.prepare(packet, inputs,
            create=allow_create and phase == 'infrastructure')
        require(encoded(prepared)==encoded(cfg) and selected==site, 'Static component preparation changed')
        return component_inputs.binding(cfg,site)
    with DeploymentAttempt(cfg,None,phases,prepare_inputs=prepare) as attempt:
        expected=attempt.binding
        import component_recovery
        complete = attempt.completed(commands.is_ancestor)
        if deferred:
            import component_routed
            if component_recovery.enabled():
                component_recovery.configured(attempt)
            else:
                require(complete, 'Deferred routes require genuine completion of this exact run and binding')
            return {'vmid':cfg['guest']['vmid'], **component_routed.run(
                cfg, site, attempt.work, attempt.operation, expected,
                **({'executor': route_executor} if route_executor is not None else {}))}
        if complete:
            return {'status':'passed','vmid':cfg['guest']['vmid'],'changed':False,'target_contacted':False}
        if phase == 'infrastructure':
            attempt.begin_infrastructure()
            if component_recovery.enabled():
                component_recovery.once(attempt.operation/'infrastructure-invocation.json', attempt.marker)
            result=proxmox_guest.infrastructure(cfg,site,attempt.work,attempt.operation,expected,
                **({'previous_configuration': attempt.previous_configuration}
                   if 'job' in cfg['app'].get('backup', {}) or 'recording_mount' in cfg['guest'] else {}),
                **({'state_identity':attempt.custody_identity} if attempt.custody_identity is not None else {}))
            attempt.infrastructure_complete(result)
        else:
            attempt.phase_ready(phase)
            payload=None
            previously_owned=False
            initialize_runtime=False
            if phase != 'preparation':
                if phase == component_guest.BACKUP_PHASE:
                    payload = component_prepare.prepare_backup(cfg, environment)
                elif phase==component_guest.AGENT_PHASE:
                    payload=component_prepare.prepare_agent(cfg,environment)
                else:
                    app_id=cfg['deployment']['payload_phases'][phase]
                    runtime=read_json(Path(cfg['deployment']['runtime_file']),private=True)
                    app=runtime['applications'][app_id]
                    previously_owned,runtime_owned=component_ownership.namespaces(attempt,app)
                    initialize_runtime=previously_owned and not runtime_owned and 'runtime_directory' in app['identity']
                    payload=component_prepare.prepare(cfg,app_id,environment,attempt=attempt)
            ready=attempt.begin_phase(phase,payload=payload)
            component_recovery.phase_controls(attempt, phase, payload)
            result=component_ansible.run_phase(cfg,site,attempt.work,attempt.operation,expected,phase,
                payload=payload,previously_owned=previously_owned,
                **({'initialize_runtime':True} if initialize_runtime else {}))
            if phase == phases[-1] and cfg['app'].get('route_checks', {}).get('mode') == 'inline':
                import component_routed
                component_routed.run(cfg, site, attempt.work, attempt.operation, expected)
            result=dict(result,changed=attempt.phase_complete(phase,result,ready,payload=payload))
        return {'status':'passed','vmid':cfg['guest']['vmid'],**result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--packet", type=Path, required=True)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        print(json.dumps(run(args.phase, args.packet)))
    except Exception as error:
        try:
            diagnostic = failure_diagnostic(error)
        except Exception:
            diagnostic = {'error_type': 'Exception', 'source': []}
        raise SystemExit(
            "Deployment held; preserve private inputs, state and all attempt evidence. "
            + ("Generated CD finalization determines rollback or reconciliation."
               if os.environ.get('HOMELAB_CD_RECOVERY') == 'v1' else "No automatic replay or restore.")
            + '\n' + json.dumps(diagnostic, sort_keys=True)
        ) from None



if __name__=="__main__":main()
