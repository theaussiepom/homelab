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


def run(phase, packet, *, inputs=Path("/var/lib/homelab-inputs/ordinary"), environment=None):
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
    require(phase == 'infrastructure' or phase in phases, 'Select this component guest phase')
    site = directory/'site.json'
    def prepare(allow_create):
        prepared, selected = component_inputs.prepare(packet, inputs,
            create=allow_create and phase == 'infrastructure')
        require(encoded(prepared)==encoded(cfg) and selected==site, 'Static component preparation changed')
        return component_inputs.binding(cfg,site)
    with DeploymentAttempt(cfg,None,phases,prepare_inputs=prepare) as attempt:
        expected=attempt.binding
        if attempt.completed(commands.is_ancestor):
            return {'status':'passed','vmid':cfg['guest']['vmid'],'changed':False,'target_contacted':False}
        if phase == 'infrastructure':
            attempt.begin_infrastructure()
            result=proxmox_guest.infrastructure(cfg,site,attempt.work,attempt.operation,expected,
                **({'previous_configuration': attempt.previous_configuration}
                   if 'job' in cfg['app'].get('backup', {}) else {}),
                **({'state_identity':attempt.custody_identity} if attempt.custody_identity is not None else {}))
            attempt.infrastructure_complete(result)
        else:
            attempt.phase_ready(phase)
            payload=None
            previously_owned=False
            if phase != 'preparation':
                if phase == component_guest.BACKUP_PHASE:
                    payload = component_prepare.prepare_backup(cfg, environment)
                elif phase==component_guest.AGENT_PHASE:
                    payload=component_prepare.prepare_agent(cfg,environment)
                else:
                    app_id=cfg['deployment']['payload_phases'][phase]
                    runtime=read_json(Path(cfg['deployment']['runtime_file']),private=True)
                    previously_owned=component_ownership.prior(attempt,runtime['applications'][app_id])
                    payload=component_prepare.prepare(cfg,app_id,environment,attempt=attempt)
            ready=attempt.begin_phase(phase,payload=payload)
            result=component_ansible.run_phase(cfg,site,attempt.work,attempt.operation,expected,phase,
                payload=payload,previously_owned=previously_owned)
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
            "Deployment held; preserve private inputs, state and all attempt evidence. No automatic replay or restore."
            + '\n' + json.dumps(diagnostic, sort_keys=True)
        ) from None



if __name__=="__main__":main()
