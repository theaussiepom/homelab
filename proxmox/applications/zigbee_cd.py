"""Initial radio phases over the existing installer; ordinary CD stays separate.

No USB operator call, data extraction, controller or alternative backend exists
here. The shared installer owns workflow/deployment locks and mutation holds.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

import deploy
import foundation_cd as files
import ordinary_cd
import zigbee2mqtt
import zigbee_usb

KIND='zigbee2mqtt'
ADAPTER_API=1
INITIAL_CAPTURE=True
MODES={'prepare','attached','first-start'}


def validate(cfg,stack):
    app=cfg['app'];mode=app.get('radio_cd_mode')
    files.require(mode in MODES and app.get('kind')==stack.get('kind')==KIND
        and app.get('usb_stage')==('prepare' if mode=='prepare' else 'attached')
        and type(app.get('radio_creation_approved')) is bool
        and app['radio_creation_approved']==(mode=='prepare')
        and 'zigbee_admission' not in app,
        'Select an explicit initial radio phase; ordinary admission is separate')
    capture=app.get('capture',{})
    files.require(capture.get('coherent') is True and isinstance(capture.get('path'),str)
        and Path(capture['path']).is_absolute() and re.fullmatch('[0-9a-f]{64}',str(capture.get('sha256',''))),
        'Bind the original verified capture without inventing first-start admission')
    if mode!='prepare':
        files.require(app.get('exclusive_writer_confirmed') is True,'Retire the original writer before attached radio operations')
    if mode=='first-start':
        approval=app.get('zigbee_first_start_approval',{})
        files.require(isinstance(approval,dict) and approval.get('approved') is True
            and approval.get('capture_sha256')==capture['sha256']
            and approval.get('selection_sha256')==zigbee2mqtt.fingerprint(stack['zigbee'])
            and re.fullmatch('[0-9a-f]{64}',str(approval.get('restore_receipt_sha256',''))),
            'First start needs its real external restore receipt and selected approval')
        zigbee2mqtt.approval_digest(approval,stack['zigbee'],capture['sha256'],approval['restore_receipt_sha256'])
    else:
        files.require('zigbee_first_start_approval' not in app,'Preparation and attachment cannot carry first-start authority')
    deploy.validate(cfg,stack)
    import render
    render.compose(stack)


def binding(cfg,site,engine):
    return {'site_sha256':engine.sha(site),'source_sha256':engine.source_hash(),'input_hashes':engine.input_hashes(cfg)}


def initial(action,site,cfg,work,*,engine):
    """Called only inside deploy.execute's existing workflow lock/hold guards."""
    files.require(not any((work/name).exists() or (work/name).is_symlink() for name in
        ('ROLLOUT-HOLD.json','HOLD.json','ORDINARY-HOLD.json')), 'Preserve an existing radio operation hold')
    stack=json.loads(Path(cfg['app']['stack_config']).read_text());validate(cfg,stack)
    mode=cfg['app']['radio_cd_mode']
    files.require(action in {'radio-prepare','radio-attach','radio-start'}
        and (action=='radio-prepare')==(mode=='prepare')
        and (action!='radio-start' or mode=='first-start'), 'The radio action differs from its selected phase')
    complete=work/f'radio-{mode}-{action}-complete.json';state=work/'terraform.tfstate'
    files.private_directory(work)
    engine.check_radio_capture(cfg)
    expected=binding(cfg,site,engine)
    if complete.exists() or complete.is_symlink():
        files.regular(state,private=True)
        old=json.loads(files.regular(complete,private=True))
        files.require(old['binding']==expected and old['state_sha256']==engine.sha(state),
            'Completed radio phase or original backend changed; preserve its evidence')
        return {'status':'passed','changed':False,'target_contacted':False,'mode':mode}
    if mode=='prepare':
        files.require(not state.exists() and not state.is_symlink(), 'Stopped creation is fresh only; never adopt or recreate')
    else:
        zigbee_usb.require_prepared(cfg,work)
        files.private_directory(work/'usb-creation')
        if mode=='first-start':files.regular(work/'radio-attached-radio-attach-complete.json',private=True)
    if action=='radio-start':
        ready=json.loads(files.regular(work/'radio-first-start-radio-attach-complete.json',private=True))
        files.require(ready['binding']==expected and ready['state_sha256']==engine.sha(state)
            and not (work/'started.json').exists(), 'Finish this exact first-start infrastructure phase; no replay')
        steps=('stage','start','verify')
    else:steps=('plan','apply')
    identity='-'.join(os.environ.get(key,'') for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'))
    files.require(re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*',identity), 'Use the identified merge-triggered radio run')
    hold=work/'ROLLOUT-HOLD.json';plan=None;marker=None
    for step in steps:
        if marker is not None:
            files.require(json.loads(files.regular(hold,private=True))==marker,'Radio hold ownership changed; no replay')
        marker={'step':step,'mode':mode,'vmid':cfg['guest']['vmid'],'run':identity,'automatic_retry':False}
        engine.write(hold,marker)
        result=engine._execute_step(step,site,plan)
        if step=='plan':plan=result['plan_sha256']
    if mode=='prepare':
        evidence=work/'usb-creation';files.private_directory(evidence,create=True)
        # Preserve creation identity evidence before attached apply replaces its
        # current plan/window. This is never a workstation state copy.
        for name in ('plan.json','apply-window.json'):
            files.write_new(evidence/name,files.regular(work/name,private=True))
    elif mode=='attached':
        engine.guest_identity.pin(cfg,work/'usb-creation',cfg['app']['address'],
            lambda path:engine.api_get(cfg,path),engine.write)
    files.require(json.loads(files.regular(hold,private=True))==marker,'Radio hold ownership changed; preserve it')
    engine.write(complete,{'binding':binding(cfg,site,engine),'state_sha256':engine.sha(state),'status':'passed','mode':mode})
    files.require(json.loads(files.regular(hold,private=True))==marker,'Radio hold ownership changed; preserve it')
    hold.unlink();engine.sync_directory(work)
    return {'status':'passed','changed':True,'mode':mode,'guest_stays_stopped':mode=='prepare',
        'application_started':action=='radio-start','ordinary_admission_inferred':False}


def run(phase,packet,**kwargs):
    files.require(not any(path.exists() or path.is_symlink() for path in
        (Path('/var/lib/homelab-bootstrap/CONFIGURING'),Path('/var/lib/homelab-bootstrap/BOOTSTRAP-CD-HOLD.json'))),
        'Preserve bootstrap maintenance custody')
    # Script (__main__) and imported callers must use the same pinned module.
    import zigbee_cd as adapter
    cfg,site=ordinary_cd.prepare(packet,adapter=adapter,**kwargs)
    mode=cfg['app']['radio_cd_mode']
    if phase=='infrastructure':action='radio-prepare' if mode=='prepare' else 'radio-attach'
    else:
        files.require(phase=='application' and mode=='first-start','Only the approved first-start phase installs or starts applications')
        action='radio-start'
    return deploy.execute(action,site)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=('infrastructure','application'),required=True);parser.add_argument('--packet',type=Path,required=True);args=parser.parse_args()
    try:print(json.dumps(run(args.phase,args.packet)))
    except Exception:raise SystemExit('Initial radio CD held. Preserve original backend, phase receipts and holds; no automatic restore, USB action or replay.') from None
