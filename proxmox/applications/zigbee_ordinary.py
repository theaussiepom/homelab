"""Radio policy for the shared ordinary engine; never restore, attach or mint admission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import deploy
import foundation_cd as files
import zigbee2mqtt
import zigbee_usb

KIND='zigbee2mqtt'
ADAPTER_API=1
ADMISSION_FIELDS={'capture_sha256','restore_receipt_sha256','admission_receipt_sha256',
                  'selection_sha256','checker_sha256'}


def validate(cfg,stack):
    app=cfg['app'];guest=cfg['guest']
    files.require(app.get('kind')==KIND and stack.get('kind')==KIND and
        'capture' not in app and 'zigbee_first_start_approval' not in app and
        'radio_cd_mode' not in app and 'radio_creation_approved' not in app and
        app.get('usb_stage')=='attached',
        'Ordinary radio deployment needs attached-stage inputs and no restore or first-start request')
    radio=zigbee2mqtt.validate(stack.get('zigbee'))
    zigbee2mqtt.mqtt_alias(stack)
    backend=[n for n in guest['interfaces'] if n.get('role')=='backend']
    files.require(guest.get('serial_device')=={'path':radio['serial_device']} and
        len(backend)==1 and backend[0]['ipv4'].split('/')[0]==radio['bind_address'],
        'Retain the exact admitted coordinator and backend listener')
    admitted=app.get('zigbee_admission')
    files.require(isinstance(admitted,dict) and set(admitted)==ADMISSION_FIELDS and
        all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in admitted.values()) and
        admitted['selection_sha256']==zigbee2mqtt.fingerprint(radio) and
        admitted['checker_sha256']==deploy.sha(Path(__file__).with_name('zigbee2mqtt.py')),
        'Bind the separately accepted first-start and restore receipts, selection and checker')
    # Validate rendering without exposing a key or opening the coordinator.
    import render
    render.compose(stack)


def check_plan(value,cfg,*,existing):
    files.require(existing,'A missing radio requires the existing stopped-create/operator/admission procedure')
    zigbee_usb.check_plan(value,cfg)


def before_infrastructure(cfg,site,work,operation,expected,*,engine):
    # Missing custody is not permission to recreate an admitted physical radio.
    files.regular(work/'terraform.tfstate')
    files.regular(work/'usb-prepared.json',private=True)
    zigbee_usb.require_prepared(cfg,work)
    zigbee_usb.verify_firewall(cfg,deploy.api_get)
    zigbee_usb.verify_live(cfg,deploy.api_get)
    return engine.application(cfg,site,work,operation,expected,
                              playbook='zigbee-preflight.yml')


def application(cfg,site,work,operation,expected,*,engine):
    zigbee_usb.verify_firewall(cfg,deploy.api_get)
    zigbee_usb.verify_live(cfg,deploy.api_get)
    return engine.application(cfg,site,work,operation,expected,
                              playbook='zigbee-reconcile.yml')


def run(phase,packet,*,engine=None,**kwargs):
    if engine is None:
        import ordinary_cd as engine
    files.require(getattr(engine,'GUEST_ADAPTER_API',None)==ADAPTER_API,
                  'Use the reviewed shared ordinary engine with its radio adapter interface')
    return engine.run(phase,packet,adapter=sys.modules[__name__],**kwargs)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('infrastructure','application'),required=True)
    parser.add_argument('--packet',type=Path,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(run(args.phase,args.packet)))
    except Exception:
        raise SystemExit('Ordinary radio deployment held. Preserve state, admissions and failure evidence; no automatic restore, USB repair or replay.') from None
