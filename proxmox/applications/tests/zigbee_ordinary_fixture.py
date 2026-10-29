"""Run the actual read-only ordinary radio preflight tasks on synthetic files."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import yaml
SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
import zigbee2mqtt as radio
from test_zigbee2mqtt import fixture,state
from test_zigbee_first_start_approval import approval_for

with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
    base=Path(tmp);root=base/'data/zigbee2mqtt';root.mkdir(parents=True)
    cfg=fixture()['zigbee'];files=state();cfg['state_sha256']={n:hashlib.sha256(v).hexdigest() for n,v in files.items()}
    for n,v in files.items():(root/n).write_bytes(v)
    checker=base/'checker.py';shutil.copyfile(SOURCE/'zigbee2mqtt.py',checker);checker.chmod(0o700)
    config=base/'config.json';config.write_text(json.dumps(cfg));config.chmod(0o600)
    restore=base/'restore.json';restore.write_text(json.dumps({'state':'complete','sha256':'1'*64,'destination':str(root.parent)}));restore.chmod(0o600)
    admitted=base/'admission.json';radio.check_start(root,cfg,admitted,restore,'1'*64,True,approval_for(cfg,'1'*64,restore))
    facts={'capture_sha256':'1'*64,'selection_sha256':radio.fingerprint(cfg),'checker_sha256':hashlib.sha256(checker.read_bytes()).hexdigest(),
        'restore_receipt_sha256':hashlib.sha256(restore.read_bytes()).hexdigest(),'admission_receipt_sha256':hashlib.sha256(admitted.read_bytes()).hexdigest()}
    tasks=copy.deepcopy(yaml.safe_load((SOURCE/'ansible/zigbee-preflight.yml').read_text())[0]['tasks'][1:])
    replacements={'/opt/homelab-app/zigbee2mqtt.py':str(checker),'/opt/homelab-app/zigbee.json':str(config),'/srv/homelab/data/zigbee2mqtt':str(root),
        '/opt/homelab-app/zigbee-admission.json':str(admitted),'/opt/homelab-app/restore.json':str(restore)}
    raw=json.dumps(tasks)
    for old,new in replacements.items():raw=raw.replace(old,new)
    playbook=base/'preflight.json';playbook.write_text(json.dumps([{'hosts':'all','connection':'local','gather_facts':False,'tasks':json.loads(raw)}]))
    variables=base/'vars.json';variables.write_text(json.dumps({'app':{'zigbee_admission':facts}}))
    command=['ansible-playbook','-i','localhost,',str(playbook),'--extra-vars','@'+str(variables)]
    def run(passes=True):
        result=subprocess.run(command,capture_output=True,text=True,timeout=45)
        if (result.returncode==0)!=passes:raise AssertionError(result.stdout+result.stderr)
    run()
    (root/'database.db').write_bytes(b'legitimate live counter changes');run()
    original=admitted.read_bytes();admitted.write_bytes(b'{}');run(False);assert admitted.read_bytes()==b'{}'
    admitted.write_bytes(original);admitted.chmod(0o600)
    facts['selection_sha256']='2'*64;variables.write_text(json.dumps({'app':{'zigbee_admission':facts}}));run(False)
    assert admitted.read_bytes()==original
    print('Ordinary radio preflight: exact private receipts/checker, mutable live data, altered admission and selected-input drift passed; no repair or first admission')
