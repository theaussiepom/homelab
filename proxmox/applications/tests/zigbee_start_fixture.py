"""Run the real radio admission tasks in Ansible; no Docker, service or USB use."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
import restore
from test_zigbee2mqtt import fixture,state
from test_zigbee_first_start_approval import approval_for

# GNU tar ACL restoration needs the ordinary writable layer, not /tmp tmpfs.
with tempfile.TemporaryDirectory(dir='/var/tmp') as temporary:
    base=Path(temporary);root=base/'data/zigbee2mqtt';root.mkdir(parents=True)
    files=state();cfg=fixture()['zigbee']
    cfg['state_sha256']={n:hashlib.sha256(v).hexdigest() for n,v in files.items()}
    for name,data in files.items():(root/name).write_bytes(data)
    capture=base/'capture.tar'
    subprocess.run(['tar','--create','--file',str(capture),'-C',str(root.parent),'zigbee2mqtt'],check=True)
    # Restore to another empty tree through the actual no-replay helper.
    destination=base/'restored';restored=base/'restore.json'
    capture_hash=restore.digest(capture)
    try:assert restore.restore(capture,destination,restored,capture_hash)
    except ValueError as error:raise AssertionError(restored.with_suffix('.tar.stderr').read_text()) from error
    root=destination/'zigbee2mqtt';admission=base/'admission.json';settings=base/'zigbee.json'
    settings.write_text(json.dumps(cfg))
    tasks=yaml.safe_load((SOURCE/'ansible/tasks/compose.yml').read_text()) + yaml.safe_load((SOURCE/'ansible/tasks/zigbee-admission.yml').read_text())
    tasks=[copy.deepcopy(t) for t in tasks if t['name'] in {
        'Require the explicit start step and retired old writers',
        'Check first-start admission or preserve the admitted live Zigbee identity'}]
    tasks=[t for i,t in enumerate(tasks) if t['name'].startswith('Require the explicit') or i==len(tasks)-1]
    assert len(tasks)==2 and tasks[0]['name'].startswith('Require the explicit')
    replacements={'/opt/homelab-app/zigbee2mqtt.py':str(SOURCE/'zigbee2mqtt.py'),
        '/opt/homelab-app/zigbee.json':str(settings),'/srv/homelab/data/zigbee2mqtt':str(root),
        '/opt/homelab-app/zigbee-admission.json':str(admission),'/opt/homelab-app/restore.json':str(restored)}
    for task in tasks:
        if 'ansible.builtin.command' in task:
            command=task['ansible.builtin.command']['argv']
            for old,new in replacements.items():command=command.replace(old,new)
            task['ansible.builtin.command']['argv']=command
    playbook=base/'playbook.json';playbook.write_text(json.dumps([{
        'hosts':'all','connection':'local','gather_facts':False,'tasks':tasks}]))
    variables=base/'variables.json'
    def run(start,writer=True,passes=True,approval=None,ordinary=False):
        app={'kind':'zigbee2mqtt','start_services':start,'exclusive_writer_confirmed':writer,
             'zigbee_first_start_approval':approval or {}}
        if ordinary:app['zigbee_admission']={'capture_sha256':capture_hash,'selection_sha256':__import__('zigbee2mqtt').fingerprint(cfg)}
        else:app['capture']={'sha256':capture_hash}
        variables.write_text(json.dumps({'app':app,'ordinary_reconcile':ordinary}))
        result=subprocess.run(['ansible-playbook','-i','localhost,',str(playbook),
            '--extra-vars','@'+str(variables)],capture_output=True,text=True,timeout=40)
        if (result.returncode==0)!=passes:raise AssertionError(result.stdout+result.stderr)
    run(False);assert not admission.exists()
    run(True,False,False);assert not admission.exists()
    (root/'database.db').write_bytes(b'altered before first start')
    run(True,passes=False);assert not admission.exists()
    (root/'database.db').write_bytes(files['database.db'])
    run(True,passes=False);assert not admission.exists()
    approved=approval_for(cfg,capture_hash,restored)
    run(True,approval=approved)
    sealed=admission.read_bytes()
    (root/'database.db').write_bytes(b'legitimate live database')
    (root/'coordinator_backup.json').write_bytes(b'{"counter":2}')
    value=yaml.safe_load(files['configuration.yaml']);value['friendly_name']='live setting'
    (root/'configuration.yaml').write_text(yaml.safe_dump(value))
    live={p.name:p.read_bytes() for p in root.iterdir()}
    assert not restore.restore(capture,destination,restored,capture_hash)
    run(True);run(True,ordinary=True)
    assert live=={p.name:p.read_bytes() for p in root.iterdir()}
    assert admission.read_bytes()==sealed
    value['advanced']['pan_id']=4321;(root/'configuration.yaml').write_text(yaml.safe_dump(value))
    run(True,passes=False)
    print('Radio first-start tasks: exclusive-writer gate, exact initial hashes, private admission, mutable live repeat, restore no-replay and identity-drift refusal passed')

# Exercise the separately owned ordinary preflight through the same CI fixture entry.
subprocess.run([sys.executable,str(SOURCE/'tests/zigbee_ordinary_fixture.py')],check=True)
