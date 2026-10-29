"""Run actual external-restore preconditions; never extract data or start services."""
import hashlib,json
from pathlib import Path
import subprocess,tempfile
import yaml
SOURCE=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temporary:
 base=Path(temporary);receipt=base/'restore.json';playbook=base/'playbook.json';vars_file=base/'vars.json'
 source=yaml.safe_load((SOURCE/'ansible/site.yml').read_text())[0]['tasks']
 guard=next(i for i,t in enumerate(source) if t.get('ansible.builtin.import_tasks')=='tasks/zigbee-staged.yml')
 packages=next(i for i,t in enumerate(source) if t.get('ansible.builtin.import_tasks')=='tasks/packages.yml');assert guard<packages
 restore=next(t for t in source if t.get('ansible.builtin.import_tasks')=='tasks/restore.yml');assert 'zigbee2mqtt' not in restore['when']
 tasks=json.loads(json.dumps(yaml.safe_load((SOURCE/'ansible/tasks/zigbee-staged.yml').read_text())).replace('/opt/homelab-app/restore.json',str(receipt)))
 playbook.write_text(json.dumps([{'hosts':'all','connection':'local','gather_facts':False,'tasks':tasks}]))
 def run(passes=True,digest=None):
  value={'app':{'capture':{'sha256':'1'*64},'zigbee_first_start_approval':{'approved':True,'restore_receipt_sha256':digest or (hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt.exists() else '2'*64)}}};vars_file.write_text(json.dumps(value))
  p=subprocess.run(['ansible-playbook','-i','localhost,',str(playbook),'--extra-vars','@'+str(vars_file)],capture_output=True,text=True,timeout=30)
  assert (p.returncode==0)==passes,p.stdout+p.stderr
 run(False)
 receipt.write_text(json.dumps({'state':'complete','sha256':'1'*64,'destination':'/srv/homelab/data'}));receipt.chmod(0o600);before=receipt.read_bytes();run();run(False,'0'*64);assert receipt.read_bytes()==before
 receipt.chmod(0o644);run(False);receipt.chmod(0o600)
 receipt.write_text(json.dumps({'state':'complete','sha256':'1'*64,'destination':'/elsewhere'}));run(False)
 assert not (base/'data').exists()
 print('Radio external staging: absent receipt, checksum/mode/destination drift refused; valid private receipt passed without extraction or repair')
