"""A wrong runner registration must fail before its startup files change.

Run only in the disposable tools container. Facts are synthetic admission inputs;
this exercises real Ansible task ordering, not native identity or service startup.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

assert Path('/.dockerenv').exists() and os.geteuid()==0
registration=Path('/opt/homelab-runner/.runner')
assert not registration.exists(), 'Use a fresh disposable fixture container'
registration.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
registration.write_text(json.dumps({'gitHubUrl':'https://github.com/fixture/wrong','agentName':'wrong-runner'}))
gate=Path('/etc/systemd/system/homelab-network-ready.service')
original=gate.read_bytes()
gate.write_bytes(b'fixture: rejected runner must preserve this file\n')
before=(gate.read_bytes(),gate.stat().st_ino,gate.stat().st_mtime_ns)
with tempfile.TemporaryDirectory() as tmp:
    variables=Path(tmp)/'vars.json'
    variables.write_text(json.dumps({'deployment_mac':'02:00:00:00:09:00',
        'deployment_repository':'fixture/expected','deployment_runner':'expected-runner',
        'ansible_hostname':'deploy','ansible_distribution':'Debian','ansible_virtualization_type':'lxc',
        'ansible_default_ipv4':{'macaddress':'02:00:00:00:09:00'}}))
    play=Path(__file__).resolve().parents[2]/'bootstrap/ansible/configure-deploy.yml'
    result=subprocess.run(['ansible-playbook','-i','deploy,','-c','local',str(play),
        '--tags','network-readiness','--extra-vars','@'+str(variables)],capture_output=True,text=True)
    assert result.returncode!=0, result.stdout+result.stderr
    assert 'Keep the existing runner bound to its intended private repository' in result.stdout, result.stdout+result.stderr
    assert 'Install the shared guest network readiness gate' not in result.stdout
    assert (gate.read_bytes(),gate.stat().st_ino,gate.stat().st_mtime_ns)==before
gate.write_bytes(original)
print('Actual Ansible runner registration rejection preserved startup configuration; no native service was tested')
