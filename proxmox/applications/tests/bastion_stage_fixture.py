"""Execute actual Ansible bastion Stage twice; no systemd/sysctl activation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bastion


def main():
    if not Path('/.dockerenv').exists() or os.geteuid()!=0:
        raise ValueError('Run only in a disposable root test container')
    with tempfile.TemporaryDirectory(prefix='bastion-stage-') as tmp:
        root=Path(tmp)
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'client')],check=True)
        key=(root/'client.pub').read_text().split()
        (root/'public').write_text(' '.join(key[:2])+'\n')
        policy={'entry_address':'198.18.15.15','management_address':'198.18.25.15',
                'runner_source':'198.18.25.11/32','maintenance':[],
                'roles':[{'name':'tunnelstage','uid':2001,'gid':2001,'sources':['198.18.10.2/32'],
                          'public_key_file':str(root/'public'),'permit_open':['198.18.25.10:8006']}]}
        source=Path(__file__).resolve().parents[1]
        directory=root/'ansible';directory.mkdir()
        (root/'bastion.py').symlink_to(source/'bastion.py')
        play=directory/'site.yml'
        play.write_text(json.dumps([{'hosts':'all','connection':'local','gather_facts':False,
                    'tasks':[{'ansible.builtin.import_tasks':str(source/'ansible/tasks/bastion.yml')}]}]))
        variables=root/'variables.json'
        variables.write_text(json.dumps({'network_ready_interfaces':['eth0','eth1'], 'app':{
            'kind':'bastion','address':'198.18.25.15','start_services':False,
            'bastion':policy,'bastion_files':bastion.render(policy)}}))
        Path('/opt/homelab-app').mkdir(exist_ok=True)
        original=Path('/etc/ssh/sshd_config').read_bytes()
        # Mock only the two read-only service queries in this staging test.
        # Activation is disabled; no systemd result is claimed.
        stub=Path('/usr/local/bin/systemctl')
        stub.write_text('#!/bin/sh\nif [ "$1" = is-active ] && [ "$2" = ssh.socket ]; then exit 3; fi\nif [ "$1" = show ]; then echo "/usr/sbin/sshd -D"; exit 0; fi\nexit 99\n')
        stub.chmod(0o755)
        command=['ansible-playbook','-i','localhost,',str(play),'--extra-vars','@'+str(variables)]
        for attempt in range(2):
            result=subprocess.run(command,capture_output=True,text=True,timeout=60)
            if result.returncode:raise AssertionError(result.stdout+result.stderr)
            if attempt and 'changed=0' not in result.stdout:raise AssertionError(result.stdout)
        if Path('/etc/ssh/sshd_config').read_bytes()!=original:
            raise AssertionError('Stage changed the active SSH policy')
        receipt=json.loads(Path('/etc/homelab-bastion-accounts.json').read_text())
        bastion.account_preflight(policy,receipt)
        if Path('/etc/ssh/bastion-keys/tunnelstage').read_text()!=bastion.public_key(root/'public'):
            raise AssertionError('Selected public key differs')
        if 'Requires=homelab-network-ready.service' not in Path('/etc/systemd/system/ssh.service.d/homelab-network-ready.conf').read_text():
            raise AssertionError('Missing service gate')
        # Refuse account drift before touching the candidate configuration.
        subprocess.run(['usermod','--shell','/bin/sh','tunnelstage'],check=True)
        candidate=Path('/opt/homelab-app/bastion-sshd.conf').read_bytes()
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        if result.returncode==0 or Path('/opt/homelab-app/bastion-sshd.conf').read_bytes()!=candidate:
            raise AssertionError('Account drift was not held before candidate writes')
        print('Actual bastion Ansible Stage passed, repeat changed=0, active SSH preserved, account drift held; activation untested')


if __name__=='__main__':main()
