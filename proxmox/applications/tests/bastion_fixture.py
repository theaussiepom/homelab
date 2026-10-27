#!/usr/bin/env python3
"""Real disposable OpenSSH fixture. Run only inside the isolated test container."""
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bastion


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=kwargs.pop('timeout', 10), **kwargs)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'allowed synthetic endpoint\n')


def main():
    if not Path('/.dockerenv').exists() or os.geteuid() != 0:
        raise ValueError('Run only inside the disposable root test container')
    print(run([sys.executable, str(Path(__file__).with_name('bastion_stage_fixture.py'))], timeout=180).stdout.strip())
    with tempfile.TemporaryDirectory(prefix='bastion-') as tmp:
        root=Path(tmp)
        for name in ('host','client','wrong-host'):
            run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/name)])
        public=(root/'client.pub').read_text().split()
        (root/'tunneladmin.pub').write_text(' '.join(public[:2])+'\n')
        policy={'entry_address':'198.18.15.15','management_address':'198.18.25.15',
                'runner_source':'198.18.25.11/32','maintenance':[],
                'roles':[{'name':'tunneladmin','uid':2000,'gid':2000,'sources':['198.18.10.2/32'],
                          'public_key_file':str(root/'tunneladmin.pub'),
                          'permit_open':['198.18.25.10:18080']}]}
        bastion.account_preflight(policy)
        run(['groupadd','--gid','2000','tunneladmin'])
        run(['useradd','--uid','2000','--gid','2000','--no-create-home','--home-dir','/nonexistent',
             '--shell','/usr/sbin/nologin','tunneladmin'])
        receipt=[{'name':'tunneladmin','uid':2000,'gid':2000}]
        bastion.account_preflight(policy,receipt)
        files=bastion.render(policy)
        Path('/etc/ssh/bastion-keys').mkdir(exist_ok=True)
        Path('/etc/ssh/bastion-keys/tunneladmin').write_text(files['keys']['tunneladmin'])
        # Root here is disposable fixture root. Its existing key path models the
        # runner key already placed by OpenTofu, not a new deployment credential.
        Path('/root/.ssh').mkdir(mode=0o700,exist_ok=True)
        Path('/root/.ssh/authorized_keys').write_text(files['keys']['tunneladmin'])
        os.chmod('/root/.ssh/authorized_keys',0o600)
        Path('/run/sshd').mkdir(exist_ok=True)
        config=files['sshd_config'].replace('198.18.15.15','127.0.0.2').replace('198.18.25.15','127.0.0.3')
        config=config.replace('198.18.25.11/32','127.0.0.1/32').replace('198.18.10.2/32','127.0.0.1/32')
        config=config.replace('198.18.25.10:18080','127.0.0.1:18080')
        config=config.replace('HostKey /etc/ssh/ssh_host_ed25519_key','HostKey '+str(root/'host'))
        path=root/'sshd_config';path.write_text(config)
        run(['/usr/sbin/sshd','-t','-f',str(path)])
        # Effective configuration must retain both user and listener boundaries.
        for user,address in [('tunneladmin','127.0.0.2'),('root','127.0.0.3'),('tunneladmin','127.0.0.3')]:
            result=run(['/usr/sbin/sshd','-T','-f',str(path),'-C',f'user={user},addr=127.0.0.1,laddr={address},lport=22,host=client.invalid']).stdout
            if address=='127.0.0.3':
                assert 'allowusers root@127.0.0.1/32' in result
                assert 'allowtcpforwarding no' in result
            else:
                for line in ('maxsessions 0','allowtcpforwarding local','permitlisten none',
                             'allowagentforwarding no','allowstreamlocalforwarding no',
                             'permitopen 127.0.0.1:18080','forcecommand /usr/sbin/nologin'):
                    assert line in result.splitlines(),line
        host=' '.join((root/'host.pub').read_text().split()[:2])
        hosts=root/'known_hosts';hosts.write_text('127.0.0.2 '+host+'\n127.0.0.3 '+host+'\n')
        wrong=root/'wrong_known_hosts';wrong.write_text('127.0.0.2 '+' '.join((root/'wrong-host.pub').read_text().split()[:2])+'\n')
        command=['ssh','-F','/dev/null','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                 '-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
                 '-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+str(hosts),
                 '-o','ConnectTimeout=3','-i',str(root/'client')]
        log=(root/'sshd.log').open('w+')
        server=socketserver.ThreadingTCPServer(('127.0.0.1',18080),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        daemon=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(path)],stdout=log,stderr=log)
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.2',22),timeout=.1):break
                except OSError:time.sleep(.05)
            positive=run(command+['-W','127.0.0.1:18080','tunneladmin@127.0.0.2'],input='')
            assert 'allowed synthetic endpoint' in positive.stdout
            positive=run(command+['root@127.0.0.3','printf preserved-runner'])
            assert positive.stdout=='preserved-runner'
            for args in [['-W','127.0.0.1:18081','tunneladmin@127.0.0.2'],
                         ['tunneladmin@127.0.0.2','id'],
                         ['-tt','tunneladmin@127.0.0.2','id'],
                         ['-s','tunneladmin@127.0.0.2','sftp'],
                         ['root@127.0.0.2','true'],
                         ['tunneladmin@127.0.0.3','true'],
                         ['-b','127.0.0.4','-W','127.0.0.1:18080','tunneladmin@127.0.0.2'],
                         ['-N','-o','ExitOnForwardFailure=yes','-R','127.0.0.1:18082:127.0.0.1:18080','tunneladmin@127.0.0.2']]:
                result=subprocess.run(command+args,check=False,capture_output=True,text=True,input='',timeout=5)
                assert result.returncode!=0, args
            wrong_command = [value.replace(str(hosts), str(wrong)) for value in command]
            result = subprocess.run(wrong_command + ['-W','127.0.0.1:18080','tunneladmin@127.0.0.2'], check=False,capture_output=True,text=True,input='',timeout=5)
            assert result.returncode != 0 and 'Host key verification failed' in result.stderr
            print(json.dumps({'status':'passed','openssh':run(['ssh','-V']).stderr.strip(),
                              'allowed':['exact local tunnel','existing runner management SSH'],
                              'denied':['wrong destination','command','PTY','SFTP','entry root','management tunneladmin',
                                        'wrong source','remote forwarding','wrong host key'],
                              'effective':['agent disabled','streamlocal disabled','exact Match/PermitOpen']}))
        finally:
            daemon.terminate();daemon.wait(timeout=5)
            server.shutdown();server.server_close();log.close()


if __name__=='__main__':main()
