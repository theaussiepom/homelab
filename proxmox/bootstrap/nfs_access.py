"""Bootstrap a separate forced-command NFS key and deliver it to main-only Secrets."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from bootstrap import HERE, ROOT, Refused
import cd_access


def setup(repository, environments, host, runner, out):
    os.umask(0o077)
    if (not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+',repository)
            or not environments or len(set(environments)) != len(environments)
            or not all(re.fullmatch(r'[A-Za-z0-9_-]{1,100}',name) for name in environments)):
        raise Refused('Select the private repository and explicit existing protected environments')
    for address in (host,runner):
        ipaddress.IPv4Address(address)
    key = Path(os.environ['HOMELAB_SSH_KEY']).resolve(strict=True)
    known = Path(os.environ['HOMELAB_KNOWN_HOSTS']).resolve(strict=True)
    if out.exists() or out.is_symlink() or out.resolve().is_relative_to(ROOT):
        raise Refused('Use a new private attempt outside source')
    for name in environments:
        cd_access.environment(repository,create=False,name=name)
    out.mkdir(mode=0o700,parents=True)
    inventory = {'all':{'children':{name:{'hosts':{name:{'ansible_host':address,'ansible_user':'root',
        'ansible_ssh_private_key_file':'/keys/bootstrap-key',
        'ansible_ssh_common_args':'-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o ControlMaster=no -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile=/keys/known_hosts'}}}
        for name,address in (('pve',host),('deploy',runner))}}}
    (out/'inventory.json').write_text(json.dumps(inventory))
    with tempfile.TemporaryDirectory(prefix='homelab-nfs-secret-') as private:
        args = ['docker','run','--rm','--platform','linux/amd64','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--user',str(os.getuid())+':'+str(os.getgid()),'--tmpfs','/tmp:rw,exec,nosuid,nodev,size=768m,mode=1777',
            '-e','HOME=/tmp','-e','ANSIBLE_LOCAL_TEMP=/tmp/ansible-local','-e','ANSIBLE_REMOTE_TEMP=/tmp/ansible-remote',
            '-v',str(HERE)+':/src/proxmox/bootstrap:ro','-v',str(ROOT/'proxmox/applications/nfs_host_helper.py')+':/src/proxmox/applications/nfs_host_helper.py:ro',
            '-v',str(out)+':/evidence','-v',private+':/secret-transport',
            '-v',str(key)+':/keys/bootstrap-key:ro','-v',str(known)+':/keys/known_hosts:ro',
            'homelab-bootstrap-test:1','ansible-playbook','-i','/evidence/inventory.json',
            '/src/proxmox/bootstrap/ansible/host-nfs.yml','-e',
            json.dumps({'nfs_helper_source':'/src/proxmox/applications/nfs_host_helper.py',
                        'nfs_evidence':'/evidence','nfs_secret_transport':'/secret-transport'})]
        with (out/'bootstrap.log').open('x') as log:
            result = subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=300,check=False)
        if result.returncode:
            raise Refused('NFS capability bootstrap failed; preserve its private attempt')
        transport = Path(private)/'key'
        info = transport.lstat()
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600):
            raise Refused('Preserve unexpected private key transport custody')
        raw = transport.read_bytes()
        if not raw.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----\n') or len(raw) > 8192:
            raise Refused('The dedicated private key transport differs')
        for name in environments:
            cd_access.environment(repository,create=False,name=name)
            result = subprocess.run(['gh','secret','set','PROXMOX_NFS_SSH_KEY','--repo',repository,'--env',name],
                input=raw,capture_output=True,timeout=30,check=False,env=dict(os.environ,GH_DEBUG=''))
            if result.returncode:
                raise Refused('NFS secret delivery failed; preserve the installed capability without retrying')
            saved = cd_access.github(repository,'/environments/'+name+'/secrets/PROXMOX_NFS_SSH_KEY')
            if not isinstance(saved,dict) or saved.get('name') != 'PROXMOX_NFS_SSH_KEY':
                raise Refused('NFS secret metadata readback differs')
    result = {'status':'ready','environments':environments,'key_rotated':False,'guest_mounts_changed':False}
    (out/'result.json').write_text(json.dumps(result)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository','host','runner'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--environment',action='append',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(setup(args.repository,args.environment,args.host,args.runner,args.out.resolve())))
        return 0
    except Exception:
        print('NFS bootstrap held; inspect its private attempt without replaying')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
