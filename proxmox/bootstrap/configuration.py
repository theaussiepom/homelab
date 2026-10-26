"""Configure a new or completed bootstrap without recreating its guest or state."""
import argparse
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import shlex
import subprocess
import tempfile
from urllib.parse import urlparse

from bootstrap import HERE, Refused, read, write
from native import workspace_lock
import host_access
import host_nas


REMOTE = '''import hashlib,json,sys,types
p=json.loads(sys.argv[1])
for name,code in p['modules'].items():
 m=types.ModuleType(name);sys.modules[name]=m;exec(compile(code,name,'exec'),m.__dict__)
a=sys.modules['host_access'];n=sys.modules['host_nas'];r=p['request']
marker='/var/lib/homelab-bootstrap/CONFIGURING'
if p.get('finish'):
 code="import json,sys;from pathlib import Path;p=Path(sys.argv[1]);assert json.loads(p.read_text())['attempt']==sys.argv[2];p.unlink()"
 n.command(['pct','exec',str(r['vmid']),'--','python3','-c',code,marker,p['attempt']])
 print(json.dumps({'status':'ready'}));sys.exit(0)
access=a.reconcile(r)
c=a.command(['pvesh','get','/nodes/'+r['node']+'/lxc/'+str(r['vmid'])+'/config','--output-format','json'])
c['node']=r['node']
nas=n.plan(r['nas'],c)
plan={'access':access,'nas':nas,'restart_deploy':r['restart_deploy'],'identity':{'node':r['node'],'vmid':r['vmid'],'mac':r['guest_mac']}}
fingerprint=hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest()
if p['apply']:
 if p['apply']!=fingerprint:raise RuntimeError('Live configuration changed after its reviewed plan')
 code="import json,sys;from pathlib import Path;p=Path(sys.argv[1]);f=p.open('x');f.write(json.dumps({'attempt':sys.argv[2]}));f.close();p.chmod(0o600)"
 n.command(['pct','exec',str(r['vmid']),'--','python3','-c',code,marker,p['attempt']])
 access=a.reconcile(r,apply=True)
 print(json.dumps({'step':'access','result':access}),flush=True)
 nas=n.ensure(r['nas'],r['vmid'],c,restart=r['restart_deploy'])
 print(json.dumps({'step':'nas','result':nas}),flush=True)
key=n.command(['pct','exec',str(r['vmid']),'--','cat','/etc/ssh/ssh_host_ed25519_key.pub']).strip()
addresses=n.command(['pct','exec',str(r['vmid']),'--','hostname','-I']).split()
print(json.dumps({'status':'ready','plan':plan,'plan_sha256':fingerprint,'guest_host_key':key,'addresses':addresses,'access':access,'nas':nas}),flush=True)
'''


def check(value):
    """Keep the bootstrap update contract small and reject undeclared operations."""
    fields = {'schema', 'applications', 'nas', 'restart_deploy'}
    if set(value) not in (fields, fields | {'expires_at'}) or value['schema'] != 'homelab-bootstrap-deployment-v1':
        raise Refused('Use the documented bootstrap deployment configuration')
    if type(value['restart_deploy']) is not bool:
        raise Refused('Select deployment-guest restart explicitly')
    host_nas.validate(value['nas'])


def remote(work, request, apply='', finish=False, attempt=''):
    """Use only the existing pinned operator SSH route; never copy its key."""
    for name in ('bootstrap-key', 'known_hosts'):
        if not (Path('/keys') / name).is_file():
            raise Refused('Supply the existing bootstrap SSH key and verified host keys')
    endpoint = urlparse(read(work / 'tofu/site.auto.tfvars.json')['site']['api_endpoint'])
    if endpoint.scheme != 'https' or endpoint.port != 8006 or not endpoint.hostname:
        raise Refused('Use the trusted Proxmox API endpoint')
    payload = {'modules': {name: (HERE / (name + '.py')).read_text()
                           for name in ['host_access', 'host_nas']},
               'request': request, 'apply': apply, 'finish': finish, 'attempt': attempt}
    command = ['ssh', '-F', '/dev/null', '-i', '/keys/bootstrap-key',
               '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/keys/known_hosts',
               '-o', 'ConnectTimeout=10', 'root@' + endpoint.hostname,
               'python3 -c ' + shlex.quote(REMOTE) + ' ' + shlex.quote(json.dumps(payload))]
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    return result


def configure(work, deployment, apply=''):
    """Plan by default; apply once, retaining a hold on any partial operation."""
    value = read(deployment); check(value)
    with workspace_lock(work, backup=True):
        values, saved = read(work / 'tofu/site.auto.tfvars.json'), read(work / 'access.json')
        guest = values['deploy']
        expected = {k: saved[k] for k in ['status', 'token_id', 'expires_at', 'grants']}
        request = {'node': values['site']['node'], 'vmid': guest['vmid'],
                   'storage_id': guest['storage_id'], 'template_storage': guest['template_file_id'].split(':', 1)[0],
                   'bridge': guest['bridge'], 'vlan': guest.get('vlan'), 'guest_mac': guest['mac'],
                   'expected': expected, 'applications': value['applications'], 'nas': value['nas'],
                   'restart_deploy': value['restart_deploy']}
        if 'expires_at' in value:
            request['expires_at'] = value['expires_at']
        host_access.declared_grants(request)
        source_hash = hashlib.sha256(b''.join((HERE / f).read_bytes() for f in
            ['configuration.py', 'host_access.py', 'host_nas.py', 'ansible/configure-deploy.yml',
             'templates/module/main.tf', 'bootstrap.py', 'native.py'])).hexdigest()
        configuration_hash = hashlib.sha256(deployment.read_bytes()).hexdigest()
        plan_path = work / 'configuration-plan.json'
        if apply:
            if (work / 'CONFIGURATION-HOLD.json').exists():
                raise Refused('Previous configuration failed; preserve its hold and inspect it before a corrected attempt')
            old = read(plan_path)
            if (old['plan_sha256'] != apply or old['source_sha256'] != source_hash
                    or old['configuration_sha256'] != configuration_hash):
                raise Refused('Use the exact reviewed configuration plan; source or inputs changed')
        attempt = Path(tempfile.mkdtemp(prefix='configure-', dir=work))
        write(attempt / 'request.json', request)
        if apply:
            write(work / 'CONFIGURATION-HOLD.json', {'attempt': str(attempt), 'status': 'started', 'automatic_retry': False})
            write(attempt / 'access-before.json', saved)
        try:
            try:
                result = remote(work, request, apply, attempt=attempt.name)
                stdout, stderr = result.stdout, result.stderr
            except subprocess.TimeoutExpired as error:
                result = None
                stdout = error.stdout or ''
                stderr = error.stderr or ''
            stdout = stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout
            stderr = stderr.decode(errors='replace') if isinstance(stderr, bytes) else stderr
            for name, text in [('stdout', stdout), ('stderr', stderr)]:
                path = attempt / name; path.write_text(text); path.chmod(0o600)
            lines = stdout.strip().splitlines()
            if apply:
                for line in lines:
                    try:
                        step = json.loads(line)
                    except ValueError:
                        continue  # A timeout may leave an incomplete final line.
                    if step.get('step') == 'access':
                        access = step['result']
                        if access.get('status') != 'ready' or access.get('token_id') != saved['token_id']:
                            raise Refused('Partial access receipt does not match this deployment token')
                        saved.update({k: access[k] for k in ['grants', 'expires_at']})
                        write(work / 'access.json', saved)
            if result is None:
                if apply:
                    write(work / 'CONFIGURATION-HOLD.json', {'attempt': str(attempt), 'status': 'UNKNOWN',
                        'remote_closure': 'unconfirmed', 'automatic_retry': False})
                raise Refused('Remote configuration timed out; preserve its unknown outcome and inspect ' + str(attempt))
            report = json.loads(lines[-1]) if lines else {}
            if result.returncode or report.get('status') != 'ready':
                raise Refused('Bootstrap configuration did not complete; inspect ' + str(attempt))
            if not apply:
                write(plan_path, {**report, 'source_sha256': source_hash,
                                 'configuration_sha256': configuration_hash})
                return {'phase': 'plan', 'plan_sha256': report['plan_sha256'],
                        'access': report['plan']['access'], 'nas': report['plan']['nas'],
                        'restart_deploy': value['restart_deploy']}
            saved.update({k: report['access'][k] for k in ['grants', 'expires_at']})
            write(work / 'access.json', saved)
            addresses = report['addresses']
            address = guest['ipv4'].split('/')[0]
            if address == 'dhcp':
                usable = [x for x in addresses if ipaddress.ip_address(x).version == 4
                          and not ipaddress.ip_address(x).is_loopback
                          and not ipaddress.ip_address(x).is_link_local]
                if len(usable) != 1:
                    raise Refused('The deployment guest needs exactly one usable management IPv4 address')
                address = usable[0]
            if address not in addresses:
                raise Refused('The deployment guest does not have its expected address')
            key = report['guest_host_key'].split()
            if len(key) < 2 or key[0] != 'ssh-ed25519':
                raise Refused('The trusted Proxmox route returned no valid deployment host key')
            known = attempt / 'known_hosts'; known.write_text(address + ' ' + ' '.join(key[:2]) + '\n'); known.chmod(0o600)
            inventory = {'all': {'hosts': {'deploy': {'ansible_host': address, 'ansible_user': 'root',
                'ansible_ssh_private_key_file': '/keys/bootstrap-key',
                'ansible_ssh_common_args': '-F /dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(known)}}}}
            write(attempt / 'inventory.json', inventory)
            variables = {'bootstrap_source': str(HERE), 'deployment_repository': read(work / 'settings.json')['repository'],
                'deployment_runner': read(work / 'settings.json')['runner_name'],
                'configuration_attempt': attempt.name,
                'deployment_mac': guest['mac'], 'bootstrap_api_token': saved['PROXMOX_VE_API_TOKEN'],
                'bootstrap_ca': str(work / 'pve-ca.pem'), 'nas_source': report['nas']['backup_source']}
            write(attempt / 'variables.json', variables)
            with (attempt / 'ansible.log').open('w') as log:
                os.chmod(attempt / 'ansible.log', 0o600)
                subprocess.run(['ansible-playbook', '-i', str(attempt / 'inventory.json'),
                    str(HERE / 'ansible/configure-deploy.yml'), '-e', '@' + str(attempt / 'variables.json')],
                    stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
            finished = remote(work, request, finish=True, attempt=attempt.name)
            if finished.returncode or json.loads(finished.stdout).get('status') != 'ready':
                raise Refused('Configuration completed but its maintenance marker remains; preserve the hold')
            receipt = {'status': 'configured', 'plan_sha256': apply, 'guest': guest['vmid'],
                       'source_sha256': source_hash, 'configuration_sha256': configuration_hash,
                       'changed': report['access']['changed'] or report['nas']['changed']}
            write(work / 'configuration-result.json', receipt)
            (work / 'CONFIGURATION-HOLD.json').unlink()
            return receipt
        except BaseException:
            # A local exit/timeout cannot prove that a remote operation was closed.
            # Keep the pre-command hold, partial stdout and private old credentials.
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--apply', default='')
    args = parser.parse_args()
    try:
        if platform.system() != 'Linux' or Path('/etc/pve').exists():
            raise Refused('Run configuration through the Linux Docker bootstrap launcher')
        print(json.dumps(configure(args.work.resolve(), args.deployment.resolve(), args.apply)))
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc) if isinstance(exc, Refused) else 'Configuration held; inspect its private attempt and logs')
