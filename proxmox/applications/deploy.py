#!/usr/bin/env python3
"""One guest per CD run. Preview, apply the saved plan, stage, then explicitly start."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from plan import check_plan

SOURCE = Path(__file__).resolve().parent


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def source_hash():
    result = hashlib.sha256()
    for path in sorted(SOURCE.rglob('*')):
        if path.is_file() and not any(p in {'.terraform', '__pycache__', '.work'} for p in path.parts):
            result.update(str(path.relative_to(SOURCE)).encode())
            result.update(bytes.fromhex(sha(path)))
    return result.hexdigest()


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def validate(cfg):
    vmid = cfg['guest']['vmid']
    if isinstance(vmid, bool) or not isinstance(vmid, int) or vmid < 100 or vmid in {900, 4914, 4915, 4920}:
        raise ValueError('Select one application guest, never the deployment controller or protected targets')
    app = cfg['app']
    if app['vmid'] != vmid or app['hostname'] != cfg['guest']['hostname'] or app['memory_mib'] != cfg['guest']['memory_mib']:
        raise ValueError('OpenTofu and Ansible must select the same guest and resource budget')
    if not any(nic['ipv4'].split('/')[0] == app['address'] and nic['mac'].lower() == app['mac'].lower() for nic in cfg['guest']['interfaces']):
        raise ValueError('Ansible must use a selected guest interface')
    if app.get('new_target') is not True:
        raise ValueError('This installer is for a selected new guest')
    for key in ('state_root', 'backup_mount', 'backup_directory', 'api_token', 'ca_file', 'private_key', 'known_hosts'):
        if not Path(cfg['paths'][key]).is_absolute():
            raise ValueError(f'{key} must be an absolute private runner path')
    backup = Path(cfg['paths']['backup_directory']).resolve()
    mount = Path(cfg['paths']['backup_mount']).resolve()
    if mount == backup or mount not in backup.parents:
        raise ValueError('State recovery copies must be below the declared NAS mount')
    if not cfg['site']['api_endpoint'].startswith('https://'):
        raise ValueError('Use the trusted TLS API endpoint')
    return vmid


def quiet(command, environment, log, cwd=None):
    with log.open('ab') as output:
        os.chmod(log, 0o600)
        subprocess.run(command, env=environment, cwd=cwd, stdout=output, stderr=output, check=True)


def backup(cfg, state, label):
    mount = Path(cfg['paths']['backup_mount']).resolve()
    if not os.path.ismount(mount):
        raise ValueError('The declared NAS recovery mount is unavailable; no local fallback')
    actual = subprocess.check_output(['findmnt', '-rn', '-o', 'FSTYPE', '--target', str(mount)], text=True).strip()
    if actual not in {'nfs', 'nfs4', 'cifs'}:
        raise ValueError('The recovery mount must be the selected NAS filesystem')
    destination = Path(cfg['paths']['backup_directory']) / str(cfg['guest']['vmid'])
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    # A write/read receipt also proves the mount is writable before initial creation.
    stamp = f'{time.time_ns()}-{label}'
    if state.exists():
        target = destination / f'{stamp}.tfstate'
        with state.open('rb') as src, target.open('xb') as dst:
            os.chmod(target, 0o600)
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if sha(target) != sha(state):
            raise ValueError('State backup readback differs')
        write(destination / f'{stamp}.json', {'sha256': sha(target), 'file': target.name})
    else:
        write(destination / f'{stamp}.json', {'state': 'not-created', 'vmid': cfg['guest']['vmid']})


def execute(action, cfg_path, approved_plan=None):
    os.umask(0o077)
    cfg = json.loads(cfg_path.read_text())
    vmid = validate(cfg)
    work = Path(cfg['paths']['state_root']) / str(vmid)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (work / 'deployment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (work / 'HOLD.json').exists():
            raise ValueError('A failed mutation is held for review; preserve its state and logs')
        state = work / 'terraform.tfstate'
        backup(cfg, state, 'before-' + action)
        environment = os.environ.copy()
        environment.update({'TF_IN_AUTOMATION': '1', 'CHECKPOINT_DISABLE': '1',
                            'SSL_CERT_FILE': cfg['paths']['ca_file'],
                            'PROXMOX_VE_API_TOKEN': Path(cfg['paths']['api_token']).read_text().strip()})
        tofu = ['tofu', '-chdir=' + str(work / 'tofu')]
        logfile = work / f'{time.time_ns()}-{action}.log'
        if action == 'plan':
            shutil.copytree(SOURCE / 'tofu', work / 'tofu', dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', '*.tfplan'))
            write(work / 'tofu' / 'site.auto.tfvars.json', {k: cfg[k] for k in ('site', 'guest', 'ssh_public_keys')})
            quiet(tofu + ['init', '-input=false', '-lockfile=readonly', '-backend-config=path=' + str(state)], environment, logfile)
            quiet(tofu + ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(work / 'guest.tfplan')], environment, logfile)
            output = subprocess.check_output(tofu + ['show', '-json', str(work / 'guest.tfplan')], env=environment)
            check_plan(json.loads(output), cfg['site']['node'], vmid)
            receipt = {'plan_sha256': sha(work / 'guest.tfplan'), 'site_sha256': sha(cfg_path), 'source_sha256': source_hash(), 'vmid': vmid}
            write(work / 'plan.json', receipt)
            return receipt
        receipt = json.loads((work / 'plan.json').read_text())
        if receipt['site_sha256'] != sha(cfg_path) or receipt['source_sha256'] != source_hash():
            raise ValueError('Source or site inputs changed; review a new plan')
        if action == 'apply':
            if not approved_plan or approved_plan != receipt['plan_sha256'] or approved_plan != sha(work / 'guest.tfplan'):
                raise ValueError('Apply requires the exact reviewed plan SHA256')
        elif action not in {'stage', 'start', 'verify'}:
            raise ValueError('Unknown deployment step')
        try:
            if action == 'apply':
                quiet(tofu + ['apply', '-input=false', '-lock-timeout=30s', str(work / 'guest.tfplan')], environment, logfile)
                write(work / 'applied.json', receipt)
            else:
                if json.loads((work / 'applied.json').read_text()) != receipt:
                    raise ValueError('Apply the selected reviewed plan before configuring its guest')
                app = dict(cfg['app'], start_services=(action == 'start'), render_dir=str(work / 'rendered'))
                write(work / 'variables.json', {'app': app})
                write(work / 'inventory.json', {'application': {'hosts': {app['hostname']: {'ansible_host': app['address'], 'ansible_user': 'root'}}}})
                environment.update({'ANSIBLE_CONFIG': str(SOURCE / 'ansible' / 'ansible.cfg'),
                                    'ANSIBLE_HOST_KEY_CHECKING': 'True',
                                    'ANSIBLE_SSH_ARGS': '-o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no -o UserKnownHostsFile=' + shlex.quote(cfg['paths']['known_hosts'])})
                playbook = 'verify.yml' if action == 'verify' else 'site.yml'
                quiet(['ansible-playbook', '-i', str(work / 'inventory.json'),
                       '--private-key', cfg['paths']['private_key'], str(SOURCE / 'ansible' / playbook),
                       '--extra-vars', '@' + str(work / 'variables.json')], environment, logfile)
            backup(cfg, state, 'after-' + action)
        except (OSError, ValueError, subprocess.CalledProcessError):
            if action != 'verify':
                write(work / 'HOLD.json', {'action': action, 'vmid': vmid, 'log': str(logfile), 'failed_at_ns': time.time_ns()})
            raise
        return {'step': action, 'vmid': vmid, 'status': 'passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'apply', 'stage', 'start', 'verify'])
    parser.add_argument('--site', required=True, type=Path)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.action, args.site, args.plan_sha256)))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        # Logs and inputs can contain secrets; do not emit command output or file contents.
        raise SystemExit(f'Deployment held ({type(error).__name__}); inspect private runner inputs/receipts') from None


if __name__ == '__main__':
    main()
