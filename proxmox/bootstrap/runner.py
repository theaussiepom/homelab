"""Install the private runner in the guest created by this bootstrap."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
from urllib.parse import urlparse

from bootstrap import HERE, Refused, read, write
import native


def allow_host_api(work, parent_ssh, request):
    """One bounded host edit before state handover, through already pinned SSH."""
    try:
        with (work / 'host-firewall-attempt.json').open('x') as stream:
            stream.write(json.dumps({'request': request, 'automatic_retry': False}) + '\n')
        (work / 'host-firewall-attempt.json').chmod(0o600)
    except FileExistsError:
        raise Refused('Host firewall setup was already attempted; preserve its receipt before another action') from None
    script = (HERE / 'host_api.py').read_text()
    remote = 'python3 -c ' + shlex.quote(script) + ' ' + shlex.quote(json.dumps(request))
    try:
        proc = subprocess.run(parent_ssh + [remote], capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        write(work / 'host-firewall-result.json', {'status': 'UNKNOWN', 'error_type': type(exc).__name__,
              'automatic_retry': False})
        raise Refused('Host API allowance was not confirmed; inspect the private receipt, no automatic retry') from exc
    receipt = {'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr,
               'automatic_retry': False, 'status': 'held'}
    try:
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        if proc.returncode == 0 and result.get('status') == 'stored':
            receipt.update(status='stored', result=result)
    except (ValueError, IndexError):
        pass
    write(work / 'host-firewall-result.json', receipt)
    if receipt['status'] != 'stored':
        raise Refused('Host API allowance was not confirmed; preserve the receipt before another action')
    return receipt['result']


def stage_handover(work):
    """Freeze workstation writes before copying and hashing the active state."""
    native.state_file(work)
    with (work / 'HANDOVER.json').open('x') as stream:
        stream.write(json.dumps({'runner_workspace': '/var/lib/homelab-bootstrap',
                                 'workstation_writes_disabled': True}) + '\n')
    (work / 'HANDOVER.json').chmod(0o600)
    receipt = native.copy_workspace(work, work / 'runner-bundle')
    write(work / 'HANDOVER.json', {'runner_workspace': '/var/lib/homelab-bootstrap',
                                  'workstation_writes_disabled': True, **receipt})
    return work / 'runner-bundle', receipt


def install(work):
    """Hold the workspace lock throughout the one-way runner handover."""
    with native.workspace_lock(work):
        return install_locked(work)


def connection_environment():
    """Allow only the scoped Proxmox API token to cross into the runner."""
    if os.environ.get('PROXMOX_VE_USERNAME') or os.environ.get('PROXMOX_VE_PASSWORD'):
        raise Refused('The runner keeps only the scoped API token; unset Proxmox username/password')
    token = os.environ.get('PROXMOX_VE_API_TOKEN')
    if not token:
        raise Refused('Create scoped API access first; the runner needs PROXMOX_VE_API_TOKEN')
    if '\n' in token or '\r' in token or '\x00' in token:
        raise Refused('Connection environment values must be single-line')
    return {'PROXMOX_VE_API_TOKEN': token}


def install_locked(work):
    """Verify the guest and token before installing the runner and transferring state."""
    environment = connection_environment()
    native.run_locked('verify', work)
    values = read(work / 'tofu/site.auto.tfvars.json')
    settings = read(work / 'settings.json')
    guest = values['deploy']; host = urlparse(values['site']['api_endpoint']).hostname
    vmid = int(guest['vmid']); address = guest['ipv4'].split('/')[0]
    if vmid in (4914, 4915, 4920): raise Refused('Protected guest ID')
    for name in ('bootstrap-key', 'known_hosts', 'pve-ca.pem'):
        if not (Path('/keys') / name).is_file(): raise Refused('Supply the SSH key, pinned host keys and PVE CA files')
    # Trust the new guest key through the already pinned PVE management SSH
    # connection, rather than accepting whichever host answers at its IP.
    command = ['ssh', '-i', '/keys/bootstrap-key', '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/keys/known_hosts',
               '-o', 'ConnectTimeout=10', 'root@' + host,
               'pct exec ' + str(vmid) + ' -- cat /etc/ssh/ssh_host_ed25519_key.pub && '
               'pct exec ' + str(vmid) + ' -- hostname -I']
    proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
    write(work / 'parent-guest-key-read.json', {'returncode': proc.returncode,
          'stdout': proc.stdout, 'stderr': proc.stderr,
          'scope': 'Public guest SSH host key and addresses only; no automatic retry'})
    lines = proc.stdout.strip().splitlines()
    key = lines[0].split() if lines else []
    if proc.returncode or len(key) < 2 or key[0] != 'ssh-ed25519':
        raise Refused('Could not read the new guest SSH key through the pinned PVE host; no retry')
    if address == 'dhcp':
        addresses = [ipaddress.ip_address(value) for value in ' '.join(lines[1:]).split()]
        address = next((str(value) for value in addresses if value.version == 4
                        and not value.is_loopback and not value.is_link_local), None)
        if address is None: raise Refused('The guest has no usable IPv4 address yet; inspect it before another attempt')
    known = work / 'guest-known-hosts'
    known.write_text(address + ' ' + ' '.join(key[:2]) + '\n'); known.chmod(0o600)
    inventory = read(work / 'inventory.json')
    inventory['all']['hosts']['deploy']['ansible_host'] = address
    inventory['all']['hosts']['deploy']['ansible_ssh_common_args'] = (
        '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(known))
    write(work / 'inventory.json', inventory)
    allow_host_api(work, command[:-1], {'node': values['site']['node'], 'vmid': vmid,
                   'guest_address': address, 'api_endpoint': values['site']['api_endpoint']})
    bundle, state = stage_handover(work)
    # Only the scoped deployment API token persists in the private guest.
    # The short-lived GitHub registration token and operator SSH key do not.
    environment_file = work / 'runner-environment'
    environment_file.write_text(''.join(name + '=' + json.dumps(value, ensure_ascii=False) + '\n'
                                        for name, value in environment.items()))
    environment_file.chmod(0o600)
    variables = work / 'runner-vars.json'
    write(variables, {'runner_repository': settings['repository'], 'runner_name': settings['runner_name'],
          'runner_owner': 'homelab-runner', 'runner_directory': '/opt/homelab-runner',
          'runner_service_file': '/etc/systemd/system/homelab-deploy.service',
          'runner_env_file': '/etc/homelab-bootstrap.env', 'bootstrap_bundle_source': str(bundle),
          'bootstrap_api_endpoint': values['site']['api_endpoint'],
          'bootstrap_source': str(HERE), 'bootstrap_environment_source': str(environment_file),
          'bootstrap_state_sha256': state['state_sha256'], 'bootstrap_provider_environment': environment})
    log = work / 'runner-install.log'; log.touch(mode=0o600)
    with log.open('w') as stream:
        proc = subprocess.run(['ansible-playbook', '-i', str(work / 'inventory.json'),
            str(HERE / 'ansible/install-runner.yml'), '-e', '@' + str(variables)],
            stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
    if proc.returncode: raise Refused('Runner setup failed; preserve the attempt and inspect the private runner-install.log')
    write(work / 'runner-result.json', {'status': 'installed', 'repository': settings['repository'],
          'github_job_verified': False, 'operator_private_key_copied': False, **state})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    try:
        install(parser.parse_args().work.resolve())
    except (Refused, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc) if isinstance(exc, Refused) else 'Runner setup failed; inspect retained private evidence')
