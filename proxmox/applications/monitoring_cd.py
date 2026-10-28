"""Small CD adapter over the existing guest installer and shared Ansible tasks.

The private proposal stays disabled until its native input files and saved plan
are reviewed. This adapter does not create a second guest/state implementation.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time

import deploy
from foundation_cd import regular, private_directory, write_new, encoded, sync

PHASES = {'bootstrap': 'monitoring-bootstrap.yml', 'database': 'monitoring-database.yml',
          'configure': 'monitoring-configure.yml', 'agents': 'monitoring-agents.yml'}


def file_references(value):
    """Bind file-backed secrets/packages/trust referenced by the Ansible input."""
    result = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str) and key.endswith('_file'):
                if not Path(child).is_absolute():
                    raise ValueError('Native monitoring file references must be absolute')
                result.add(child)
            result.update(file_references(child))
    elif isinstance(value, list):
        for child in value:
            result.update(file_references(child))
    return result


def run(packet, phase):
    if packet.get('enabled') is not True:
        return {'status': 'disabled', 'production_changed': False}
    if packet.get('schema') != 'homelab-monitoring-cd-v1':
        raise ValueError('Use the reviewed monitoring CD packet')
    if phase not in set(PHASES) | {'server', 'verify'}:
        raise ValueError('Select a fixed monitoring CD phase')
    # Every input, including package/PSK/trust files and the inventories, must be
    # present with its exact reviewed digest before any native phase begins.
    for name, expected in packet['input_sha256'].items():
        if not Path(name).is_absolute() or deploy.sha(name) != expected:
            raise ValueError('Monitoring input drift; preserve the packet for review')
    required = {packet['site_file'], packet['inventory'], packet['variables'], packet['known_hosts'], packet['ssh_key']}
    if not required <= set(packet['input_sha256']):
        raise ValueError('Bind the site, inventory, variables, host trust and SSH key')
    cfg = json.loads(regular(Path(packet['site_file']), private=True))
    vmid = deploy.validate(cfg)
    if cfg['app']['kind'] != 'monitoring':
        raise ValueError('This adapter accepts only the clean monitoring guest')
    variables = json.loads(regular(Path(packet['variables']), private=True))
    required.update(deploy.input_hashes(cfg))
    required.update(file_references(variables))
    if 'access' in packet:
        required.update(packet['access'][key] for key in ('config', 'token', 'ca'))
    if not required <= set(packet['input_sha256']):
        raise ValueError('Bind all referenced monitoring secrets, packages and trust files')
    if variables.get('ansible_httpapi_use_ssl', True) is not True or variables.get('ansible_httpapi_validate_certs', True) is not True:
        raise ValueError('Native monitoring API configuration requires trusted HTTPS')
    work = Path(cfg['paths']['state_root']) / str(vmid)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(work)
    binding = hashlib.sha256(encoded(packet)).hexdigest()
    with (work / 'monitoring.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        hold = work / 'MONITORING-HOLD.json'
        receipt = work / ('monitoring-' + phase + '.json')
        if hold.exists() or any((work / marker).exists() for marker in ('HOLD.json', 'ROLLOUT-HOLD.json', 'CONTINUATION-HOLD.json')):
            raise ValueError('Monitoring attempt is held; no automatic replay')
        done = receipt.exists()
        if done and json.loads(regular(receipt, private=True))['packet_sha256'] != binding:
            raise ValueError('Commissioned monitoring packet changed; review a maintenance packet')
        # Completed write phases are never replayed. The final read-only phase
        # remains responsible for fresh metrics and browser-facing HTTPS checks.
        if done and phase != 'verify':
            return {'status': 'completed', 'phase': phase, 'replayed': False}
        for dependency in {'database': ['bootstrap'], 'server': ['bootstrap', 'database'],
                           'configure': ['server'], 'agents': ['configure'],
                           'verify': ['agents']}.get(phase, []):
            previous = work / ('monitoring-' + dependency + '.json')
            if not previous.exists() or json.loads(regular(previous, private=True))['packet_sha256'] != binding:
                raise ValueError('Complete the matching monitoring dependency through CD first')
        deploy.backup(cfg, work / 'terraform.tfstate', 'before-monitoring-' + phase)
        write_new(hold, encoded({'phase': phase, 'packet_sha256': binding, 'automatic_retry': False}))
        # Persist the hold on the existing NAS recovery boundary before writes.
        evidence = Path(cfg['paths']['backup_directory']) / str(vmid) / ('monitoring-' + str(time.time_ns()))
        evidence.mkdir(mode=0o700)
        write_new(evidence / 'HOLD.json', regular(hold, private=True))
        environment = dict(os.environ, ANSIBLE_CONFIG=str(deploy.SOURCE / 'ansible/ansible.cfg'),
            ANSIBLE_HOST_KEY_CHECKING='True', ANSIBLE_SSH_ARGS='-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no -o IdentitiesOnly=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=' + shlex.quote(packet['known_hosts']))
        logfile = work / (str(time.time_ns()) + '-monitoring-' + phase + '.log')
        if phase == 'bootstrap':
            sys.path.insert(0, str(deploy.SOURCE.parent / 'bootstrap'))
            from bootstrap_cd import API
            import monitoring_access
            access = packet['access']
            access_cfg = json.loads(regular(Path(access['config'])))
            api = API(access_cfg['endpoint'], regular(Path(access['token']), private=True).decode().strip(), Path(access['ca']))
            monitoring_access.initialize(api, access_cfg, Path(access['state']), Path(access['backup']))
        if phase in PHASES:
            deploy.quiet(['ansible-playbook', '-i', packet['inventory'], '--private-key', packet['ssh_key'],
                          str(deploy.SOURCE / 'ansible' / PHASES[phase]), '-e', '@' + packet['variables']], environment, logfile)
        elif phase == 'server':
            deploy.execute('deploy', Path(packet['site_file']), packet['plan_sha256'])
        else:
            deploy.quiet(['ansible-playbook', '-i', packet['inventory'], str(deploy.SOURCE / 'ansible/monitoring-verify.yml'),
                          '-e', '@' + packet['variables']], environment, logfile)
        deploy.backup(cfg, work / 'terraform.tfstate', 'after-monitoring-' + phase)
        result = {'status': 'passed', 'phase': phase, 'packet_sha256': binding}
        if not done:
            write_new(receipt, encoded(result))
        write_new(evidence / 'complete.json', encoded(result))
        (evidence / 'HOLD.json').unlink(); sync(evidence)
        hold.unlink(); sync(work)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=[*PHASES, 'server', 'verify'])
    args = parser.parse_args()
    try:
        print(json.dumps(run(json.loads(args.packet.read_text()), args.phase)))
    except Exception:
        raise SystemExit('Monitoring CD stopped. Retain its private evidence and holds; no automatic retry.') from None
