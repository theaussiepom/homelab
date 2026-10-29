"""Verify steady-state PegaProx availability without replaying installation or startup."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import deploy
import foundation_cd as files

FIELDS = {'schema', 'vmid', 'completion_sha256', 'container_id', 'image_id',
          'compose_sha256', 'restart_policy'}


def validate(policy, cfg):
    """Bind one existing guest and its accepted runtime, with explicit ongoing policy."""
    files.require(set(policy) == FIELDS and policy['schema'] == 'homelab-pegaprox-availability-v1'
        and type(policy['vmid']) is int and policy['vmid'] >= 100
        and policy['vmid'] == cfg['guest']['vmid'] == cfg['app']['vmid']
        and cfg['app']['kind'] == 'pegaprox' and cfg['guest']['started'] is True
        and cfg['guest']['start_on_boot'] is True and policy['restart_policy'] == 'unless-stopped',
        'Select the admitted existing PegaProx guest with ongoing startup policy')
    files.require(all(isinstance(policy[k], str) and re.fullmatch('[0-9a-f]{64}', policy[k])
        for k in ('completion_sha256', 'container_id', 'compose_sha256'))
        and isinstance(policy['image_id'], str) and re.fullmatch('sha256:[0-9a-f]{64}', policy['image_id']),
        'Bind the original completion and exact existing container, image and Compose')


def check(policy, cfg, host, status, runtime):
    """Reject unavailable runtime or policy drift without changing the guest or account."""
    validate(policy, cfg)
    files.require(host.get('hostname') == cfg['guest']['hostname']
        and host.get('protection') == 1 and host.get('unprivileged') == 1
        and host.get('onboot') == 1 and not host.get('lock') and status.get('status') == 'running',
        'PegaProx must retain the protected existing guest, running with autostart enabled')
    expected_mounts = sorted([
        ['/srv/homelab/data/pegaprox/config', '/app/config', True],
        ['/srv/homelab/data/pegaprox/logs', '/app/logs', True],
        ['/opt/homelab-app/runtime/pegaprox-db-key', '/run/secrets/pegaprox-db-key', False],
    ])
    files.require(runtime.get('id') == policy['container_id']
        and runtime.get('image_id') == policy['image_id'] and runtime.get('running') is True
        and runtime.get('restart_policy') == {'Name': 'unless-stopped', 'MaximumRetryCount': 0}
        and runtime.get('compose_sha256') == policy['compose_sha256']
        and runtime.get('docker_enabled') is True and runtime.get('mounts') == expected_mounts,
        'PegaProx must retain its running container, image, mounts and accepted startup policy')
    return {'status': 'passed', 'vmid': policy['vmid'], 'guest_autostart': True,
            'container_restart': 'unless-stopped', 'changed': False}


def verify(policy, cfg):
    """Read admitted custody, native policy and pinned guest SSH; perform no mutations."""
    validate(policy, cfg)
    work = Path(cfg['paths']['state_root']) / str(policy['vmid'])
    completion = files.regular(work / 'pegaprox-complete.json', private=True)
    files.require(hashlib.sha256(completion).hexdigest() == policy['completion_sha256']
        and json.loads(completion).get('status') == 'passed',
        'Preserve the original completed PegaProx installation receipt')
    # guest_trust can establish a missing receipt during installation; this read-only path cannot.
    trust = work / 'ssh-trust.json'
    files.require(trust.is_file() and not trust.is_symlink(),
                  'Require the original SSH trust binding; no availability-time adoption')
    files.regular(trust, private=True)
    base = '/nodes/' + cfg['site']['node'] + '/lxc/' + str(policy['vmid'])
    host, status = deploy.api_get(cfg, base + '/config'), deploy.api_get(cfg, base + '/status/current')
    files.require(host.get('hostname') == cfg['guest']['hostname'] and host.get('onboot') == 1
        and status.get('status') == 'running', 'Require the accepted running guest before SSH')
    deploy.guest_trust(cfg, work)
    code = '''import hashlib,json,pathlib,subprocess
c=json.loads(subprocess.check_output(['docker','inspect',CONTAINER],timeout=10))[0]
p=pathlib.Path('/opt/homelab-app/compose.yml')
enabled=subprocess.run(['systemctl','is-enabled','--quiet','docker'],capture_output=True,timeout=10).returncode==0
print(json.dumps({'id':c['Id'],'image_id':c['Image'],'running':c['State']['Running'],
 'restart_policy':c['HostConfig']['RestartPolicy'],'compose_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
 'docker_enabled':enabled,'mounts':sorted([[m['Source'],m['Destination'],m['RW']] for m in c['Mounts'] if m['Type']=='bind'])}))
'''.replace('CONTAINER', repr(policy['container_id']))
    options = ['-F', '/dev/null', '-i', cfg['paths']['private_key'], '-o', 'IdentitiesOnly=yes',
        '-o', 'ForwardAgent=no', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' + cfg['paths']['known_hosts'], '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no', '-o', 'ControlMaster=no',
        '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1']
    result = subprocess.run(['ssh', '-T', *options, 'root@' + cfg['app']['address'], 'python3 -B -'],
        input=code, text=True, capture_output=True, timeout=35)
    files.require(result.returncode == 0 and len(result.stdout) <= 8192,
                  'Read-only PegaProx availability inspection did not complete')
    return check(policy, cfg, host, status, json.loads(result.stdout))


def main():
    """Check ongoing availability separately from the frozen installation inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--deployment', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(json.loads(args.policy.read_text()),
            json.loads(args.deployment.read_text())['site_config'])))
    except Exception:
        raise SystemExit('PegaProx availability verification failed; preserve runtime and evidence. No automatic start, recreation or account setup.') from None


if __name__ == '__main__':
    main()
