"""One-time Mac setup: separate Proxmox CD token and main-only GitHub environment."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from urllib.parse import urlsplit

from bootstrap_cd import API, require, save

ENVIRONMENT = 'homelab-bootstrap'


def github(repo, path, method='GET', payload=None):
    args = ['gh', 'api', '--hostname', 'github.com', '--method', method, 'repos/' + repo + path]
    if payload is not None:
        args += ['--input', '-']
    proc = subprocess.run(args, input=None if payload is None else json.dumps(payload),
                          capture_output=True, text=True, timeout=30,
                          env=dict(os.environ, GH_DEBUG=''))
    require(proc.returncode == 0, 'GitHub environment setup failed; preserve this attempt')
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def environment(repo):
    metadata = github(repo, '')
    require(metadata['private'] and metadata['permissions']['admin'], 'Use a private repository with administration access')
    envs = github(repo, '/environments?per_page=100')
    require(envs['total_count'] <= 100, 'Environment inventory exceeds this bounded setup')
    existing = [e for e in envs['environments'] if e['name'] == ENVIRONMENT]
    if not existing:
        github(repo, '/environments/' + ENVIRONMENT, 'PUT', {
            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}})
        github(repo, '/environments/' + ENVIRONMENT + '/deployment-branch-policies', 'POST', {'name': 'main', 'type': 'branch'})
    value = github(repo, '/environments/' + ENVIRONMENT)
    require(value.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True},
            'The existing bootstrap environment must already use custom branch restrictions')
    policies = github(repo, '/environments/' + ENVIRONMENT + '/deployment-branch-policies')
    require(policies['total_count'] == 1 and policies['branch_policies'][0]['name'] == 'main'
            and policies['branch_policies'][0].get('type') == 'branch', 'The bootstrap secret must be restricted to main')
    return value


def setup(bundle, out):
    os.umask(0o077)
    settings = json.loads((bundle / 'settings.json').read_text())
    site = json.loads((bundle / 'tofu/site.auto.tfvars.json').read_text())['site']
    repo = settings['repository']
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', repo), 'Use an owner/repository name')
    endpoint = urlsplit(site['api_endpoint'])
    require(endpoint.scheme == 'https' and endpoint.port == 8006 and endpoint.hostname
            and not endpoint.username and not endpoint.password, 'Use the saved HTTPS endpoint')
    # Verify a completed setup without rotating or republishing its credential.
    if out.exists():
        require(out.is_dir() and not out.is_symlink() and (out / 'result.json').is_file(),
                'A previous incomplete setup needs review; do not rerun it')
        saved = json.loads((out / 'result.json').read_text())
        require(saved['status'] == 'ready' and saved['repository'] == repo
                and saved['endpoint'] == site['api_endpoint'], 'Saved CD setup identity differs')
        token = (out / 'token').read_text().strip()
        api = API(site['api_endpoint'], token, bundle / 'pve-ca.pem')
        metadata = api.call('/access/users/root@pam/token/homelab-bootstrap-cd-900')['data']
        require(metadata.get('expire') == 0 and metadata.get('privsep') == 1, 'Saved bootstrap token metadata differs')
        return {**saved, 'changed': False}
    key = Path(os.environ['HOMELAB_SSH_KEY']).resolve(strict=True)
    hosts = Path(os.environ['HOMELAB_KNOWN_HOSTS']).resolve(strict=True)
    require(key.is_file() and hosts.is_file(), 'Supply existing operator SSH key and verified host keys')
    out.mkdir(mode=0o700)
    save(out / 'attempt.json', {'repository': repo, 'endpoint': site['api_endpoint'], 'automatic_retry': False})
    environment(repo)
    source = Path(__file__).with_name('host_cd_access.py').read_text()
    remote = 'python3 -c ' + shlex.quote(source) + ' ' + shlex.quote(json.dumps({'node': site['node'], 'verify': False}))
    args = ['ssh', '-F', '/dev/null', '-i', str(key), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(hosts),
            '-o', 'ConnectTimeout=8', 'root@' + endpoint.hostname, remote]
    with (out / 'credential.stdout').open('x') as stdout, (out / 'credential.stderr').open('x') as stderr:
        proc = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=120)
    lines = [json.loads(line) for line in (out / 'credential.stdout').read_text().splitlines()]
    require(proc.returncode == 0 and len(lines) == 2 and lines[0]['status'] == 'credential_created_acl_pending'
            and lines[1]['status'] == 'ready', 'Credential setup did not finish; preserve partial receipts')
    token = lines[0]['token']
    (out / 'token').write_text(token + '\n')
    (out / 'token').chmod(0o600)
    api = API(site['api_endpoint'], token, bundle / 'pve-ca.pem')
    require(site['node'] in {r['node'] for r in api.call('/nodes')['data']}, 'API credential node check failed')
    proc = subprocess.run(['gh', 'secret', 'set', 'PROXMOX_BOOTSTRAP_TOKEN', '--env', ENVIRONMENT,
                           '--repo', repo], input=token, text=True, capture_output=True, timeout=30,
                          env=dict(os.environ, GH_DEBUG=''))
    require(proc.returncode == 0, 'GitHub secret upload failed; preserve the saved credential without retrying')
    result = {'status': 'ready', 'repository': repo, 'endpoint': site['api_endpoint'],
              'token_id': lines[1]['token_id'], 'environment': ENVIRONMENT,
              'allowed_branch': 'main', 'expires_at': 0, 'bitwarden_save': 'pending',
              'guest_or_network_changes': False}
    save(out / 'result.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(setup(args.bundle.resolve(strict=True), args.out.resolve())))
    except Exception:
        raise SystemExit('Bootstrap CD credential setup stopped. Inspect private receipts; do not automatically retry.') from None
