"""Obtain a scoped Proxmox API token and CA through pinned SSH, saving privately."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from urllib.parse import urlparse

from bootstrap import HERE, Refused, read, sha, write
from native import workspace_lock


def upload_template(work, parent_ssh):
    """Transfer the verified cached archive over pinned SSH and retain its receipt."""
    request = read(work / 'template.json')
    source = work / 'template.archive'
    if source.is_symlink() or sha(source) != request['sha256'] or source.stat().st_size != request['size_bytes']:
        raise Refused('Private cached template changed; no transfer attempted')
    remote = 'python3 -c ' + shlex.quote((HERE / 'host_template.py').read_text()) + ' ' + shlex.quote(json.dumps(request))
    out_path, err_path = work / 'template.stdout', work / 'template.stderr'
    try:
        with source.open('rb') as archive, \
                os.fdopen(os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out, \
                os.fdopen(os.open(err_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as err:
            proc = subprocess.run(parent_ssh + [remote], stdin=archive, stdout=out, stderr=err, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        write(work / 'template-result.json', {'status': 'UNKNOWN', 'error_type': type(exc).__name__, 'automatic_retry': False})
        raise Refused('Template transfer not confirmed; preserve private partial receipts, no retry') from exc
    try:
        result = json.loads(out_path.read_text().strip().splitlines()[-1])
    except (ValueError, IndexError):
        result = {'status': 'held'}
    write(work / 'template-result.json', {'returncode': proc.returncode, **result})
    if proc.returncode or result.get('status') != 'stored' or any(result.get(k) != request[k] for k in ('file_id', 'sha256', 'size_bytes')):
        raise Refused('Template transfer failed readback; preserve receipts before another action')


def setup(work, expires_in):
    """Reuse valid saved access or request one scoped token without replaying failures."""
    with workspace_lock(work):
        if (work / 'access.json').exists():
            saved = read(work / 'access.json')
            if (saved.get('status') != 'ready' or not (work / 'pve-ca.pem').is_file()
                    or (saved['expires_at'] and saved['expires_at'] <= time.time())):
                raise Refused('Saved access is incomplete or expired; preserve it before another credential action')
            return {'status': 'ready', 'token_id': saved['token_id'], 'expires_at': saved['expires_at'], 'changed': False}
        values = read(work / 'tofu/site.auto.tfvars.json')
        if values.get('template') is not None:
            raise Refused('Use a cached template over pinned SSH; API template downloads are outside this MVP')
        guest = values['deploy']
        endpoint = urlparse(values['site']['api_endpoint'])
        if endpoint.scheme != 'https' or endpoint.port != 8006 or not endpoint.hostname or endpoint.username or endpoint.password:
            raise Refused('Use the host HTTPS API endpoint on port 8006')
        for name in ('bootstrap-key', 'known_hosts'):
            if not (Path('/keys') / name).is_file():
                raise Refused('Supply the ISO SSH key and verified known-hosts file')
        request = {'node': values['site']['node'], 'vmid': guest['vmid'],
                   'storage_id': guest['storage_id'], 'bridge': guest['bridge'],
                   'vlan': guest.get('vlan'),
                   'template_storage': guest['template_file_id'].split(':', 1)[0],
                   'download_template': False, 'expires_in': expires_in}
        marker = work / 'access-attempt.json'
        try:
            with marker.open('x') as stream:
                stream.write(json.dumps({'request': request, 'automatic_retry': False}) + '\n')
            marker.chmod(0o600)
        except FileExistsError:
            raise Refused('Access setup already attempted; preserve its private receipts before another action') from None
        remote = 'python3 -c ' + shlex.quote((HERE / 'host_access.py').read_text()) + ' ' + shlex.quote(json.dumps(request))
        parent_ssh = ['ssh', '-i', '/keys/bootstrap-key', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/keys/known_hosts',
                '-o', 'ConnectTimeout=10', 'root@' + endpoint.hostname]
        if (work / 'template.json').exists():
            upload_template(work, parent_ssh)
        args = parent_ssh + [remote]
        try:
            with os.fdopen(os.open(work / 'access.stdout', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out, \
                    os.fdopen(os.open(work / 'access.stderr', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as err:
                proc = subprocess.run(args, stdout=out, stderr=err, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            write(work / 'access-result.json', {'status': 'UNKNOWN', 'error_type': type(exc).__name__, 'automatic_retry': False})
            raise Refused('Access setup not confirmed; retain private stdout/stderr, no automatic retry') from exc
        try:
            result = json.loads((work / 'access.stdout').read_text().strip().splitlines()[-1])
        except (ValueError, IndexError):
            result = {'status': 'held'}
        if proc.returncode or result.get('status') != 'ready':
            write(work / 'access-result.json', {'status': 'held', 'returncode': proc.returncode, 'automatic_retry': False})
            raise Refused('Access setup failed; preserve the private partial credential receipt, no automatic retry')
        ca = result.pop('ca_pem')
        (work / 'pve-ca.pem').write_text(ca)
        (work / 'pve-ca.pem').chmod(0o600)
        write(work / 'access.json', result)
        summary = {k: result[k] for k in ('status', 'token_id', 'expires_at', 'grants')}
        write(work / 'access-result.json', summary)
        return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--expires-in', type=int, default=21600)
    args = parser.parse_args()
    try:
        print(json.dumps(setup(args.work.resolve(), args.expires_in)))
    except (Refused, OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc) if isinstance(exc, Refused) else 'Access setup failed; inspect private receipts without retrying')
