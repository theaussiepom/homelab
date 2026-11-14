"""Reconcile only an existing deployment token's declared bootstrap permissions."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from bootstrap import Refused, read, write
import host_access


def digest(value):
    """Bind a plan to its source, complete request and observed permission delta."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


@contextmanager
def locked(work):
    """Serialize this permission receipt without unlocking infrastructure state."""
    if work.is_symlink():
        raise Refused('Use a real private access workspace')
    work.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(work / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def request_for(path, work):
    """Use a saved successful receipt on repeats; reject undeclared operations."""
    request = read(path)
    fields = {'node', 'vmid', 'storage_id', 'template_storage', 'bridge', 'vlan',
              'guest_mac', 'applications', 'expected'}
    if set(request) != fields:
        raise Refused('Use only the documented access request fields')
    expected = request['expected']
    if set(expected) != {'status', 'token_id', 'expires_at', 'grants'}:
        raise Refused('Supply only the saved non-secret access receipt')
    identity = {k: request[k] for k in ('node', 'vmid', 'guest_mac')}
    saved = work / 'access.json'
    if saved.exists():
        current = read(saved)
        if current['identity'] != identity or current['access']['token_id'] != expected['token_id']:
            raise Refused('Saved access workspace belongs to another deployment identity')
        if current['access']['expires_at'] != expected['expires_at']:
            raise Refused('This command does not change the token lifetime')
        request['expected'] = current['access']
    host_access.declared_grants(request)
    return request, identity


def remote(host, request, source_sha256, apply):
    """Run the existing ACL writer over pinned SSH; never read a token secret."""
    key = Path(os.environ['HOMELAB_SSH_KEY'])
    hosts = Path(os.environ['HOMELAB_KNOWN_HOSTS'])
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host) or not key.is_file() or not hosts.is_file():
        raise Refused('Supply the selected host, existing SSH key and verified host keys')
    payload = {'request': request, 'source_sha256': source_sha256, 'apply': apply}
    program = (
        "import hashlib,json\nns={'__name__':'bootstrap_host_access'}\n"
        + 'exec(compile(' + repr(Path(host_access.__file__).read_text())
        + ",'<bootstrap-host-access>','exec'),ns)\n"
        + 'payload=json.loads(' + repr(json.dumps(payload)) + ')\n'
        + REMOTE
    )
    args = ['ssh', '-F', '/dev/null', '-i', str(key), '-T', '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile=' + str(hosts),
            '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no',
            '-o', 'ControlMaster=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'ConnectTimeout=8',
            'root@' + host, 'env PYTHONDONTWRITEBYTECODE=1 python3 -']
    result = subprocess.run(args, input=program, capture_output=True, text=True, timeout=210)
    if result.returncode:
        error = Refused('Access reconciliation stopped; preserve its hold and inspect the host')
        error.stdout, error.stderr = result.stdout, result.stderr
        raise error
    return json.loads(result.stdout)


REMOTE = '''request=payload['request']
plan=ns['reconcile'](request)
value={'request':request,'source_sha256':payload['source_sha256'],'access':plan}
fingerprint=hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
if payload['apply'] and payload['apply']!=fingerprint:
 raise RuntimeError('Source, request or live permissions changed after the reviewed plan')
commands=[]
def execute(args):
 commands.append(args)
 return ns['command'](args)
access=ns['reconcile'](request,execute=execute,apply=True) if payload['apply'] else plan
print(json.dumps({'status':'ready','plan_sha256':fingerprint,'access':access,
 'acl_modifications':sum(c[:3]==['pveum','acl','modify'] for c in commands)}))
'''


def reconcile(work, path, host, apply=''):
    """Plan by default, save successful scope, and hold every uncertain apply."""
    with locked(work):
        hold = work / 'ACCESS-HOLD.json'
        if hold.exists():
            raise Refused('Previous access apply is held; inspect it before another attempt')
        request, identity = request_for(path, work)
        source = digest([Path(__file__).read_text(), Path(host_access.__file__).read_text()])
        inputs = {'source_sha256': source, 'request_sha256': digest(request), 'host': host}
        if apply:
            plan = read(work / 'plan.json')
            if plan['inputs'] != inputs or plan['result']['plan_sha256'] != apply:
                raise Refused('Use the exact reviewed plan for unchanged source and inputs')
            attempt = Path(tempfile.mkdtemp(prefix='apply-', dir=work))
            write(hold, {'attempt': attempt.name, 'automatic_retry': False})
            write(attempt / 'request.json', request)
        try:
            result = remote(host, request, source, apply)
        except (OSError, ValueError, Refused, subprocess.TimeoutExpired) as error:
            if apply:
                diagnostics = {name: str(getattr(error, name, '') or '')
                               for name in ('stdout', 'stderr')}
                write(attempt / 'failure.json', {'error_type': type(error).__name__,
                      'automatic_retry': False, **diagnostics})
            raise
        if apply:
            write(attempt / 'result.json', result)
        if result['status'] != 'ready':
            raise Refused('Access readback is incomplete; preserve any apply hold')
        if not apply:
            write(work / 'plan.json', {'inputs': inputs, 'result': result})
        else:
            access = {k: result['access'][k] for k in ('status', 'token_id', 'expires_at', 'grants')}
            if access['token_id'] != request['expected']['token_id'] or access['expires_at'] != request['expected']['expires_at']:
                raise Refused('Applied token identity or lifetime differs; preserve the hold')
            write(work / 'access.json', {'identity': identity, 'access': access})
            hold.unlink()
        return result


def main():
    """Expose a permission-only bootstrap operation with explicit pinned inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--apply', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(reconcile(args.work.absolute(), args.request, args.host, args.apply)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, Refused, subprocess.TimeoutExpired):
        print('Access reconciliation stopped; preserve workspace receipts and any hold. No automatic retry.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
