"""Plan or apply additive Proxmox personal SSH access through pinned bootstrap SSH."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'applications'))
import component_control
import component_ssh
import host_ssh
from bootstrap import Refused, read, write
from reconcile_access import locked, digest


def remote(host, request, source, apply, modules):
    key, known = Path(os.environ['HOMELAB_SSH_KEY']), Path(os.environ['HOMELAB_KNOWN_HOSTS'])
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]*', host) or not key.is_file() or not known.is_file():
        raise Refused('Select the existing SSH identity, verified host keys and host')
    program = 'import base64,sys,types,json\n'
    for name, code in modules:
        program += (f"m=types.ModuleType('{name}')\n"
                    f"exec(compile(base64.b64decode('{code}'),'<bootstrap-public-ssh>','exec'),m.__dict__)\n"
                    f"sys.modules['{name}']=m\n")
    program += f"print(json.dumps(m.run({request!r},{source!r},{apply!r})))\n"
    args = ['ssh', '-F', '/dev/null', '-T', '-i', str(key), '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile='+str(known),
            '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no', '-o', 'ControlMaster=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'ConnectTimeout=8',
            'root@'+host, 'env PYTHONDONTWRITEBYTECODE=1 python3 -']
    result = subprocess.run(args, input=program, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise Refused('Proxmox SSH preparation stopped; preserve the local attempt')
    return json.loads(result.stdout)


def run(work, path, host, apply=''):
    request = read(path)
    host_ssh.request(request)
    modules = tuple((module.__name__, base64.b64encode(Path(module.__file__).read_bytes()).decode())
                    for module in (component_control, component_ssh, host_ssh))
    source = digest([Path(__file__).read_text(), modules])
    inputs = {'source_sha256': source, 'request_sha256': digest(request), 'host': host}
    with locked(work):
        failed = work/'SSH-UNKNOWN.json'
        if failed.exists() or failed.is_symlink():
            raise Refused('Inspect the unconfirmed SSH apply before any further write')
        attempt = None
        if apply:
            plan = read(work/'plan.json')
            if plan['inputs'] != inputs or plan['result']['plan_sha256'] != apply:
                raise Refused('Use the exact plan for unchanged source, request and host')
            attempt = Path(tempfile.mkdtemp(prefix='apply-', dir=work))
            write(failed, {'attempt': attempt.name, 'automatic_retry': False})
        result = remote(host, request, source, apply, modules)
        if attempt:
            write(attempt/'result.json', result)
        if (result.get('status') != 'ready' or result.get('node') != request['node']
                or result.get('applied') != bool(apply) or result.get('preserved_existing_bytes') is not True
                or apply and result.get('plan_sha256') != apply):
            raise Refused('SSH readback does not match the selected node and operation')
        if apply:
            failed.unlink()
        else:
            write(work/'plan.json', {'inputs': inputs, 'result': result})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--apply', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.work.absolute(), args.request, args.host, args.apply)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, Refused, subprocess.TimeoutExpired):
        print('Proxmox personal SSH stopped; inspect local receipts before another write.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
