"""Receive one checksum-pinned template over the existing trusted SSH channel."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys


def node_ready(node):
    return (os.path.ismount('/etc/pve') and Path('/etc/pve/local').resolve() == Path('/etc/pve/nodes/' + node))


def command(args):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if proc.returncode:
        raise RuntimeError('Selected template storage is unavailable: ' + proc.stderr.strip())
    return proc.stdout.strip()


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def store(request, source, execute=command):
    node = request['node']
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', node)
            or socket.gethostname().split('.')[0] != node or not node_ready(node)):
        raise RuntimeError('The selected local Proxmox node must be ready')
    match = re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]*:vztmpl/([A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.(?:zst|gz|xz))', request['file_id'])
    size = request['size_bytes']
    if (not match or type(size) is not int or not 0 < size <= 1024 ** 3
            or not re.fullmatch(r'[a-f0-9]{64}', request['sha256'])):
        raise RuntimeError('Supply one bounded template file and its exact checksum')
    target = Path(execute(['pvesm', 'path', request['file_id']]))
    if not target.is_absolute() or target.name != match.group(1) or target.is_symlink():
        raise RuntimeError('Unexpected template storage path; no write')
    exists = target.exists()
    if exists and (not target.is_file() or target.stat().st_size != size or digest(target) != request['sha256']):
        raise RuntimeError('Existing template differs; it will not be overwritten')
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + '.bootstrap-partial')
    output = None if exists else os.fdopen(os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
    checksum, received = hashlib.sha256(), 0
    try:
        while chunk := source.read(1024 ** 2):
            received += len(chunk)
            if received > size:
                raise RuntimeError('Template stream exceeds its declared size')
            checksum.update(chunk)
            if output is not None:
                output.write(chunk)
        if received != size or checksum.hexdigest() != request['sha256']:
            raise RuntimeError('Template size/checksum mismatch; preserve partial evidence')
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
    finally:
        if output is not None:
            output.close()
    if not exists:
        os.link(partial, target)  # Atomic publication fails rather than overwriting a concurrent file.
        partial.unlink()
    if digest(target) != request['sha256'] or target.stat().st_size != size:
        raise RuntimeError('Published template readback differs; no retry')
    return {'status': 'stored', 'changed': not exists, 'file_id': request['file_id'],
            'size_bytes': size, 'sha256': request['sha256']}


if __name__ == '__main__':
    try:
        print(json.dumps(store(json.loads(sys.argv[1]), sys.stdin.buffer)), flush=True)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'held', 'reason': str(exc), 'automatic_retry': False}), flush=True)
        raise SystemExit(1)
