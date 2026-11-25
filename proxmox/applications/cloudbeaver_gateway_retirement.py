"""Retire the dedicated OAuth gateway using the previous successful deployment proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path('/opt/homelab-app')
MOUNTS = {'oauth2.cfg': '/etc/oauth2-proxy/oauth2.cfg', 'oauth2-alpha.json': '/etc/oauth2-proxy/alpha.json'}


def require(value):
    if not value:
        raise ValueError('CloudBeaver gateway ownership could not be verified')


def docker(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True, timeout=90).stdout.strip()


def verified_file(path, uid, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
                and stat.S_IMODE(info.st_mode) == mode and info.st_size <= 1024 * 1024)
        raw = stream.read(1024 * 1024 + 1)
        require(len(raw) == info.st_size)
        return hashlib.sha256(raw).hexdigest()


def retire(proof, compose):
    project, gateway = proof['project'], proof['gateway']
    require(all(re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', name) for name in (project, gateway)))
    require(compose.parent == ROOT and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}\.ya?ml', compose.name))
    runtime = Path(proof['runtime'])
    require(re.fullmatch(re.escape(str(ROOT)) + '/runtime(?:/[a-z0-9_-]+)*', str(runtime))
            and runtime.resolve(strict=True) == runtime)
    directory = ROOT
    for part in ('', *runtime.relative_to(ROOT).parts):
        directory = directory / part
        info = directory.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022)
    require(proof['files'].keys() == MOUNTS.keys() and re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', proof['image']))
    compose_hash = verified_file(compose, 0, 0o600)
    require(compose_hash in (proof['previous_compose_sha256'], proof['next_compose_sha256']))
    container = docker('ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project,
                       '--filter', 'label=com.docker.compose.service=' + gateway)
    if container:
        require(re.fullmatch('[0-9a-f]{64}', container) and compose_hash == proof['previous_compose_sha256'])
        fields = '[{{json .Config.Image}},{{json .Config.Labels}},{{json .Mounts}}]'
        image, labels, mounts = json.loads(docker('inspect', '--type=container', '--format', fields, container))
        require(image == proof['image'] and labels.get('com.docker.compose.project') == project
                and labels.get('com.docker.compose.service') == gateway and len(mounts) == len(MOUNTS))
        require(all(m['Type'] == 'bind' and m['RW'] is False for m in mounts)
                and {m['Source']: m['Destination'] for m in mounts} ==
                    {str(runtime / name): dest for name, dest in MOUNTS.items()})
    remaining = []
    for name, expected in proof['files'].items():
        path = runtime / name
        try:
            actual = verified_file(path, 65532, 0o400)
        except FileNotFoundError:
            require(not container)
            continue
        require(actual == expected)
        remaining.append(path)
    if container:
        docker('stop', '--time', '60', container)
        docker('rm', container)
    for path in remaining:
        path.unlink()
    return bool(container or remaining)


if __name__ == '__main__':
    try:
        print(json.dumps({'changed': retire(json.load(sys.stdin), Path(sys.argv[1]))}))
    except Exception:
        sys.exit('CloudBeaver gateway retirement refused')
