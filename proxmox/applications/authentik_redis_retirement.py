"""Retire the single proved pre-2025.10 Redis container during a retained upgrade."""
import json
from pathlib import Path
import re
import stat
import subprocess
import sys


def require(value):
    if not value:
        raise ValueError('Cannot verify the retained Authentik Redis container')


def docker(*args):
    return subprocess.run(['docker', *args], timeout=90, check=True, capture_output=True,
                          text=True).stdout.strip()


def retire(selection, compose):
    project = selection['project']
    names = selection['services']
    require(len(names) == 2 and len(set(names)) == 2 and selection['lifecycle'] == 'retained')
    allowed = set(names + selection['peers'])
    listing = docker('ps', '--all', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project,
                     '--format', '{{.ID}} {{.Label "com.docker.compose.service"}}')
    extra = []
    seen = set()
    for line in listing.splitlines():
        container, service = line.split()
        require(re.fullmatch('[0-9a-f]{64}', container) and service not in seen)
        seen.add(service)
        if service not in allowed:
            extra.append((container, service))
    if not extra:
        return False
    require(selection['previously_owned'] and len(extra) == 1 and set(names) <= seen)
    container, redis = extra[0]
    require(re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', redis))
    info = compose.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_size <= 1024 * 1024)
    previous = json.loads(compose.read_bytes())
    require(previous['name'] == project and set(previous['services']) == allowed | {redis})
    services = previous['services']
    for name, role in zip(names, ('server', 'worker'), strict=True):
        require(services[name]['command'] == role
                and services[name]['environment']['AUTHENTIK_REDIS__HOST'] == redis
                and services[name]['depends_on'] == {redis:{'condition':'service_healthy'}})
    require(all(redis not in services[peer].get('depends_on', {}) for peer in selection['peers']))
    old = services[redis]
    require(re.fullmatch(r'(?:docker\.io/(?:library/)?)?redis(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}', old['image'])
            and old['command'] == ['--save', '60', '1', '--loglevel', 'warning'] and not old.get('ports')
            and len(old['volumes']) == 1 and isinstance(old['volumes'][0], str))
    source, target = old['volumes'][0].split(':')
    require(Path(source).is_absolute() and target == '/data')
    digest = docker('compose', '-f', str(compose), 'config', '--hash', redis).split()
    require(len(digest) == 2 and digest[0] == redis and re.fullmatch('[0-9a-f]{64}', digest[1]))
    fields = '[{{json .Config.Image}},{{json .Config.Labels}},{{json .Mounts}}]'
    image, labels, mounts = json.loads(docker('inspect', '--type=container', '--format', fields, container))
    require(image == old['image'] and labels.get('com.docker.compose.project') == project
            and labels.get('com.docker.compose.service') == redis
            and labels.get('com.docker.compose.config-hash') == digest[1]
            and len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == source
            and mounts[0]['Destination'] == '/data' and mounts[0]['RW'] is True)
    docker('stop', '--time', '60', container)
    docker('rm', container)
    return True


def main():
    require(len(sys.argv) == 2)
    compose = Path(sys.argv[1])
    require(compose.parent == Path('/opt/homelab-app') and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}\.ya?ml', compose.name))
    print(json.dumps({'changed': retire(json.load(sys.stdin), compose)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('Retained Redis retirement refused')
