"""Update only the declared image in an already running ingress Compose stack.

Called by the reviewed CD maintenance playbook on the selected guest. This never
restores data, edits DNS, replaces credentials, or starts a second service.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

COMPOSE = Path('/opt/homelab-app/compose.yml')
IDENTITY = Path('/etc/homelab-application.json')
STATE = Path('/var/lib/homelab-component-updates')


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size <= 1024 * 1024, 'Expected the private component input')
        content = stream.read(1024 * 1024 + 1)
        require(len(content) <= 1024 * 1024, 'Oversized component input')
        return content


def save(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CommandFailed(RuntimeError):
    """A private subprocess failed; never retain its output in a public message."""


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=180, check=False)
    if result.returncode != 0:
        raise CommandFailed('Component command failed; retain the update hold')
    return result.stdout


def image(value):
    require(isinstance(value, str) and re.fullmatch(r'traefik@sha256:[0-9a-f]{64}', value),
            'Use an immutable official Traefik image')


def candidate(original, before, after):
    image(before); image(after)
    require(before != after, 'Select a different reviewed image')
    value = json.loads(original)
    require(value.get('name') == 'homelab-ingress' and set(value.get('services', {})) == {'traefik'}
            and value['services']['traefik'].get('image') == before,
            'Expected only the installed ingress component and image')
    value['services']['traefik']['image'] = after
    return (json.dumps(value, indent=2) + '\n').encode()


def runtime(expected):
    ids = command(['docker', 'compose', '-f', str(COMPOSE), 'ps', '-q', 'traefik']).decode().split()
    require(len(ids) == 1 and re.fullmatch('[0-9a-f]{12,64}', ids[0]), 'Expected one Traefik container')
    rows = json.loads(command(['docker', 'inspect', '--format', '{{json .}}', ids[0]]))
    require(rows['State']['Running'] is True and rows['Config']['Image'] == expected,
            'The running component image differs')


def run(vmid, before, after, compose_sha256, verify_only=False):
    image(before); image(after)
    require(os.geteuid() == 0 and type(vmid) is int and vmid >= 100
            and vmid not in {900, 4914, 4915, 4920}
            and re.fullmatch('[0-9a-f]{64}', compose_sha256), 'Select the reviewed ingress guest')
    identity = json.loads(read(IDENTITY))
    require(identity.get('vmid') == vmid and identity.get('kind') == 'ingress', 'Wrong installed component identity')
    STATE.mkdir(mode=0o700, exist_ok=True)
    info = STATE.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'Expected the private component evidence directory')
    operation = STATE / after.rsplit(':', 1)[1]
    if verify_only:
        info = operation.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'Expected the original private component operation')
        original = read(operation / 'compose-before.json')
        require(hashlib.sha256(original).hexdigest() == compose_sha256
                and read(operation / 'complete.json') == b'{"status":"passed"}\n'
                and not (operation / 'HOLD.json').exists() and not (operation / 'HOLD.json').is_symlink(),
                'Update completion differs')
        require(read(COMPOSE) == candidate(original, before, after), 'Completed Compose configuration changed')
        runtime(after)
        return {'status': 'passed', 'changed': False}
    # An interrupted/failed attempt cannot be repeated by a later push.
    operation.mkdir(mode=0o700)
    with (operation / 'operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            original = read(COMPOSE)
            require(hashlib.sha256(original).hexdigest() == compose_sha256, 'Installed Compose configuration drifted')
            updated = candidate(original, before, after)
            runtime(before)
            save(operation / 'compose-before.json', original)
            save(operation / 'HOLD.json', b'{"automatic_retry":false}\n')
            staging = COMPOSE.with_name('.image-update-' + after[-12:] + '.json')
            save(staging, updated)
            command(['docker', 'compose', '-f', str(staging), 'config', '--quiet'])
            command(['docker', 'pull', after])
            # Preserve the mounted file inode and metadata; refuse concurrent edits.
            with os.fdopen(os.open(COMPOSE, os.O_RDWR | os.O_NOFOLLOW), 'r+b') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600 and stream.read() == original,
                        'Compose changed before the approved image update')
                stream.seek(0); stream.write(updated); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
            command(['docker', 'compose', '-f', str(COMPOSE), 'up', '-d', '--no-deps', '--pull', 'never', 'traefik'])
            require(read(COMPOSE) == updated, 'Updated Compose readback differs')
            runtime(after)
            save(operation / 'complete.json', b'{"status":"passed"}\n')
            (operation / 'HOLD.json').unlink(); sync(operation)
            staging.unlink(); sync(COMPOSE.parent)
            return {'status': 'passed', 'changed': True}
        except Exception as error:
            # Only our exact, controlled ValueError messages are safe to retain.
            # Parser and subprocess exceptions may carry private input or output.
            reason = str(error) if type(error) is ValueError else None
            try:
                save(operation / 'FAILURE.json', (json.dumps({'error': type(error).__name__, 'reason': reason}) + '\n').encode())
            except OSError:
                pass  # Preserve the original failure even if evidence storage fails.
            raise



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vmid', required=True, type=int)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    parser.add_argument('--compose-sha256', required=True)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.vmid, args.before, args.after, args.compose_sha256, args.verify_only)))
    except Exception:
        raise SystemExit('Component image update held; preserve its private evidence. No automatic retry.') from None
