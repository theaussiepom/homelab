"""Bounded managed-file capture/restore used inside protected Ansible recovery.

Input paths are selected by the controller's verified component descriptors.
No directory recursion, application-data capture, shell or database command is
provided. Capture output is private and must never be written to public logs.
The protected caller holds the existing guest deployment lock. Out-of-band
root writers are not serialized by the final comparison and atomic rename.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import uuid

MAX_BYTES = 512 * 1024


def require(ok):
    if not ok:
        raise ValueError('Managed configuration recovery verification failed')


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def parent(path):
    require(isinstance(path, str) and path.startswith('/') and len(path) <= 4096
            and str(PurePosixPath(path)) == path and '..' not in path.split('/')
            and len(PurePosixPath(path).parts) >= 3)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in PurePosixPath(path).parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        yield fd, PurePosixPath(path).name
    finally:
        os.close(fd)


def capture_file(path):
    try:
        with parent(path) as (directory, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_BYTES)
                raw = stream.read(MAX_BYTES + 1)
                after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                          'st_uid', 'st_gid', 'st_mode', 'st_nlink')
                require(len(raw) <= MAX_BYTES and all(
                    getattr(info, key) == getattr(after, key) for key in fields))
        return {'exists': True, 'content': base64.b64encode(raw).decode(),
                'sha256': fingerprint(raw), 'uid': info.st_uid, 'gid': info.st_gid,
                'mode': stat.S_IMODE(info.st_mode)}
    except FileNotFoundError:
        return {'exists': False}


def validate_file(value):
    require(isinstance(value, dict) and type(value.get('exists')) is bool)
    if not value['exists']:
        require(set(value) == {'exists'})
        return None
    require(set(value) == {'exists', 'content', 'sha256', 'uid', 'gid', 'mode'}
            and all(type(value[k]) is int and value[k] >= 0 for k in ('uid', 'gid', 'mode'))
            and value['mode'] <= 0o777 and isinstance(value['content'], str))
    raw = base64.b64decode(value['content'], validate=True)
    require(len(raw) <= MAX_BYTES and fingerprint(raw) == value['sha256'])
    return raw


def validate_metadata(value):
    require(isinstance(value, dict) and set(value) == {'uid', 'gid', 'mode'}
            and all(type(value[key]) is int and value[key] >= 0 for key in value)
            and value['mode'] <= 0o777)


def restore_file(path, value, allowed, *, metadata=None):
    raw = validate_file(value)
    actual = capture_file(path)
    if metadata is not None:
        validate_metadata(metadata)
        require(actual['exists'] and {key: actual[key] for key in metadata} == metadata)
    if actual == value:
        return False
    require(isinstance(allowed, list) and len(allowed) <= 4
            and (not actual['exists'] or actual['sha256'] in allowed))
    with parent(path) as (directory, name):
        if raw is None:
            require(capture_file(path) == actual)
            os.unlink(name, dir_fd=directory)
        else:
            temporary = '.homelab-recovery-' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw); stream.flush()
                    os.fchown(stream.fileno(), value['uid'], value['gid'])
                    os.fchmod(stream.fileno(), value['mode']); os.fsync(stream.fileno())
                require(capture_file(path) == actual)
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        os.fsync(directory)
    require(capture_file(path) == value)
    return True


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout.encode()) <= 65536)
    return result.stdout.strip()


def packages(names):
    require(isinstance(names, list) and len(names) <= 128 and len(names) == len(set(names)))
    result = []
    for selected in names:
        require(isinstance(selected, str) and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?:=[A-Za-z0-9.+:~_-]+)?', selected))
        name = selected.partition('=')[0]
        version = command(['dpkg-query', '--show', '--showformat=${Version}', name])
        require(re.fullmatch(r'[A-Za-z0-9.+:~_-]+', version))
        result.append(name + '=' + version)
    return result


def image_selection(row, *, captured=False):
    require(isinstance(row, dict) and set(row) == {'project', 'service', 'image'} | (
                {'image_id'} if captured or 'image_id' in row else set())
                and all(isinstance(row[k], str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}', row[k])
                        for k in ('project', 'service'))
                and isinstance(row['image'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,511}', row['image'])
                and ('image_id' not in row or isinstance(row['image_id'], str)
                     and re.fullmatch('sha256:[0-9a-f]{64}', row['image_id'])))


def restore_images(rows):
    """Check all retained IDs before retargeting only their owned Compose refs."""
    require(isinstance(rows, list) and len(rows) <= 128)
    refs = {}
    for row in rows:
        image_selection(row, captured=True)
        wanted = row['image_id']
        require(refs.setdefault(row['image'], wanted) == wanted)
        require(command(['docker', 'image', 'inspect', '--format', '{{.Id}}', wanted]) == wanted)
        if '@' in row['image'] or row['image'].startswith('sha256:'):
            require(command(['docker', 'image', 'inspect', '--format', '{{.Id}}', row['image']]) == wanted)
    for ref, wanted in refs.items():
        if '@' not in ref and not ref.startswith('sha256:'):
            command(['docker', 'image', 'tag', wanted, ref])


def images(rows):
    require(isinstance(rows, list) and len(rows) <= 128)
    result = []
    for row in rows:
        image_selection(row)
        ids = command(['docker', 'ps', '--all', '--quiet', '--no-trunc', '--filter',
                       'label=com.docker.compose.project=' + row['project'], '--filter',
                       'label=com.docker.compose.service=' + row['service']])
        require(re.fullmatch('[0-9a-f]{64}', ids))
        actual = command(['docker', 'inspect', '--format', '{{.Image}} {{.State.Running}}', ids])
        image = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', row['image']])
        require(re.fullmatch('sha256:[0-9a-f]{64}', image) and actual == image + ' true'
                and row.get('image_id', image) == image)
        result.append({**row, 'image_id': image})
    return result


def run(value):
    fields = {'mode', 'files', 'packages', 'images', 'allowed'}
    require(isinstance(value, dict) and (set(value) == fields
            or set(value) == fields | {'metadata'} and value['mode'] == 'restore')
            and value['mode'] in ('capture', 'restore', 'verify') and isinstance(value['files'], dict)
            and len(value['files']) <= 256 and isinstance(value['allowed'], dict)
            and set(value['allowed']) <= set(value['files']))
    metadata = value.get('metadata', {})
    require(isinstance(metadata, dict) and set(metadata) <= set(value['files']))
    for expected in metadata.values():
        validate_metadata(expected)
    mode = value['mode']
    if mode == 'capture':
        require(all(row is None for row in value['files'].values()) and not value['allowed'])
        files = {path: capture_file(path) for path in value['files']}
    else:
        require(sum(len(validate_file(row) or b'') for row in value['files'].values()) <= MAX_BYTES)
        if mode == 'restore':
            restore_images(value['images'])
            for path, row in value['files'].items():
                restore_file(path, row, value['allowed'].get(path, []), metadata=metadata.get(path))
        files = {path: capture_file(path) for path in value['files']}
        require(files == value['files'])
    require(sum(len(validate_file(row) or b'') for row in files.values()) <= MAX_BYTES)
    return {'files': files, 'packages': packages(value['packages']),
            'images': [] if mode == 'restore' else images(value['images'])}


def main():
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024)
    result = run(json.loads(raw))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Managed configuration recovery held; preserve private diagnostics.') from None
