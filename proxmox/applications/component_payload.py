"""Versioned selected-app payloads inside the existing immutable input tree.

This is an owned-file primitive. It does not read a secret source, create an
account, acquire a lock, admit an attempt or execute a deployment action.
The caller holds the existing deployment locks before preparing these files.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from private_io import encoded, require, write_new

SCHEMA = 'homelab-selected-app-inputs-v1'
BINDING_SCHEMA = 'homelab-component-deployment-binding-v1'
MANIFEST = 'selected-app.json'
MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * MAX_FILE


def _id(value):
    return isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', value)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _directory(path):
    """Anchor every ancestor with NOFOLLOW before accessing private leaves."""
    path = Path(path)
    require(path.is_absolute() and path.as_posix() == str(path) and
            not any(part in ('.', '..') for part in str(path).split('/')),
            'Use a confined selected-app input directory')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'Preserve selected-app directory ownership and permissions')
        yield descriptor
    finally:
        os.close(descriptor)


def _read(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_FILE,
                'Preserve bounded owned selected-app input files')
        raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE and _identity(info) == _identity(os.fstat(stream.fileno()))
                and _identity(info) == _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                'Selected-app inputs changed while reading')
        return raw


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _files(values):
    require(isinstance(values, dict) and len(values) <= 128 and
            all(isinstance(name, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,127}', name)
                and name != MANIFEST and isinstance(raw, bytes) and len(raw) <= MAX_FILE
                for name, raw in values.items()) and sum(map(len, values.values())) <= MAX_TOTAL,
            'Use only bounded selected adapter input files')
    return {name: _sha(raw) for name, raw in sorted(values.items())}


class AppPayload:
    """An in-memory pin to one exact immutable protected manifest."""
    def __init__(self, directory, identity, app, manifest):
        require(isinstance(identity, str) and re.fullmatch('[0-9a-f]{64}', identity) and _id(app),
                'Bind selected inputs to a packet and stable app identity')
        self.directory, self.identity, self.app = Path(directory), identity, app
        self.manifest = manifest
        self.manifest_sha256 = _sha(manifest)

    @classmethod
    def load(cls, directory, proof):
        require(isinstance(proof, dict) and set(proof) == {'schema', 'identity', 'app', 'payload_sha256'}
                and proof['schema'] == SCHEMA, 'Preserve the selected-app phase binding')
        with _directory(directory) as descriptor:
            manifest = _read(descriptor, MANIFEST)
        selected = cls(directory, proof['identity'], proof['app'], manifest)
        require(selected.check() == proof, 'Selected-app phase binding differs from its immutable payload')
        return selected

    def check(self):
        with _directory(self.directory) as directory:
            pinned = os.fstat(directory)
            require(_read(directory, MANIFEST) == self.manifest,
                    'Preserve changed or incomplete selected-app inputs')
            value = json.loads(self.manifest)
            require(set(value) == {'schema', 'identity', 'app', 'files'} and value['schema'] == SCHEMA
                    and value['identity'] == self.identity and value['app'] == self.app
                    and isinstance(value['files'], dict) and len(value['files']) <= 128
                    and set(os.listdir(directory)) == set(value['files']) | {MANIFEST},
                    'Preserve selected-app input ownership')
            total = 0
            for name, digest in value['files'].items():
                require(isinstance(name, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,127}', name)
                        and name != MANIFEST and isinstance(digest, str)
                        and re.fullmatch('[0-9a-f]{64}', digest), 'Preserve selected-app input manifest')
                raw = _read(directory, name)
                total += len(raw)
                require(_sha(raw) == digest and total <= MAX_TOTAL, 'Selected-app input bytes changed')
            with _directory(self.directory) as current:
                actual = os.fstat(current)
                require((pinned.st_dev, pinned.st_ino) == (actual.st_dev, actual.st_ino),
                        'Selected-app input directory changed')
        return {'schema': SCHEMA, 'identity': self.identity, 'app': self.app,
                'payload_sha256': self.manifest_sha256}


def prepare(parent, identity, app, values):
    """Create once or verify exactly; partial failures never resume or rotate."""
    manifest = encoded({'schema': SCHEMA, 'identity': identity, 'app': app, 'files': _files(values)})
    selected = AppPayload(Path(parent) / app, identity, app, manifest)
    with _directory(parent) as parent_fd:
        try:
            os.stat(app, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(app, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
            directory = os.open(app, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                for name, raw in sorted(values.items()):
                    write_new(name, raw, dir_fd=directory)
                write_new(MANIFEST, manifest, dir_fd=directory)
            finally:
                os.close(directory)
    selected.check()
    return selected


def existing(parent, identity, app):
    """Refuse incomplete existing inputs before reading any new secret source."""
    require(_id(app), 'Bind the selected app identity')
    with _directory(parent) as directory:
        try:
            os.stat(app, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
    path = Path(parent)/app
    with _directory(path) as directory:
        manifest = _read(directory, MANIFEST)
    selected = AppPayload(path, identity, app, manifest)
    selected.check()
    return selected
