"""Descriptor-relative deletion of inventoried generated files, never runtime paths."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

from component_payload import _directory
from private_io import encoded, private_writer, regular, require, sync

LIMIT = 4096


def identity(info):
    file = stat.S_ISREG(info.st_mode)
    # Directory size/link counts change as children are removed. A surviving
    # file must still have its original bytes' metadata, mode and ownership.
    return [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, stat.S_IMODE(info.st_mode),
            info.st_nlink if file else 0, info.st_size if file else 0, info.st_mtime_ns if file else 0]


@contextmanager
def child(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        require(os.fstat(fd).st_dev == os.fstat(parent).st_dev,
                'Cleanup cannot cross a filesystem boundary')
        yield fd
    finally:
        os.close(fd)


def inventory(parent, name):
    """Snapshot a named generated subtree; refuse links, mounts and special files."""
    result = {}
    def visit(fd, leaf, relative):
        info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                'Preserve unexpected cleanup file ownership or type')
        result[relative] = identity(info)
        require(len(result) <= LIMIT, 'Bound one cleanup inventory')
        if stat.S_ISDIR(info.st_mode):
            with child(fd, leaf) as nested:
                for entry in sorted(os.listdir(nested)):
                    visit(nested, entry, relative + '/' + entry)
    with _directory(parent) as fd:
        visit(fd, name, name)
    return result


def remove(parent, entries):
    """Retry only the sealed inventory, checking surviving identities before unlink."""
    require(isinstance(entries, dict) and 0 < len(entries) <= LIMIT,
            'Require a bounded cleanup inventory')
    for name, expected in entries.items():
        require(isinstance(name, str) and name == str(Path(name)) and not name.startswith('/')
                and not {'.', '..'} & set(name.split('/'))
                and isinstance(expected, list) and len(expected) == 8
                and all(type(value) is int for value in expected)
                and expected[2] in (stat.S_IFDIR, stat.S_IFREG), 'Preserve malformed cleanup inventory')
    roots = {name.split('/')[0] for name in entries}
    for name in roots:
        try:
            actual = inventory(parent, name)
        except FileNotFoundError:
            continue
        require(all(entries.get(path) == value for path, value in actual.items()),
                'Preserve new or replaced files during cleanup retry')
    def erase(fd, parts, expected):
        try:
            if len(parts) > 1:
                with child(fd, parts[0]) as nested:
                    erase(nested, parts[1:], expected)
            else:
                require(identity(os.stat(parts[0], dir_fd=fd, follow_symlinks=False)) == expected,
                        'Cleanup file identity changed')
                if expected[2] == stat.S_IFDIR:
                    os.rmdir(parts[0], dir_fd=fd)
                else:
                    os.unlink(parts[0], dir_fd=fd)
        except FileNotFoundError:
            pass
    with _directory(parent) as fd:
        for name in sorted(entries, key=lambda name: (name.count('/'), name), reverse=True):
            erase(fd, name.split('/'), entries[name])
        os.fsync(fd)


def replace(path, value):
    """Only cleanup-owned records use this retryable temporary file."""
    if path.exists() or path.is_symlink():
        regular(path, private=True)
    temporary = path.with_name(path.name + '.writing')
    with private_writer(temporary) as stream:
        stream.write(encoded(value))
    os.replace(temporary, path)
    sync(path.parent)
