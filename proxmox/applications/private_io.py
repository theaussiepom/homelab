"""Owned private files and durable receipts; no target or application behavior."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def private_directory(path, create=False):
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "Expected an owned mode-0700 private directory",
    )


def regular(path, private=False, *, limit=1024 * 1024, modes=(0o600,)):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            "Expected a bounded regular private input",
        )
        if private:
            require(
                info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) in modes,
                "Expected an owned private input with the selected permissions",
            )
        value = stream.read(limit + 1)
    require(len(value) <= limit, "Oversized private input")
    return value


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def relative_name(path, dir_fd):
    path = Path(path)
    require(
        dir_fd is None or (path.name == str(path) and path.name not in {"", ".", ".."}),
        "Descriptor-relative private files need a single filename",
    )
    return path


@contextmanager
def private_writer(
    path, *, append=False, exclusive=False, dir_fd=None, readable=False, create=True
):
    """Validate identity and permissions before truncating or appending evidence."""
    path = relative_name(path, dir_fd)
    flags = (os.O_RDWR if readable else os.O_WRONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    if append:
        flags |= os.O_APPEND
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Preserve unexpected private file identity or permissions",
        )
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "r+b" if readable else "wb") as stream:
        if not append:
            stream.truncate(0)
        try:
            yield stream
        finally:
            stream.flush()
            os.fsync(stream.fileno())
            if dir_fd is None:
                sync(path.parent)
            else:
                os.fsync(dir_fd)


def write_new(path, value, *, dir_fd=None):
    with private_writer(path, exclusive=True, dir_fd=dir_fd) as stream:
        stream.write(value)


def write_bytes(path, value):
    with private_writer(path) as stream:
        stream.write(value)


def replace_receipt(path, value):
    # Only our own held phase can be updated under the adapter lock. Never use
    # this helper to replace an input, public phase receipt or failed log.
    if path.exists() or path.is_symlink():
        regular(path, private=True)
    temporary = path.with_name(path.name + ".pending")
    write_new(temporary, encoded(value))
    os.replace(temporary, path)
    sync(path.parent)


def sha(path, *, dir_fd=None):
    result = hashlib.sha256()
    path = relative_name(path, dir_fd)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        require(
            stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
            "Hash only regular source or state files",
        )
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write(path, value):
    write_bytes(path, encoded(value))


def read_json(path, *, private=False):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON field")
            result[key] = value
        return result

    return json.loads(regular(path, private=private), object_pairs_hook=unique)
