"""Verify an installed public bundle without importing any code from that bundle."""
import hashlib
import os
from pathlib import Path
import stat
import sys


def metadata(path, directory):
    info = path.lstat()
    if not ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022
            and (directory or info.st_nlink == 1)):
        raise ValueError('Preserve foreign public backup source ownership')


def ancestors(directory):
    directory = Path(directory)
    if not directory.is_absolute() or str(directory) != str(directory.resolve(strict=False)):
        raise ValueError('Use a canonical public source directory')
    for path in reversed([directory, *directory.parents]):
        if path.exists() or path.is_symlink(): metadata(path, True)


def verify(directory, expected=None):
    directory = Path(directory); ancestors(directory)
    if expected is None: return
    paths = sorted([*directory.rglob('*'), *(directory.parent/'common').rglob('*')])
    if not paths or len(paths) > 8192: raise ValueError('Bound the installed source inventory')
    result = hashlib.sha256()
    for path in paths:
        metadata(path, path.is_dir())
        if path.is_file() and not any(part in {'.terraform', '__pycache__', '.work'} for part in path.parts):
            result.update(str(path.relative_to(directory.parent)).encode())
            result.update(hashlib.sha256(path.read_bytes()).digest())
    if result.hexdigest() != expected: raise ValueError('The installed public source differs from the selected bundle')


def main():
    if len(sys.argv) not in (2, 3): raise ValueError('Supply one pinned public bundle path and optional digest')
    verify(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)


if __name__ == '__main__': main()
