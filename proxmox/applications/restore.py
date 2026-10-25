#!/usr/bin/env python3
"""Restore a frozen, hashed capture into an empty new guest, preserving metadata."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def validate_archive(path):
    """GNU tar does the extraction; inspect members and links before it writes."""
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError('The capture is empty')
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError('The capture contains a special file or escaping path')
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or '..' in link.parts:
                    raise ValueError('Review escaping or absolute links separately')
        # Do not let a later member traverse a symlink created by an earlier one.
        links = {PurePosixPath(m.name) for m in members if m.issym()}
        if any(link in PurePosixPath(m.name).parents for m in members for link in links):
            raise ValueError('A capture member traverses a symlink')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def sync_directory(path):
    """Persist receipt names before a native command can start or complete."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore(archive, destination, receipt, expected):
    if digest(archive) != expected:
        raise ValueError('Capture SHA256 does not match')
    validate_archive(archive)
    if receipt.exists():
        status = json.loads(receipt.read_text())
        if status == {'state': 'complete', 'sha256': expected, 'destination': str(destination)}:
            return False
        raise ValueError('A prior restore is incomplete or different; preserve it for review')
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ValueError('Restore requires an empty new destination')
    receipt.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.mkdir(mode=0o750, parents=True, exist_ok=True)
    status = {'state': 'started', 'sha256': expected, 'destination': str(destination)}
    fd = os.open(receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(status, stream)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(receipt.parent)
    errors = receipt.with_suffix('.tar.stderr')
    fd = os.open(errors, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    sync_directory(receipt.parent)
    with os.fdopen(fd, 'w') as diagnostic:
        extracted = subprocess.run(['tar', '--extract', '--file', str(archive), '--directory', str(destination),
                                    '--numeric-owner', '--same-owner', '--same-permissions', '--acls', '--xattrs',
                                    '--xattrs-include=*', '--delay-directory-restore'],
                                   stdout=subprocess.DEVNULL, stderr=diagnostic)
        diagnostic.flush()
        os.fsync(diagnostic.fileno())
    if extracted.returncode != 0 or errors.stat().st_size:
        raise ValueError('Tar restore held; inspect the private .tar.stderr beside its receipt')
    status['state'] = 'complete'
    temporary = receipt.with_suffix('.tmp')
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(status, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(receipt)
    sync_directory(receipt.parent)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root inside the selected new guest to preserve numeric ownership')
    print(json.dumps({'restored': restore(args.archive, args.destination, args.receipt, args.sha256)}))


if __name__ == '__main__':
    main()
