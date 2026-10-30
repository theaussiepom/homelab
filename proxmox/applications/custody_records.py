"""Bounded read-only custody snapshots, marker refusal and existing NAS identity."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import subprocess
from private_io import require, digest

LIMIT = 1024 * 1024


def decode(raw):
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs), "Preserve duplicate custody JSON fields")
        return value
    return json.loads(raw, object_pairs_hook=unique)


def no_markers(directory, *, own_ordinary=False, bootstrap=False):
    """Pending or hidden failure markers never become completion exceptions."""
    names = list(directory.iterdir())
    require(len(names) <= 4096, "Bound the custody marker inventory")
    for path in names:
        name = path.name.lstrip(".")
        ordinary = own_ordinary and path.name == "ORDINARY-HOLD.json"
        marker = (name.endswith("HOLD.json") or name in {"VERIFYING.json", "SERVICE-VERIFYING.json"}
                  or bootstrap and name == "CONFIGURING")
        pending = "pending" in name.lower() and (
            "HOLD" in name or "VERIFYING" in name or name.startswith(("ordinary-complete.json", "request.json", "claim.json", "complete.json", "overlay.json"))
            or bootstrap and "CONFIGURING" in name)
        require(not pending and (not marker or ordinary), "Preserve unresolved or pending custody")


class Snapshot:
    """Read through non-symlink parents; verify names and bytes before returning."""

    def __init__(self):
        self.directories = {}
        self.hashes = {}
        self.private = {}

    def read(self, path, *, private=True):
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts, "Use exact custody paths")
        with ExitStack() as opened:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened.callback(os.close, fd)
            parent = Path("/")
            for name in path.parts[1:-1]:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                opened.callback(os.close, fd)
                parent /= name
                info = os.fstat(fd)
                identity = (info.st_dev, info.st_ino)
                require(self.directories.get(parent, identity) == identity, "Custody parent changed during read")
                self.directories[parent] = identity
            source = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(source, "rb") as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT,
                        "Read only bounded regular custody files")
                require(not private or info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                        "Keep private custody ownership and permissions")
                raw = stream.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "Oversized custody file")
        value_hash = digest(raw)
        require(self.hashes.get(str(path), value_hash) == value_hash, "Custody bytes changed during read")
        self.hashes[str(path)] = value_hash
        self.private[str(path)] = private or self.private.get(str(path), False)
        require(len(self.hashes) <= 128 and len(self.directories) <= 512, "Bound the custody proof set")
        return raw

    def finish(self):
        for path, expected in self.directories.items():
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == expected,
                    "Custody directory or mount changed during read")
        original = dict(self.hashes)
        for path in original:
            self.read(path, private=self.private[path])
        require(self.hashes == original, "Custody proof set changed during read")
        return dict(self.hashes)


def recovery(cfg):
    """Check an existing recovery mount; never mkdir, mount or repair a path."""
    mount = Path(cfg["paths"]["backup_mount"])
    require(os.path.ismount(mount), "The selected NAS recovery mount is unavailable")
    info = mount.lstat()
    require(stat.S_ISDIR(info.st_mode), "Preserve the existing recovery mount identity")
    fields = subprocess.check_output(
        ["findmnt", "-rn", "-o", "FSTYPE,SOURCE", "--target", str(mount)], text=True, timeout=10
    ).split()
    require(len(fields) == 2 and fields[0] in {"nfs", "nfs4", "cifs"}
            and fields[1] == cfg["paths"]["backup_source"], "The selected NAS filesystem/source changed")
    return mount


def read_existing(path, *, private=True):
    snapshot = Snapshot()
    raw = snapshot.read(path, private=private)
    snapshot.finish()
    return raw
