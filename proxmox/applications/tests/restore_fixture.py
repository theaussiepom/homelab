"""Real GNU-tar restore with synthetic ownership, modes and xattrs inside Docker."""
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import restore

# Docker's ordinary writable layer supports POSIX ACLs; its /tmp tmpfs may not.
with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
    root = Path(tmp)
    source = root / 'source'; source.mkdir()
    data = source / 'synthetic-config'; data.write_text('synthetic-only\n')
    os.chown(data, 70, 1000); os.chmod(data, 0o640)
    os.setxattr(data, b'user.homelab-fixture', b'preserved')
    acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, identity) for tag, perm, identity in
        [(1, 6, 0xffffffff), (2, 4, 12345), (4, 0, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)])
    os.setxattr(data, b'system.posix_acl_access', acl)
    archive = root / 'capture.tar'
    subprocess.run(['tar', '--create', '--file', str(archive), '--acls', '--xattrs', '--numeric-owner', '-C', str(source), '.'], check=True)
    target = root / 'target'; receipt = root / 'receipt.json'
    assert restore.restore(archive, target, receipt, restore.digest(archive))
    result = target / 'synthetic-config'
    assert result.read_bytes() == data.read_bytes()
    assert (result.stat().st_uid, result.stat().st_gid, result.stat().st_mode & 0o777) == (70, 1000, 0o640)
    assert os.getxattr(result, b'user.homelab-fixture') == b'preserved'
    assert os.getxattr(result, b'system.posix_acl_access') == os.getxattr(data, b'system.posix_acl_access')
    assert not restore.restore(archive, target, receipt, restore.digest(archive))
    print('GNU tar restore: contents, UID 70, GID 1000, mode, POSIX ACL, xattr and repeat receipt passed')
