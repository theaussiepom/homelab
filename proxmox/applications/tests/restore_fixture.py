"""Real GNU-tar and Ansible restore regressions with synthetic data in Docker."""
import json
import os
from pathlib import Path
import shutil
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

    # Exercise the real Ansible restore task against the native volume shape.
    # These absolute guest paths exist only in this disposable Docker container.
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    volume = Path('/srv/homelab'); volume.mkdir(parents=True, exist_ok=False)
    recovery = volume / 'lost+found'; recovery.mkdir(mode=0o700)
    marker = recovery / 'filesystem-recovery'; marker.write_text('leave this alone')
    os.chown(recovery, 65534, 65534)
    recovery_stat = recovery.stat()
    installation = Path('/opt/homelab-app'); installation.mkdir(mode=0o700, exist_ok=False)
    shutil.copyfile(Path(restore.__file__), installation / 'restore.py')
    playbook = root / 'restore.yml'
    tasks = Path(__file__).resolve().parents[1] / 'ansible/tasks/restore.yml'
    playbook.write_text(json.dumps([{'hosts':'all', 'connection':'local', 'gather_facts':False,
                                    'tasks':[{'ansible.builtin.import_tasks':str(tasks)}]}]))
    variables = root / 'variables.json'
    settings = {'app':{'capture':{'path':str(archive),'sha256':restore.digest(archive),'coherent':True}}}
    variables.write_text(json.dumps(settings))
    command = ['ansible-playbook','-i','localhost,',str(playbook),'--extra-vars','@'+str(variables)]
    for _ in range(2):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
    copied = volume / 'data/synthetic-config'
    assert copied.read_bytes() == data.read_bytes()
    assert (copied.stat().st_uid,copied.stat().st_gid,copied.stat().st_mode & 0o777) == (70,1000,0o640)
    assert os.getxattr(copied,b'user.homelab-fixture') == b'preserved'
    assert os.getxattr(copied,b'system.posix_acl_access') == os.getxattr(data,b'system.posix_acl_access')
    assert marker.read_text() == 'leave this alone'
    assert (recovery.stat().st_ino,recovery.stat().st_uid,recovery.stat().st_gid,recovery.stat().st_mode) == (recovery_stat.st_ino,recovery_stat.st_uid,recovery_stat.st_gid,recovery_stat.st_mode)
    settings['app']['capture']['sha256'] = '0' * 64
    variables.write_text(json.dumps(settings))
    failed = subprocess.run(command, capture_output=True, text=True)
    assert failed.returncode != 0
    assert 'Capture SHA256 does not match' in failed.stdout + failed.stderr
    assert "filter plugin 'ansible.builtin.from_json' failed" not in failed.stdout + failed.stderr
    print('Ansible restore: formatted-volume metadata preserved, exact data metadata, repeat and original error reporting passed')
