"""Execute the exact guest probe in a fictional FD/mount namespace, no SSH."""
import builtins
from contextlib import nullcontext
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_staging


class MountedScriptTests(unittest.TestCase):
    def exercise(self, **case):
        descriptors = {}; closed = set(); counts = {}; reads = {}; printed = []
        def open_(path, flags, *, dir_fd=None):
            if case.get('symlink') and path == 'stage': raise OSError('synthetic symlink refusal')
            if dir_fd is not None: path = descriptors[dir_fd].rstrip('/')+'/'+path
            fd = len(descriptors)+1; descriptors[fd] = path; return fd
        def metadata(path):
            counts[path] = counts.get(path, 0)+1
            is_stage = path == '/srv/stage'
            return SimpleNamespace(st_dev=2 if is_stage else 1,
                st_ino=999 if case.get('inode_changes') and is_stage and counts[path] >= 3 else 34 if is_stage else 1,
                st_mode=stat.S_IFDIR | (0o777 if case.get('writable') and path == '/srv' else 0o755),
                st_uid=1 if case.get('foreign') and path == '/srv' else 0, st_gid=0,
                st_mtime_ns=101, st_ctime_ns=102)
        def stat_(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            result = metadata(descriptors[dir_fd].rstrip('/')+'/'+name)
            if case.get('link_changes') and name == 'stage': result.st_ino += 1
            return result
        def read_(fd, bound):
            path = descriptors[fd]; reads[path] = reads.get(path, 0)+1
            if case.get('oversize'): return b'x'*bound
            if path == '/proc/self/mountinfo':
                if case.get('malformed'): return b'unparseable\n'
                root_source = 'rpool/data/root'
                source = root_source if case.get('rootfs') else 'rpool/data/subvol-6100-disk-2'
                if case.get('dataset_changes') and reads[path] > 1: source = 'rpool/data/other'
                fs = 'ext4' if case.get('wrong_type') else 'zfs'
                root = '/directory' if case.get('bind_subdirectory') else '/'
                device = '0:3' if case.get('wrong_device') else '0:2'
                target = '/other' if case.get('wrong_target') else '/srv/stage'
                result = '1 0 0:1 / / rw - zfs '+root_source+' rw\n'
                result += f'2 1 {device} {root} {target} rw - {fs} {source} rw\n'
                if case.get('duplicate'): result += f'3 1 0:2 / /alias rw - zfs {source} rw\n'
                if case.get('descendant'): result += '4 2 0:4 / /srv/stage/lost+found rw - zfs rpool/foreign rw\n'
                return result.encode()
            target = descriptors[int(path.rsplit('/', 1)[1])]
            value = 2 if target == '/srv/stage' else 1
            if case.get('wrong_mnt_id') and target == '/srv/stage': value = 3
            if case.get('same_parent') and target == '/srv': value = 2
            return (('mnt_id: '+str(value)+'\n')* (2 if case.get('duplicate_fdinfo') else 1)).encode()
        def entries(fd):
            names = case.get('children', [])
            return nullcontext([SimpleNamespace(name=name, stat=lambda follow_symlinks: SimpleNamespace(
                st_mode=(stat.S_IFLNK if case.get('child_link') else stat.S_IFDIR)|
                        (0o777 if case.get('child_writable') else 0o700),
                st_uid=1 if case.get('child_foreign') else 0, st_gid=0)) for name in names])
        fake = SimpleNamespace(**{name: getattr(os, name, 2**20) for name in
            ('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NOATIME')},
            open=open_, close=closed.add, read=read_, fstat=lambda fd: metadata(descriptors[fd]), stat=stat_,
            scandir=entries, fstatvfs=lambda fd: SimpleNamespace(f_blocks=case.get('blocks', 1024), f_frsize=4096),
            geteuid=lambda: 1000 if case.get('wrong_actor') else 0, major=os.major, minor=os.minor)
        namespace = dict(vars(builtins))
        def imported(name, *args, **kwargs):
            if name == 'os': return fake
            if name == 'sys': return SimpleNamespace(argv=['-', '/srv/stage', 'rpool/data/subvol-6100-disk-2',
                                                          str(4*1024**3), 'false' if case.get('repeat') else 'true'])
            return builtins.__import__(name, *args, **kwargs)
        namespace.update(__import__=imported, print=lambda value: printed.append(value))
        try:
            exec(compile(backup_staging.MOUNTED_SCRIPT, '<mounted-staging-probe>', 'exec'), {'__builtins__': namespace})
        finally:
            self.assertEqual(set(descriptors), closed)
        self.assertEqual(len(printed), 1)
        return json.loads(printed[0])

    def test_first_zfs_root_is_empty_and_later_owned_private_history_passes(self):
        self.assertEqual(self.exercise()['device'], [0, 2])
        self.exercise(repeat=True, children=['.homelab-backup'])

    def test_foreign_ambiguous_unstable_or_nonempty_first_mount_refuses(self):
        cases = [{'wrong_actor': True}, {'symlink': True}, {'foreign': True}, {'writable': True},
                 {'inode_changes': True}, {'link_changes': True}, {'oversize': True}, {'malformed': True},
                 {'rootfs': True}, {'dataset_changes': True}, {'wrong_type': True}, {'bind_subdirectory': True},
                 {'wrong_device': True}, {'wrong_target': True}, {'duplicate': True}, {'wrong_mnt_id': True},
                 {'same_parent': True}, {'duplicate_fdinfo': True}, {'blocks': 0}, {'blocks': 2**30},
                 {'children': ['existing']}, {'children': ['lost+found']}, {'children': ['.homelab-backup']},
                 {'descendant': True}, {'repeat': True, 'descendant': True},
                 {'repeat': True, 'children': ['.homelab-backup'], 'child_link': True},
                 {'repeat': True, 'children': ['.homelab-backup'], 'child_writable': True},
                 {'repeat': True, 'children': ['.homelab-backup'], 'child_foreign': True}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises((ValueError, OSError)):
                self.exercise(**case)


if __name__ == '__main__': unittest.main()
