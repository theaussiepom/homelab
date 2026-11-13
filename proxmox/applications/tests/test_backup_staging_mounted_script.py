"""Execute the exact guest probe in a fictional FD/mount namespace, no SSH."""
import ast
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
        """Execute the exact mounted probe in a fictional FD and mount namespace."""
        descriptors = {}; closed = set(); counts = {}; reads = {}; printed = []
        payloads = {}; offsets = {}
        def open_(path, flags, *, dir_fd=None):
            """Allocate fictional descriptors and model a refused symlink traversal."""
            if case.get('symlink') and path == 'stage': raise OSError('synthetic symlink refusal')
            if dir_fd is not None: path = descriptors[dir_fd].rstrip('/')+'/'+path
            fd = len(descriptors)+1; descriptors[fd] = path; return fd
        def metadata(path):
            """Return controlled ownership and inode changes for fictional paths."""
            counts[path] = counts.get(path, 0)+1
            is_stage = path == '/srv/stage'
            return SimpleNamespace(st_dev=2 if is_stage else 1,
                st_ino=999 if case.get('inode_changes') and is_stage and counts[path] >= 3 else 34 if is_stage else 1,
                st_mode=stat.S_IFDIR | (0o777 if case.get('writable') and path == '/srv' else 0o755),
                st_uid=1 if case.get('foreign') and path == '/srv' else 0, st_gid=0,
                st_mtime_ns=101, st_ctime_ns=102)
        def stat_(name, *, dir_fd, follow_symlinks):
            """Check no-follow path readback and simulate a replaced directory link."""
            self.assertFalse(follow_symlinks)
            result = metadata(descriptors[dir_fd].rstrip('/')+'/'+name)
            if case.get('link_changes') and name == 'stage': result.st_ino += 1
            return result
        def read_(fd, bound):
            """Supply bounded fictional mountinfo and FD mount-identity observations."""
            if fd not in payloads:
                payloads[fd] = contents(descriptors[fd], bound)
            start = offsets.get(fd, 0)
            raw = payloads[fd][start:start+min(bound, case.get('chunk_size', bound))]
            offsets[fd] = start+len(raw)
            return raw
        def contents(path, bound):
            """Keep each opened proc file stable while permitting later recheck changes."""
            reads[path] = reads.get(path, 0)+1
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
            """Describe controlled stage children without reading any real directory."""
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
            """Inject only the fictional OS and argument interfaces into the exact probe."""
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
        """Accept an empty first root and the permitted later private history directory."""
        self.assertEqual(self.exercise()['device'], [0, 2])
        self.exercise(repeat=True, children=['.homelab-backup'])

    def test_short_proc_reads_reach_the_complete_mount_and_fdinfo(self):
        """Read beyond short non-EOF prefixes before validating the exact mount."""
        self.assertEqual(self.exercise(chunk_size=7)['device'], [0, 2])
        self.exercise(chunk_size=1, repeat=True, children=['.homelab-backup'])

    def test_proc_exact_bound_eof_overflow_and_error_always_close(self):
        """Keep the proc byte ceiling and close guard across short reads and errors."""
        tree = ast.parse(backup_staging.MOUNTED_SCRIPT)
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('require', 'proc')]
        for payload, error in [(b'12345678', False), (b'123456789', False), (b'12', True)]:
            with self.subTest(payload=payload, error=error):
                calls = []; closed = []; offset = 0
                def open_(path, flags):
                    """Assert the exact proc open flags without opening a real path."""
                    self.assertEqual(path, '/proc/self/mountinfo')
                    self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    return 77
                def read_(fd, bound):
                    """Return short byte chunks, EOF or an injected read error."""
                    nonlocal offset
                    self.assertEqual(fd, 77); calls.append(bound)
                    if error and offset: raise OSError('synthetic proc read error')
                    chunk = payload[offset:offset+min(2, bound)]; offset += len(chunk)
                    return chunk
                fake = SimpleNamespace(open=open_, read=read_, close=closed.append,
                    O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC)
                namespace = {'os': fake}
                exec(compile(ast.Module(body=nodes, type_ignores=[]), '<exact-proc-reader>', 'exec'), namespace)
                if len(payload) > 8 or error:
                    with self.assertRaises((ValueError, OSError)):
                        namespace['proc']('/proc/self/mountinfo', 8)
                else:
                    self.assertEqual(namespace['proc']('/proc/self/mountinfo', 8), payload)
                    self.assertEqual(calls[-1], 1)  # EOF is established at the exact limit.
                self.assertEqual(closed, [77])

    def test_foreign_ambiguous_unstable_or_nonempty_first_mount_refuses(self):
        """Refuse foreign, unstable, nested, writable or nonempty first-use stages."""
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
