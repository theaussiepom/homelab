"""Trusted current allocation/guest joins; no real API, SSH or secret reads."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_staging as staging
from private_io import encoded, write_bytes, write_new
from test_backup_mount_reconciliation import mount, selection


def configuration():
    """Build the fixed synthetic configuration for an operational staging proof."""
    return {'site': {'node': 'pve-lab'}, 'guest': {'vmid': 6100, 'storage_id': 'local-zfs'},
            'app': {'address': '198.18.25.10', 'backup': {'job': {'staging':
                {'path': '/srv/stage', 'size_bytes': 4*1024**3}}}},
            'paths': {'known_hosts': '/private/synthetic/known_hosts', 'private_key': '/private/synthetic/id'}}


def values():
    """Provide matching active config, custom ZFS storage and volume-info responses."""
    volume = mount(2)['volume']
    return ({'rootfs': 'local-zfs:subvol-6100-disk-0,size=8G', 'digest': 'opaque-config-digest',
             'mp0': 'local-zfs:subvol-6100-disk-1,mp=/srv/data,size=8G,backup=1',
             'mp1': volume+',mp=/srv/stage,size=4G'},
            [{'storage': 'local-zfs', 'type': 'zfspool', 'pool': 'rpool/data', 'mountpoint': '/custom/zfs'}],
            {'format': 'subvol', 'path': '/custom/zfs/subvol-6100-disk-2', 'size': 4*1024**3})


def proof():
    """Return the closed fictional guest-filesystem identity projection."""
    return {'device': [0, 17], 'inode': 34, 'uid': 0, 'gid': 0, 'mode': 0o755,
            'mtime_ns': 101, 'ctime_ns': 102, 'bytes': 4*1024**3, 'mount_id': 55,
            'source': hashlib.sha256(b'rpool/data/subvol-6100-disk-2').hexdigest()}


class StagingOwnershipTests(unittest.TestCase):
    def setUp(self):
        """Create an owned private fixture directory without native inputs."""
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)

    def backend(self, rows):
        """Write one fictional selected guest backend with the supplied mount sequence."""
        state = {'resources': [{'module': 'module.guest', 'type': 'proxmox_virtual_environment_container',
                 'name': 'guest', 'instances': [{'attributes': {'mount_point': rows}}]}]}
        path = self.root/'terraform.tfstate'; write_bytes(path, encoded(state))
        return state

    def test_first_ownership_uses_original_backend_and_genuine_prior_configuration(self):
        """Derive first ownership from prior source and state rather than refreshed mounts."""
        cfg = configuration(); previous = copy.deepcopy(cfg); previous['app'].pop('backup')
        for rows in (None, [], [mount(1)]):
            self.backend(rows)
            self.assertTrue(staging.original(cfg, previous, self.root))
        self.backend([mount(1), mount(2)])
        with self.assertRaisesRegex(ValueError, 'implicitly'):
            staging.original(cfg, previous, self.root)
        with self.assertRaises(ValueError): staging.original(cfg, None, self.root)

    def test_later_ownership_preserves_stage_path_capacity_pool_and_volume(self):
        """Require the existing owned stage identity, capacity and storage on later runs."""
        cfg = configuration(); self.backend([mount(1), mount(2)])
        self.assertFalse(staging.original(cfg, copy.deepcopy(cfg), self.root))
        for change in (lambda v: v['app']['backup']['job']['staging'].update(path='/srv/other'),
                       lambda v: v['app']['backup']['job']['staging'].update(size_bytes=8*1024**3),
                       lambda v: v['guest'].update(storage_id='foreign')):
            old = copy.deepcopy(cfg); change(old)
            with self.assertRaises(ValueError): staging.original(cfg, old, self.root)
        self.backend([])
        with self.assertRaises(ValueError): staging.original(cfg, cfg, self.root)
        state = self.backend([mount(2)]); state['resources'].append(copy.deepcopy(state['resources'][0]))
        write_bytes(self.root/'terraform.tfstate', encoded(state))
        with self.assertRaises(ValueError): staging.original(cfg, cfg, self.root)

    def test_refreshed_slot_requires_one_exact_selected_path(self):
        """Reject missing or ambiguous staging paths in the refreshed mount sequence."""
        plan = {'resource_changes': [{'address': staging.GUEST_RESOURCE,
                 'change': {'before': {'mount_point': [mount(1), mount(2)]}}}]}
        self.assertEqual(staging.stage_row(plan, '/srv/stage'), (mount(2), 1))
        for rows in (None, [], [mount(2), mount(2)]):
            plan['resource_changes'][0]['change']['before']['mount_point'] = rows
            with self.assertRaises(ValueError): staging.stage_row(plan, '/srv/stage')

    def test_applied_allocation_requires_one_known_owned_subvolume(self):
        """Bind fresh applied state to one exact allocated staging subvolume."""
        cfg = configuration(); self.backend([mount(1), mount(2)])
        self.assertEqual(staging.applied(cfg, self.root), (mount(2), 1))
        for rows in ([], [mount(2), mount(2)], [dict(mount(2), volume='local-zfs')]):
            self.backend(rows)
            with self.assertRaises(ValueError): staging.applied(cfg, self.root)

    def exercise(self, *, api_values=None, emitted=None, first=True, label='before', mutate_after=False):
        """Run the real join validator against controlled API and SSH responses."""
        cfg = configuration(); current = values() if api_values is None else api_values
        calls = []
        def api(path):
            """Return a selected fictional response and optionally change its later digest."""
            calls.append(path)
            result = current[1] if path == '/storage?type=zfspool' else current[0] if path.endswith('/config?current=1') else current[2]
            if mutate_after and len(calls) > 3 and path.endswith('/config?current=1'):
                result = dict(result, digest='changed')
            return copy.deepcopy(result)
        def quiet(argv, environment, target, **kwargs):
            """Check the strict SSH probe invocation and write only fictional proof bytes."""
            self.assertEqual(environment, {'PATH': '/usr/bin:/bin'})
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertNotIn('ControlMaster=auto', argv)
            self.assertEqual(kwargs, {'input_bytes': staging.MOUNTED_SCRIPT, 'timeout': 30})
            self.assertIn("/usr/bin/python3 - /srv/stage rpool/data/subvol-6100-disk-2", argv[-1])
            write_new(target, encoded(proof() if emitted is None else emitted))
        with patch.object(staging, 'quiet', side_effect=quiet):
            result = staging.verify(cfg, mount(2), 1, self.root/'infrastructure.log', api,
                                    first=first, label=label, mounts=[mount(1, backup=True), mount(2)])
        return result, calls

    def test_api_dataset_custom_mountpoint_and_guest_identity_join_is_exact(self):
        """Bind exact allocation and dataset identity without persisting runtime mount IDs."""
        before, calls = self.exercise()
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(path.endswith('?current=1') for path in calls if '/config' in path))
        self.assertTrue(all('/content?' not in path for path in calls))
        self.assertTrue(any('/content/local-zfs%3Asubvol-6100-disk-2' in path for path in calls))
        after = proof(); after.update(device=[0, 99], mount_id=999, mtime_ns=201, ctime_ns=202)
        actual, _ = self.exercise(emitted=after, first=False, label='after')
        self.assertEqual(before, actual)
        self.assertNotIn('device', actual); self.assertNotIn('mount_id', actual)

    def test_storage_index_type_pool_mountpoint_and_bounds_are_closed(self):
        """Reject ambiguous, shared, malformed or unsupported selected ZFS storage."""
        rows = values()[1]
        self.assertEqual(staging.storage(rows, 'local-zfs'), ('rpool/data', '/custom/zfs'))
        for value in ({'storage': 'local-zfs', 'type': 'zfspool', 'pool': 'rpool/data'},
                      {'storage': 'local-zfs', 'type': 'zfspool', 'pool': 'rpool/data', 'mountpoint': None}):
            self.assertEqual(staging.storage([value], 'local-zfs'), ('rpool/data', '/rpool/data'))
        invalid = [None, {}, [None], [], rows*2, rows*33]
        for key, value in [('type', 'dir'), ('shared', True), ('shared', 0.0), ('pool', None), ('pool', 'rpool/../other'),
                           ('pool', 'bad pool'), ('pool', 'x'*257), ('mountpoint', 'relative'),
                           ('mountpoint', '/x/..'), ('mountpoint', '/x/'+'y'*1024)]:
            invalid.append([dict(rows[0], **{key: value})])
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(ValueError): staging.storage(rows, 'local-zfs')

    def test_native_slot_exact_options_owner_capacity_and_uniqueness_refuse_changes(self):
        """Preserve the complete active mount sequence and refuse changed native options."""
        base, _, _ = values(); row = mount(2)
        mounts = [mount(1, backup=True), row]
        self.assertEqual(staging.native_mount(base, row, 1, mounts)[0], (base['mp0'], base['mp1']))
        mutations = [lambda v: v.update(mp1=None), lambda v: v.update(mp1='x'*4097),
            lambda v: v.update(mp1=v['mp1']+',backup=0,backup=0'),
            lambda v: v.update(mp1=v['mp1']+',unknown=1'), lambda v: v.update(mp1=v['mp1']+',bad'),
            lambda v: v.update(mp1=v['mp1']+',backup=1'), lambda v: v.update(mp1=v['mp1']+',replicate=0'),
            lambda v: v.update(mp1=v['mp1']+',ro=1'), lambda v: v.update(mp1=v['mp1'].replace('size=4G', 'size=8G')),
            lambda v: v.update(mp1=v['mp1'].replace('subvol-6100-disk-2', 'subvol-6101-disk-2')),
            lambda v: v.update(rootfs=row['volume']), lambda v: v.update(rootfs=None),
            lambda v: v.update(mp2=v['mp1'])]
        for change in mutations:
            value = copy.deepcopy(base); change(value)
            with self.subTest(case=mutations.index(change)), self.assertRaises(ValueError):
                staging.native_mount(value, row, 1, mounts)
        with self.assertRaises(ValueError): staging.native_mount(None, row, 1, mounts)

    def test_wrong_api_volume_and_changed_api_during_probe_refuse(self):
        """Refuse incorrect volume metadata or an API change around the guest probe."""
        for field, value in [('format', 'raw'), ('path', '/foreign'), ('size', True), ('size', 8*1024**3)]:
            current = list(values()); current[2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.exercise(api_values=current)
        current = list(values()); current[2] = None
        with self.assertRaises(ValueError): self.exercise(api_values=current)
        with self.assertRaises(ValueError): self.exercise(mutate_after=True)

    def test_pending_desired_stage_or_data_flags_cannot_replace_active_values(self):
        """Refuse pending desired flags when active stage or data flags still differ."""
        cfg = configuration(); desired, pools, info = values()
        for slot in ('mp0', 'mp1'):
            active = copy.deepcopy(desired)
            active[slot] += ',backup=1' if slot == 'mp1' else ',backup=0'
            if slot == 'mp0': active[slot] = active[slot].replace(',backup=1,backup=0', ',backup=0')
            calls = []
            def api(path):
                """Distinguish desired pending values from the deliberately conflicting active config."""
                calls.append(path)
                if path.endswith('/config'): return desired
                if path.endswith('/config?current=1'): return active
                return pools if path == '/storage?type=zfspool' else info
            with patch.object(staging, 'quiet') as ssh, self.assertRaises(ValueError):
                staging.verify(cfg, mount(2), 1, self.root/'infrastructure.log', api,
                               first=True, label='before', mounts=[mount(1, backup=True), mount(2)])
            ssh.assert_not_called()
            self.assertEqual(calls, ['/nodes/pve-lab/lxc/6100/config?current=1'])

    def test_old_volume_options_are_preserved_using_provider_native_semantics(self):
        """Retain legitimate old mount options and their provider-normalized ordering."""
        value, _, _ = values()
        old = dict(mount(1, backup=True), acl=True, quota=True, read_only=True, replicate=False,
                   shared=True, mount_options=['noatime', 'nodev'])
        value['mp0'] += ',acl=1,quota=1,ro=1,replicate=0,shared=1,mountoptions=noatime;nodev'
        staging.native_mount(value, mount(2), 1, [old, mount(2)])
        for suffix in (',acl=0', ',mountoptions=nodev;noatime'):
            changed = copy.deepcopy(value)
            if 'acl' in suffix: changed['mp0'] = changed['mp0'].replace(',acl=1', ',acl=0')
            else: changed['mp0'] = changed['mp0'].replace('mountoptions=noatime;nodev', 'mountoptions=nodev;noatime')
            with self.assertRaises(ValueError): staging.native_mount(changed, mount(2), 1, [old, mount(2)])
        with self.assertRaises(ValueError): staging.native_mount(value, mount(2), True, [old, mount(2)])
        with self.assertRaises(ValueError): staging.native_mount(value, mount(2), 1, [old])

    def test_guest_output_is_closed_typed_bounded_and_preserves_prior_evidence(self):
        """Reject malformed proof fields while preserving earlier evidence and sanitizing errors."""
        for number, (field, value) in enumerate([('device', [0]), ('device', [False, 1]), ('device', 'bad'),
            ('inode', 0), ('inode', False), ('uid', 1), ('gid', 1), ('mode', 0o777), ('mode', 0o10000),
            ('bytes', 0), ('bytes', 8*1024**3), ('mount_id', 0), ('source', 'private-sentinel'), ('extra', 1)]):
            output = proof(); output[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError) as caught:
                self.exercise(emitted=output)
            self.assertNotIn('private-sentinel', str(caught.exception))
            (self.root/'backup-staging-before.json').unlink()
        for output in ({}, [], None):
            if output is None: continue
            with self.assertRaises(ValueError): self.exercise(emitted=output)
            (self.root/'backup-staging-before.json').unlink()
        with self.assertRaises(ValueError): self.exercise(first=1)
        with self.assertRaises(ValueError): self.exercise(label='foreign')
        self.exercise()
        old = (self.root/'backup-staging-before.json').read_bytes()
        with self.assertRaises(ValueError): self.exercise()
        self.assertEqual((self.root/'backup-staging-before.json').read_bytes(), old)

    def test_malformed_duplicate_or_oversized_probe_output_is_never_admitted(self):
        """Reject invalid JSON, duplicate keys and output exceeding the private proof bound."""
        for raw in (b'{"inode":1,"inode":2}', b'private-sentinel-invalid-json'):
            with patch.object(staging, 'regular', return_value=raw), self.assertRaises(ValueError) as caught:
                self.exercise()
            self.assertNotIn('private-sentinel', str(caught.exception))
            (self.root/'backup-staging-before.json').unlink()
        oversized = proof(); oversized['extra'] = 'x'*4097
        with self.assertRaises(ValueError): self.exercise(emitted=oversized)


if __name__ == '__main__': unittest.main()
