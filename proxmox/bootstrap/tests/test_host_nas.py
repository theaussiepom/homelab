"""NFS setup cannot replace an existing mount, bind other paths or remap users."""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_nas


class NasTests(unittest.TestCase):
    def setUp(self):
        """Use invented storage identity and an unprivileged deployment guest."""
        self.nas = {'server': '198.18.20.2', 'export': '/volume1/test',
                    'version': '4.1', 'directory': 'bootstrap-state'}
        self.guest = {'hostname': 'deploy', 'unprivileged': 1}

    def test_plan_has_no_commands_and_completed_configuration_needs_no_writes(self):
        """A read-only plan recognises its exact existing units and bind."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            plan = host_nas.plan(self.nas, self.guest, root)
            self.assertEqual(len(plan['units_to_create']), 2)
            self.assertTrue(plan['bind_to_add'])
            unitdir = root / 'etc/systemd/system'; unitdir.mkdir(parents=True)
            for name, content in host_nas.units(self.nas).items():
                (unitdir / name).write_text(content)
            self.guest['mp0'] = plan['binding']
            again = host_nas.plan(self.nas, self.guest, root)
            self.assertEqual(again['units_to_create'], [])
            self.assertFalse(again['bind_to_add'])
            self.assertIn('hard,nosuid,nodev,noexec', host_nas.units(self.nas)[host_nas.UNIT])
            self.assertNotIn('Requires=', host_nas.units(self.nas)[host_nas.AUTOMOUNT])

    def test_other_mounts_and_changed_units_are_held(self):
        """No adoption or broad sharing of existing host paths is allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for change in [{'mp0': '/etc,mp=/secrets'}, {'mp1': '/data,mp=/data'}, {'unprivileged': 0}]:
                with self.assertRaises(RuntimeError):
                    host_nas.plan(self.nas, dict(self.guest, **change), root)
            unitdir = root / 'etc/systemd/system'; unitdir.mkdir(parents=True)
            (unitdir / host_nas.UNIT).write_text('somebody else owns this mount')
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                host_nas.plan(self.nas, self.guest, root)

    def test_paths_and_version_are_explicit(self):
        """Never turn an invalid selection into another path, server or version."""
        for change in [{'server': '127.0.0.1'}, {'export': '/volume1/../etc'},
                       {'directory': '../other'}, {'version': 'auto'}]:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                host_nas.units(dict(self.nas, **change))

    def test_one_graceful_restart_activates_bind_then_rerun_is_a_noop(self):
        """Exercise host setup and default UID mapping without a real mount."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'etc/systemd/system').mkdir(parents=True)
            proc = root / 'proc/123'; proc.mkdir(parents=True)
            (proc / 'mountinfo').write_text('')
            for kind in ('uid', 'gid'): (proc / (kind + '_map')).write_text('0 100000 65536\n')
            calls, owners, active, pending, mounted = [], {}, {}, {}, [False]
            private = root / str(host_nas.HOST_MOUNT / self.nas['directory']).lstrip('/')
            real_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if path == private and path in owners:
                    values = list(result); values[4:6] = owners[path]
                    return os.stat_result(values)
                return result

            def execute(args):
                calls.append(args)
                if args[0] == 'findmnt':
                    # systemd leaves an autofs mount under the active NFS mount.
                    return 'nfs4 198.18.20.2:/volume1/test\n' if ['-t', 'nfs,nfs4'] == args[2:4] else 'autofs systemd-1\nnfs4 198.18.20.2:/volume1/test\n'
                if args == ['lxc-info', '-n', '4917', '-p', '-H']: return '123\n'
                if args[:2] == ['pct', 'exec']: return '1000\n'
                if args[0] == 'pvesh': return json.dumps(active)
                if args[:2] == ['pct', 'set']: pending['mp0'] = args[-1]
                if args[:2] == ['pct', 'status']: return 'status: stopped\n'
                if args[:2] == ['pct', 'start']:
                    active.update(pending)
                    (proc / 'mountinfo').write_text('1 2 0:1 /bootstrap-state /srv/homelab-backups rw - nfs4 198.18.20.2:/volume1/test rw\n')
                if args == ['systemctl', 'start', host_nas.UNIT]: mounted[0] = True
                return ''

            guest = dict(self.guest, node='test-pve')
            with patch.object(host_nas.os, 'chown', side_effect=lambda p,u,g: owners.update({p: [u,g]})), \
                    patch.object(host_nas.os.path, 'ismount', side_effect=lambda p: mounted[0]), \
                    patch.object(Path, 'stat', fake_stat):
                first = host_nas.ensure(self.nas, 4917, guest, execute, root, restart=True)
                self.assertTrue(first['changed']); self.assertEqual(first['mapped_uid'], 101000)
                second = host_nas.ensure(self.nas, 4917, dict(guest, **active), execute, root, restart=True)
                self.assertFalse(second['changed'])
            self.assertEqual([c for c in calls if c[:2] == ['pct', 'shutdown']], [['pct', 'shutdown', '4917', '--timeout', '30']])
            self.assertEqual([c for c in calls if c[:2] == ['pct', 'start']], [['pct', 'start', '4917']])
            self.assertEqual(len([c for c in calls if c[:2] == ['pct', 'set']]), 1)

    def test_proxmox_mount_option_order_is_harmless_but_other_options_are_not(self):
        wanted = '/mnt/homelab_backups/bootstrap-state,mp=/srv/homelab-backups,backup=0'
        self.assertTrue(host_nas.same_binding('/mnt/homelab_backups/bootstrap-state,backup=0,mp=/srv/homelab-backups', wanted))
        self.assertTrue(host_nas.same_binding('/mnt/homelab_backups/bootstrap-state,mp=/srv/homelab-backups', wanted))
        self.assertFalse(host_nas.same_binding(wanted + ',shared=1', wanted))
        self.assertFalse(host_nas.same_binding(wanted + ',backup=1', wanted))

    def test_restart_dhcp_wait_is_bounded_and_uses_only_the_selected_guest(self):
        calls = []
        answers = iter(['', 'fe80::1', '198.18.25.10 fe80::1'])
        def execute(args):
            calls.append(args); return next(answers)
        with patch.object(host_nas.time, 'sleep') as pause:
            self.assertEqual(host_nas.guest_addresses(4917, execute), ['198.18.25.10', 'fe80::1'])
            self.assertEqual(pause.call_count, 2)
        self.assertEqual(calls, [['pct', 'exec', '4917', '--', 'hostname', '-I']] * 3)
        with patch.object(host_nas.time, 'sleep') as pause:
            with self.assertRaisesRegex(RuntimeError, 'bounded DHCP wait'):
                host_nas.guest_addresses(4917, lambda args: '')
            self.assertEqual(pause.call_count, 29)


if __name__ == '__main__':
    unittest.main()
