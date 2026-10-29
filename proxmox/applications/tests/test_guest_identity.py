"""A network key is accepted only after independently trusted PVE evidence."""
import base64
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_identity as identity


def public_key(byte=1):
    return base64.b64encode(struct.pack('!I', 11) + b'ssh-ed25519' + struct.pack('!I', 32) + bytes([byte]) * 32).decode()


class IdentityTests(unittest.TestCase):
    def setup_fixture(self, root):
        cfg = {'site': {'node': 'practice-pve'},
               'guest': {'vmid': 6101, 'hostname': 'practice-dns', 'interfaces': [
                   {'mac': '02:00:00:00:61:01', 'bridge': 'vmbr0', 'vlan': 40}]},
               'app': {'mac': '02:00:00:00:61:01'},
               'paths': {'known_hosts': str(root / 'hosts'), 'api_token': str(root / 'api')}}
        (root / 'hosts').touch(mode=0o600)
        (root / 'api').write_text('fixture@pve!deploy=synthetic')
        (root / 'plan.json').write_text(json.dumps({'plan_sha256': '1' * 64}))
        (root / 'apply-window.json').write_text(json.dumps({'plan_sha256': '1' * 64,
            'started_at_ns': 1_700_000_000_000_000_000, 'finished_at_ns': 1_700_000_010_000_000_000}))
        self.config = {'hostname': 'practice-dns', 'protection': 1, 'unprivileged': 1,
                       'net0': 'name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:61:01,tag=40'}
        self.interfaces = [{'hwaddr': '02:00:00:00:61:01', 'inet': '198.18.100.42/24'}]
        self.tasks = [{'node': 'practice-pve', 'id': '6101', 'type': 'vzcreate',
                       'user': 'fixture@pve', 'tokenid': 'deploy', 'status': 'OK',
                       'starttime': 1_700_000_001, 'endtime': 1_700_000_009, 'upid': 'synthetic-creation'}]
        self.log = [{'n': 3, 't': "Creating SSH host key 'ssh_host_ed25519_key' - this may take some time ..."},
                    {'n': 4, 't': 'done: ' + identity.fingerprint(public_key()) + ' root@practice-dns'}]
        self.calls = []
        return cfg

    def fetch(self, path):
        self.calls.append(path)
        if path.endswith('/config'): return self.config
        if path.endswith('/interfaces'): return self.interfaces
        if '/log?' in path: return self.log
        if '/tasks?' in path: return self.tasks
        self.fail('Unexpected API resource')

    def command(self, argv, **kwargs):
        if argv[0] == 'ssh-keygen': return subprocess.CompletedProcess(argv, 1, '', '')
        return subprocess.CompletedProcess(argv, 0, '198.18.100.42 ssh-ed25519 ' + public_key() + '\n', '')

    @staticmethod
    def persist(path, value):
        path.write_text(json.dumps(value))

    def test_first_key_is_pinned_only_after_matching_own_successful_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = self.setup_fixture(root)
            with patch.object(identity.subprocess, 'run', side_effect=self.command):
                result = identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
            self.assertEqual(result['fingerprint'], identity.fingerprint(public_key()))
            self.assertIn(public_key(), (root / 'hosts').read_text())
            self.assertEqual(result['source'], 'synthetic-creation')
            self.assertEqual((root / 'hosts').stat().st_mode & 0o777, 0o600)

    def test_untagged_interface_is_supported_without_inventing_a_vlan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = self.setup_fixture(root)
            cfg['guest']['interfaces'][0]['vlan'] = None
            self.config['net0'] = self.config['net0'].replace(',tag=40', '')
            with patch.object(identity.subprocess, 'run', side_effect=self.command):
                identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)

    def test_wrong_key_cannot_write_trust_or_a_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = self.setup_fixture(root)
            def wrong(argv, **kwargs):
                result = self.command(argv, **kwargs)
                if argv[0] == 'ssh-keyscan': result.stdout = result.stdout.replace(public_key(), public_key(2))
                return result
            with patch.object(identity.subprocess, 'run', side_effect=wrong), self.assertRaises(ValueError):
                identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
            self.assertEqual((root / 'hosts').read_text(), '')
            self.assertFalse((root / 'host-key-evidence.json').exists())

    def test_append_refuses_to_join_an_unterminated_existing_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = self.setup_fixture(root)
            original = '198.18.100.99 ssh-ed25519 ' + public_key(2)
            (root / 'hosts').write_text(original)
            with patch.object(identity.subprocess, 'run', side_effect=self.command), self.assertRaisesRegex(ValueError, 'newline'):
                identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
            self.assertEqual((root / 'hosts').read_text(), original)
            self.assertFalse((root / 'host-key-evidence.json').exists())

    def test_other_guest_creator_old_task_failed_task_and_ambiguity_are_refused(self):
        for field, value in [('id', '6102'), ('node', 'other-pve'), ('tokenid', 'other'),
                             ('user', 'other@pve'), ('starttime', 1), ('status', 'failed'), ('duplicate', True)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); cfg = self.setup_fixture(root)
                if field == 'duplicate': self.tasks.append(copy.deepcopy(self.tasks[0]))
                else: self.tasks[0][field] = value
                with patch.object(identity.subprocess, 'run', side_effect=self.command) as run, self.assertRaises(ValueError):
                    identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
                self.assertFalse(any(call.args[0][0] == 'ssh-keyscan' for call in run.call_args_list))
                self.assertEqual((root / 'hosts').read_text(), '')

    def test_different_mac_vlan_or_address_stops_before_any_ssh(self):
        for change in ('mac', 'vlan', 'address'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); cfg = self.setup_fixture(root)
                if change == 'mac': self.config['net0'] = self.config['net0'].replace('61:01', '61:02')
                elif change == 'vlan': self.config['net0'] = self.config['net0'].replace('tag=40', 'tag=41')
                else: self.interfaces[0]['inet'] = '198.18.100.43/24'
                with patch.object(identity.subprocess, 'run') as run, self.assertRaises(ValueError):
                    identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
                run.assert_not_called()

    def test_existing_key_is_preserved_and_does_not_require_a_new_creation_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = self.setup_fixture(root)
            line = '198.18.100.42 ssh-ed25519 ' + public_key() + '\n'
            (root / 'hosts').write_text(line)
            def existing(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, line, '')
            with patch.object(identity.subprocess, 'run', side_effect=existing):
                result = identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
            self.assertEqual(result['source'], 'existing-pinned-key')
            self.assertEqual((root / 'hosts').read_text(), line)
            self.assertFalse(any('/tasks?' in path for path in self.calls))

    def test_incomplete_fingerprint_and_invalid_key_blob_are_refused(self):
        self.assertRaises(ValueError, identity.creation_fingerprint, [])
        self.assertRaises(ValueError, identity.fingerprint, base64.b64encode(b'not-an-SSH-key').decode())


    def test_hardlinked_host_trust_cannot_be_mutated_by_new_guest_pinning(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = self.setup_fixture(root)
            original = b"198.18.100.99 ssh-ed25519 " + public_key(2).encode() + b"\n"
            hosts = root / "hosts"
            hosts.write_bytes(original)
            os.link(hosts, root / "retained-trust")
            with (
                patch.object(identity.subprocess, "run", side_effect=self.command),
                self.assertRaises(ValueError),
            ):
                identity.pin(cfg, root, "198.18.100.42", self.fetch, self.persist)
            self.assertEqual(hosts.read_bytes(), original)
            self.assertEqual((root / "retained-trust").read_bytes(), original)
            self.assertFalse((root / "host-key-evidence.json").exists())

    def test_removed_or_replaced_host_trust_is_never_recreated_or_appended(self):
        for replace in (False, True):
            with self.subTest(replace=replace), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = self.setup_fixture(root)
                hosts = root/'hosts'
                original = ('198.18.100.99 ssh-ed25519 '+public_key(2)+'\n').encode()
                hosts.write_bytes(original)
                def replace_during_scan(argv, **kwargs):
                    result = self.command(argv, **kwargs)
                    if argv[0] == 'ssh-keyscan':
                        hosts.rename(root/'retained-trust')
                        if replace:
                            hosts.write_bytes(b'')
                            hosts.chmod(0o600)
                    return result
                with patch.object(identity.subprocess,'run',side_effect=replace_during_scan), self.assertRaises((ValueError, FileNotFoundError)):
                    identity.pin(cfg, root, '198.18.100.42', self.fetch, self.persist)
                self.assertEqual((root/'retained-trust').read_bytes(), original)
                self.assertEqual(hosts.exists(), replace)
                if replace:
                    self.assertEqual(hosts.read_bytes(), b'')
                self.assertFalse((root/'host-key-evidence.json').exists())


if __name__ == '__main__':
    unittest.main()
