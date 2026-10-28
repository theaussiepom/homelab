"""Cross-bind runtime changes to the exact saved network operation before stops."""
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_worker as worker
from test_database_network_server import contract


class Tests(unittest.TestCase):
    def setUp(self):
        self.catalogue = contract()
        self.request = {'engine': 'postgresql', 'phase': 'cutover', 'client_vmids': [211,202],
                        'legacy_server_address': '10.88.30.23'}
        self.context = {'request': self.request, 'catalogue_raw': json.dumps(self.catalogue).encode()}
        self.runtime = {'endpoint': {'address': '10.88.31.23', 'port': 5432},
                        'old_address': '10.88.30.23', 'clients': [dict(c) for c in sorted(
                            self.catalogue['networks']['postgresql']['clients'], key=lambda c:c['vmid'])
                            if c['vmid'] in (211,202)]}

    def bind(self, packet=None):
        worker.bind_runtime('postgresql', packet or self.runtime, self.context, Path('/adapter'), [211,202])

    def test_exact_server_endpoint_and_two_selected_clients_are_accepted(self):
        self.bind()

    def test_future_client_cannot_be_granted_by_a_valid_but_different_saved_plan(self):
        self.request['client_vmids'].append(213)
        with self.assertRaises(ValueError): self.bind()

    def test_wrong_runtime_new_or_old_endpoint_or_future_client_is_refused(self):
        for mutate in (lambda p:p['endpoint'].update(address='10.88.99.23'),
                       lambda p:p.update(old_address='10.88.30.24'),
                       lambda p:p['clients'].append(dict(vmid=213, address='10.88.31.27'))):
            value = copy.deepcopy(self.runtime); mutate(value)
            with self.assertRaises(ValueError): self.bind(value)

    def test_non_cutover_or_other_database_request_is_refused(self):
        for key, value in [('phase','additive'), ('engine','mariadb')]:
            with patch.dict(self.request, {key:value}), self.assertRaises(ValueError): self.bind()

    def test_client_owned_binding_guard_is_required_and_receives_exact_group(self):
        validator = Mock(return_value=True)
        module = types.SimpleNamespace(validate_binding=validator)
        with patch.object(worker.importlib, 'import_module', return_value=module):
            worker.bind_runtime('identity', {'private':'runtime'}, self.context, Path('/adapter'), [211,202])
        validator.assert_called_once_with({'private':'runtime'}, self.catalogue, [202,211], '10.88.30.23')
        validator.return_value = False
        with patch.object(worker.importlib, 'import_module', return_value=module), self.assertRaises(ValueError):
            worker.bind_runtime('identity', {}, self.context, Path('/adapter'), [211,202])

    def test_pgadmin_resume_uses_the_exact_quiesce_phase_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); receipt = directory / 'quiesce.json'
            value = {'phase':'quiesce', 'role':'db-tools', 'result': {'status':'passed',
                     'action':'quiesce', 'quiesced': {'request_sha256':'a'*64}}}
            worker.maintenance.write_new(receipt, worker.encoded(value))
            cfg = {'app':{'kind':'db-tools'}}; member = {'runtime_packet':{'original':'binding'}}
            captured = []
            def ansible(deployment, cfg, source, playbook, variables, output, action):
                captured.append(variables)
                worker.maintenance.write_new(Path(variables['database_network_result_path']),
                                              b'{"status":"passed"}')
            with patch.object(worker, 'ansible', side_effect=ansible):
                worker.runtime(None, cfg, Path('/adapter'), 'db-tools', member, directory, 'activate', receipt)
            self.assertEqual(captured[0]['database_network_request'],
                {'original':'binding', 'quiesced':{'request_sha256':'a'*64}})
            self.assertEqual(member, {'runtime_packet':{'original':'binding'}})
            value['role'] = 'identity'; receipt.unlink()
            worker.maintenance.write_new(receipt, worker.encoded(value))
            with patch.object(worker, 'ansible') as remote, self.assertRaises(ValueError):
                worker.runtime(None, cfg, Path('/adapter'), 'db-tools', member, directory, 'activate', receipt)
            remote.assert_not_called()

    def test_pgadmin_missing_quiesce_receipt_is_not_an_implicit_resume(self):
        with patch.object(worker, 'ansible') as remote, self.assertRaises(ValueError):
            worker.runtime(None, {'app':{}}, Path('/adapter'), 'db-tools',
                           {'runtime_packet':{}}, Path('/private'), 'activate')
        remote.assert_not_called()

    def test_authentik_original_compose_requires_exact_private_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            raw = b'private synthetic compose\n'
            member = {'runtime_packet': {'compose_sha256': worker.digest(raw)}}
            with self.assertRaises(FileNotFoundError):
                worker.identity_recovery(member, directory)
            worker.save(directory / 'identity-original-compose.yml', raw)
            self.assertEqual(worker.identity_recovery(member, directory), raw)
            (directory / 'identity-original-compose.yml').chmod(0o644)
            with self.assertRaises(ValueError): worker.identity_recovery(member, directory)
            (directory / 'identity-original-compose.yml').chmod(0o600)
            with self.assertRaises(ValueError):
                worker.identity_recovery({'runtime_packet': {'compose_sha256': 'f'*64}}, directory)

    def test_authentik_capture_stays_private_and_never_returns_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); raw = b'private synthetic compose\n'
            member = {'runtime_packet': {'compose_sha256': worker.digest(raw)}}
            cfg = {'guest': {'vmid':211}, 'app': {'address':'192.0.2.20'}, 'paths': {'private_key':'/key', 'known_hosts':'/known'}}
            deployment = types.SimpleNamespace(guest_trust=Mock())
            with patch.object(worker.subprocess, 'run', return_value=types.SimpleNamespace(stdout=raw)) as remote:
                result = worker.capture_identity_recovery(deployment, cfg, member, directory)
            self.assertEqual(result, worker.digest(raw))
            self.assertEqual(worker.identity_recovery(member, directory), raw)
            self.assertNotIn(raw.decode(), str(remote.call_args))
            self.assertIn('StrictHostKeyChecking=yes', remote.call_args.args[0])
            self.assertNotIn('scp', remote.call_args.args[0])

    def test_authentik_wrong_capture_is_refused_without_writing_a_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            member = {'runtime_packet': {'compose_sha256': 'a'*64}}
            cfg = {'guest': {'vmid':211}, 'app': {'address':'192.0.2.20'}, 'paths': {'private_key':'/key', 'known_hosts':'/known'}}
            deployment = types.SimpleNamespace(guest_trust=Mock())
            with patch.object(worker.subprocess, 'run', return_value=types.SimpleNamespace(stdout=b'changed')):
                with self.assertRaises(ValueError):
                    worker.capture_identity_recovery(deployment, cfg, member, directory)
            self.assertFalse((directory / 'identity-original-compose.yml').exists())

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'The offline Linux image supplies root-owned synthetic files')
    def test_fixed_reader_enforces_ownership_mode_links_size_and_digest_on_synthetic_files(self):
        actual_run = subprocess.run
        raw = b'services: {} # synthetic, no application settings\n'
        cfg = {'guest': {'vmid':211}, 'app': {'address':'192.0.2.20'},
               'paths': {'private_key':'/unused-key', 'known_hosts':'/unused-known-hosts'}}
        deployment = types.SimpleNamespace(guest_trust=Mock())
        for case in ('valid', 'owner', 'mode', 'links', 'size', 'digest'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); directory = root / 'custody'; directory.mkdir(mode=0o700)
                source = root / 'synthetic-compose.yml'; source.write_bytes(raw); source.chmod(0o600)
                member = {'runtime_packet': {'compose_sha256': worker.digest(raw)}}
                if case == 'owner': os.chown(source, 1, 1)
                if case == 'mode': source.chmod(0o644)
                if case == 'links': os.link(source, root / 'extra-link')
                if case == 'size': source.write_bytes(b'x' * (1024 * 1024 + 1))
                if case == 'digest': member['runtime_packet']['compose_sha256'] = 'f' * 64
                def local_reader(argv, **kwargs):
                    # SSH is never executed. Only its fixed Python reader runs
                    # against this disposable synthetic file inside the test image.
                    command = shlex.split(argv[-1]); self.assertEqual(command[:2], ['python3', '-c'])
                    literal = "'/opt/homelab-app/compose.yml'"
                    self.assertEqual(command[2].count(literal), 1)
                    script = command[2].replace(literal, repr(str(source)))
                    return actual_run([sys.executable, '-c', script], input=kwargs['input'],
                                      capture_output=True, check=True, timeout=5)
                with patch.object(worker.subprocess, 'run', side_effect=local_reader):
                    if case == 'valid':
                        self.assertEqual(worker.capture_identity_recovery(deployment, cfg, member, directory),
                                         worker.digest(raw))
                        self.assertEqual(worker.identity_recovery(member, directory), raw)
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            worker.capture_identity_recovery(deployment, cfg, member, directory)
                        self.assertFalse((directory / 'identity-original-compose.yml').exists())


if __name__ == '__main__': unittest.main()
