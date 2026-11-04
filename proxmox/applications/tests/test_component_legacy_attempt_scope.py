"""Real attempt selection -> legacy continuity, with synthetic owned proof files.

The constructor and continuity readers run unchanged; no attempt is entered and
no lock, controller writer, subprocess, credential store or native executor runs.
"""
import copy
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_continuity as continuity
import component_private_material as material
import initial_ordinary
import private_io as io
from deployment_state import DeploymentAttempt
from custody_fixtures import CompletedGroup
from fixtures import guest
from test_component_private_material import telemetry


class LegacyAttemptScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)

    def standalone(self, role, *, token=False):
        root = self.root / (role + ('-token' if token else ''))
        root.mkdir(mode=0o700)
        cfg = guest(root)
        cfg['schema'] = 'homelab-component-guest-v1'
        cfg['app']['kind'] = role
        hashes = {}
        def save(name, value):
            path = root / name
            io.write_new(path, value)
            hashes[str(path)] = io.sha(path)
            return str(path)
        if role == 'zigbee2mqtt':
            selected, options = telemetry()
            values = {'options': io.encoded(options)}
            settings = copy.deepcopy(selected['settings'])
            settings['configuration_file'] = save('options.json', values['options'])
            stack = {'winet': settings}
            schema = initial_ordinary.ZIGBEE_SCHEMA
        else:
            selected = {'adapter': 'node_red', 'settings': {}, 'input_sources': {}}
            values = {'api_token': b'synthetic-existing-token'} if token else {}
            if token:
                selected['input_sources']['api_token'] = {'type': 'environment', 'name': 'EXISTING_TOKEN'}
            environment = {'FLOWS': 'flows.json'}
            if token:
                environment['NODE_RED_API_TOKEN'] = values['api_token'].decode()
            stack = {'services': {'node_red': {'environment': environment}}}
            schema = initial_ordinary.AUTOMATION_SCHEMA
        selected.update(id='owned-app', lifecycle='retained')
        old = copy.deepcopy(cfg)
        old['app'] = {'stack_config': save('stack.json', io.encoded(stack))}
        installed = save('site.json', io.encoded(old))
        cfg['initial_ordinary'] = {
            'schema': schema, 'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node'],
            'installed_site': installed, 'installed_site_sha256': io.sha(installed),
            'initial_state_sha256': 'a' * 64, 'incomplete_operations': [],
            'receipt': {'operation': 'ordinary-100-1', 'sha256': 'b' * 64,
                        'immutable_sha256': 'c' * 64, 'source_sha256': 'd' * 64}}
        attempt = DeploymentAttempt(cfg, None, ['preparation', 'selected'],
                                    prepare_inputs=lambda allow: None)
        attempt.work.mkdir(parents=True, mode=0o700)
        receipt = {'status': 'passed', 'binding': {
            'vmid': cfg['guest']['vmid'], 'site_sha256': io.sha(installed),
            'source_sha256': 'd' * 64, 'blueprint_sha256': 'e' * 64,
            'input_hashes': {key: value for key, value in hashes.items() if key != installed}}}
        io.write_new(attempt.receipt, io.encoded(receipt))
        return attempt, selected, values, receipt

    def guarded(self):
        contexts = ExitStack()
        for target in ('private_io.private_writer', 'component_payload.prepare',
                       'deployment_state.fcntl.flock', 'subprocess.Popen',
                       'socket.create_connection'):
            contexts.enter_context(patch(target, side_effect=AssertionError('No writer, lock, process or target')))
        return contexts

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.stat().st_ino, path.stat().st_mode,
                path.read_bytes()) for path in self.root.rglob('*') if path.is_file()}

    def test_real_radio_and_automation_attempts_use_canonical_installed_site_for_continuity(self):
        for role, token in (('zigbee2mqtt', False), ('automation', False), ('automation', True)):
            with self.subTest(role=role, token=token):
                attempt, selected, values, receipt = self.standalone(role, token=token)
                self.assertNotIn('installed_site', attempt.initial_selection)
                self.assertEqual(set(attempt.initial_selection), {'vmid', 'node',
                    'initial_state_sha256', 'initial_ordinary', 'incomplete_operations'})
                canonical = attempt.cfg['initial_ordinary']['installed_site']
                before = self.snapshot()
                with self.guarded(), patch.object(continuity, '_read', wraps=continuity._read) as reads:
                    continuity.verify(attempt, selected,
                        continuity.document(selected, material.project(selected, values)))
                self.assertIn(unittest.mock.call(canonical), reads.call_args_list)
                self.assertEqual(before, self.snapshot())
                self.assertFalse(attempt.hold.exists())
                self.assertEqual(io.read_json(attempt.receipt), receipt)

    def test_real_group_attempts_keep_exact_member_locator_without_initial_selection(self):
        for postgres in (False, True):
            root = self.root / ('postgres' if postgres else 'maria')
            root.mkdir(mode=0o700)
            group = CompletedGroup(root, postgres=postgres)
            for role, cfg in group.cfgs.items():
                with self.subTest(role=role):
                    cfg = copy.deepcopy(cfg)
                    cfg['schema'] = 'homelab-component-guest-v1'
                    attempt = DeploymentAttempt(cfg, None, ['preparation'], prepare_inputs=lambda allow: None)
                    self.assertIsNone(attempt.initial_selection)
                    installed = group.group['members'][role]['installed_site']
                    before = self.snapshot()
                    with self.guarded(), patch.object(continuity, '_read', wraps=continuity._read) as reads:
                        actual = continuity._legacy_site(attempt, {'binding': {
                            'site_sha256': io.sha(installed), 'input_hashes': {}}})
                    self.assertEqual(reads.call_args_list, [unittest.mock.call(installed)])
                    self.assertEqual(actual, io.read_json(installed))
                    self.assertEqual(before, self.snapshot())

    def test_actual_attempt_refuses_malformed_initial_selection_before_any_legacy_read(self):
        attempt, _, _, _ = self.standalone('zigbee2mqtt')
        mutations = [lambda cfg: cfg['initial_ordinary'].pop('installed_site'),
            lambda cfg: cfg['initial_ordinary'].update(installed_site='relative/site.json'),
            lambda cfg: cfg['initial_ordinary'].update(node='foreign-node'),
            lambda cfg: cfg['initial_ordinary'].update(vmid=999),
            lambda cfg: cfg['initial_ordinary'].update(extra=True)]
        before = self.snapshot()
        for mutate in mutations:
            cfg = copy.deepcopy(attempt.cfg)
            mutate(cfg)
            with self.subTest(mutate=mutate), self.guarded(), \
                 patch.object(continuity, '_read', side_effect=AssertionError('No legacy read')), \
                 self.assertRaises(ValueError):
                DeploymentAttempt(cfg, None, ['preparation'], prepare_inputs=lambda allow: None)
        self.assertEqual(before, self.snapshot())

    def test_actual_standalone_attempt_retains_site_hash_owner_and_material_refusals(self):
        attempt, selected, values, receipt = self.standalone('zigbee2mqtt')
        installed = Path(attempt.cfg['initial_ordinary']['installed_site'])
        original = installed.read_bytes()
        wrong_hash = copy.deepcopy(receipt)
        wrong_hash['binding']['site_sha256'] = 'f' * 64
        with self.guarded(), self.assertRaisesRegex(ValueError, 'hash-bound compiled site'):
            continuity.legacy(attempt, wrong_hash, selected)
        for section, key, value in (('site', 'node', 'foreign-node'),
                                    ('guest', 'vmid', 999), ('guest', 'hostname', 'foreign-host')):
            old = io.decode_json(original)
            old[section][key] = value
            installed.write_bytes(io.encoded(old))
            changed = copy.deepcopy(receipt)
            changed['binding']['site_sha256'] = io.sha(installed)
            with self.subTest(key=key), self.guarded(), self.assertRaisesRegex(ValueError, 'guest owner'):
                continuity.legacy(attempt, changed, selected)
        installed.write_bytes(original)
        options = Path(next(path for path in receipt['binding']['input_hashes'] if path.endswith('options.json')))
        options.write_bytes(options.read_bytes() + b' ')
        with self.guarded(), self.assertRaisesRegex(ValueError, 'source changed'):
            continuity.verify(attempt, selected,
                continuity.document(selected, material.project(selected, values)))
        self.assertFalse(attempt.hold.exists())


if __name__ == '__main__':
    unittest.main()
