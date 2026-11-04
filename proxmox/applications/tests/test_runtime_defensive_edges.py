"""Finite helper refusals over owned files; no service or target is contacted."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
import component_payload
import deployment_state
import monitoring_agent
import music_assistant
import ordinary_failure
from private_io import encoded, write_new
from test_component_monitoring_agent import component
from test_music_mqtt import settings


class HelperRefusalTests(unittest.TestCase):
    def test_monitoring_invalid_ip_literals_refuse_before_the_config_formatter(self):
        for address in ('not-an-ip', '198.18.1.999'):
            selected = component()
            selected['app']['monitoring']['server_active'] = address + ':10051'
            with self.subTest(address=address), patch.object(monitoring_agent.monitoring, 'agent_config') as formatter, \
                 self.assertRaisesRegex(ValueError, '^Use one private active server on TCP10051$'):
                monitoring_agent.configuration(selected)
            formatter.assert_not_called()
        for field, value in [('postgresql_address', None), ('influxdb_address', 'invalid')]:
            selected = component('monitoring', True)
            selected['app']['monitoring'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^Use only selected private monitoring endpoints$'):
                monitoring_agent.validate(selected)

    def test_root_monitoring_can_omit_unselected_influx_member_without_inference(self):
        selected = component('monitoring', True)
        selected['app']['monitoring'].pop('influxdb_address')
        selected['app']['monitoring']['members'] = [selected['app']['monitoring']['members'][0]]
        before = copy.deepcopy(selected)
        self.assertEqual(monitoring_agent.validate(selected), selected['app']['monitoring'])
        self.assertEqual(selected, before)


    def test_music_opened_playlists_metadata_must_still_describe_a_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'playlists').mkdir()
            (root / 'settings.json').write_text(json.dumps(settings()))
            for name in ('library.db', 'auth.db'):
                (root / name).write_bytes(b'SQLite format 3\x00synthetic')
            before = {path.name: (path.stat().st_ino, path.read_bytes()) for path in root.iterdir() if path.is_file()}
            inode = (root / 'playlists').stat().st_ino
            original = music_assistant.os.fstat
            def changed(fd):
                info = original(fd)
                return SimpleNamespace(st_mode=stat.S_IFREG) if info.st_ino == inode else info
            with patch.object(music_assistant.os, 'fstat', side_effect=changed), \
                 self.assertRaisesRegex(ValueError, 'playlists directory'):
                music_assistant.check_bound_directory(str(root), '198.18.100.241')
            self.assertEqual({path.name: (path.stat().st_ino, path.read_bytes()) for path in root.iterdir() if path.is_file()}, before)

    def test_explorer_partial_directory_creation_closes_both_descriptors_and_never_repairs(self):
        spec = importlib.util.spec_from_file_location('defensive_explorer_state', APP / 'mqtt_explorer_state.py')
        state = importlib.util.module_from_spec(spec); spec.loader.exec_module(state)
        with tempfile.TemporaryDirectory() as temporary:
            selected = Path(temporary).resolve() / 'new-workspace'; observed = []
            original_open = state.os.open
            def opened(name, flags, *args, **kwargs):
                fd = original_open(name, flags, *args, **kwargs)
                observed.append(fd)
                return fd
            with patch.object(state.os, 'open', side_effect=opened), \
                 patch.object(state.os, 'fchmod', side_effect=OSError('synthetic mode failure')), \
                 self.assertRaisesRegex(OSError, 'synthetic mode failure'):
                with state.directory(selected, create=True):
                    self.fail('Failed publication must not yield an adopted directory')
            self.assertTrue(selected.is_dir())
            self.assertEqual(list(selected.iterdir()), [])
            for fd in observed:
                with self.assertRaises(OSError):
                    os.fstat(fd)


class HistoricalPhaseBytes(unittest.TestCase):
    def test_legacy_current_binding_refuses_before_state_directory_or_lock_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            cfg = {'schema': 'homelab-component-guest-v1', 'guest': {'vmid': 610},
                   'paths': {'state_root': str(root / 'state')}}
            attempt = deployment_state.DeploymentAttempt(cfg, {'vmid': 610, 'input_hashes': {}}, ['preparation'])
            with self.assertRaisesRegex(ValueError, 'closed component ordinary binding'):
                with attempt:
                    self.fail('A historical binding cannot start a new attempt')
            self.assertEqual(list(root.iterdir()), [])

    def test_absent_bootstrap_root_requires_no_creation_or_marker_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'absent-bootstrap'
            deployment_state.bootstrap_closed(root)
            self.assertFalse(root.exists())

    def test_old_phase_start_keeps_exact_raw_equality(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve(); raw = b'{ "historical": true }\n'
            write_new(path / 'service-started.json', raw)
            held = {'binding': {'vmid': 610}}
            ordinary_failure.phase_start(None, path, {'phase': 'service'}, held, raw)
            with self.assertRaisesRegex(ValueError, 'completed infrastructure checkpoint'):
                ordinary_failure.phase_start(None, path, {'phase': 'service'}, held, raw + b' ')
            self.assertEqual((path / 'service-started.json').read_bytes(), raw)

    def test_component_preparation_has_no_payload_and_keeps_exact_hold_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()
            binding = {'schema': component_payload.BINDING_SCHEMA, 'vmid': 610, 'site_sha256': 'a' * 64,
                'source_sha256': 'b' * 64, 'input_identity': 'c' * 64,
                'app_inputs_directory': str(path / 'applications'), 'input_hashes': {}}
            held = {'binding': binding, 'operation': str(path), 'automatic_retry': False,
                'workflow': ['example/site', 'example/site/.github/workflows/deploy.yml'],
                'run_number': 1, 'site_revision': 'd' * 40, 'previous_ordinary_sha256': 'e' * 64}
            raw = encoded(held); started = path / 'preparation-started.json'
            write_new(started, raw)
            with patch.object(component_payload.AppPayload, 'load') as payload:
                ordinary_failure.phase_start(None, path, {'phase': 'preparation'}, held, raw)
            payload.assert_not_called()
            started.write_bytes(encoded(dict(held, phase_inputs=None)))
            with self.assertRaisesRegex(ValueError, 'failed preparation input boundary'):
                ordinary_failure.phase_start(None, path, {'phase': 'preparation'}, held, raw)


if __name__ == '__main__':
    unittest.main()
