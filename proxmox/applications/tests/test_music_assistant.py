"""Protect restored credentials/state and reject a stale Docker listener."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('music_profile', ROOT / 'music-assistant/profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)
from test_render import render, image


def fixture():
    return dict(kind='music-assistant', guest_memory_mib=2048, music_bind_address='198.18.100.20',
                services={'music_assistant': image()})


def settings():
    return dict(server_id='synthetic-server', onboard_done=True,
                providers={'spotify': {'domain': 'spotify', 'enabled': True,
                                      'values': {'refresh_token_global': 'synthetic-$unchanged'}}},
                players={'synthetic': {'provider': 'airplay'}},
                core={'webserver': {'values': {'bind_ip': '198.18.100.20'}},
                      'streams': {'values': {'bind_ip': '198.18.100.20',
                                            'publish_ip': '198.18.100.20'}}})


class MusicTests(unittest.TestCase):
    def test_restored_state_is_required_and_not_automatically_created(self):
        service = render.compose(fixture())['services']['music_assistant']
        self.assertEqual(service['volumes'], [{'type': 'bind',
            'source': '/srv/homelab/data/music-assistant', 'target': '/data',
            'bind': {'create_host_path': False}}])
        self.assertEqual(service['network_mode'], 'host')
        self.assertEqual(service['restart'], 'no')
        for key in ('privileged', 'cap_add', 'security_opt', 'user'):
            self.assertNotIn(key, service)
        self.assertEqual(service['healthcheck']['test'][0:2], ['CMD', 'python3'])

    def test_only_music_assistant_admits_the_requested_latest_tag(self):
        cfg = fixture(); cfg['services']['music_assistant']['image'] = 'ghcr.io/music-assistant/server:latest'
        self.assertEqual(render.compose(cfg)['services']['music_assistant']['pull_policy'], 'always')
        cfg['services']['music_assistant']['image'] = 'ghcr.io/music-assistant/server:beta'
        with self.assertRaises(ValueError): render.compose(cfg)
        from test_render import fixture as other_fixture
        other = other_fixture('automation')
        other['services']['mqtt']['image'] = 'ghcr.io/music-assistant/server:latest'
        with self.assertRaises(ValueError): render.compose(other)

    def test_player_listener_must_match_an_assigned_guest_interface(self):
        from test_deploy import fixture as guest_fixture, deploy
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cfg = guest_fixture(root)
            stack = root / 'stack.json'; stack.write_text(json.dumps(fixture()))
            cfg['app'].update(kind='music-assistant', music_address='198.18.100.20',
                              stack_config=str(stack))
            self.assertEqual(deploy.validate(cfg), 6101)
            cfg['app']['music_address'] = '198.18.100.21'
            with self.assertRaises(ValueError): deploy.validate(cfg)
            cfg['app']['music_address'] = '198.18.100.20'
            cfg['guest']['interfaces'][0]['ipv4'] = '198.18.100.22/24'
            cfg['app']['address'] = '198.18.100.22'
            with self.assertRaises(ValueError): deploy.validate(cfg)

    def test_mount_privilege_or_extra_storage_needs_separate_admission(self):
        for key, value in [('cap_add', ['SYS_ADMIN']), ('extra_mounts', [
                {'source': '/srv/homelab/data/media', 'target': '/media'}]),
                ('security_opt', ['apparmor:unconfined']), ('user', '1000:1000'),
                ('command', ['new-command']), ('privileged', True)]:
            cfg = fixture(); cfg['services']['music_assistant'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                render.compose(cfg)

    def test_stale_bind_publish_or_share_provider_is_held(self):
        good = settings(); profile.validate_settings(good, '198.18.100.20')
        cases = []
        for domain, key in [('webserver', 'bind_ip'), ('streams', 'publish_ip'), ('streams', 'bind_ip')]:
            bad = copy.deepcopy(good); bad['core'][domain]['values'][key] = '172.20.0.10'; cases.append(bad)
        bad = copy.deepcopy(good); del bad['core']['streams']; cases.append(bad)
        bad = copy.deepcopy(good); bad['providers']['nas'] = {'domain': 'filesystem_smb', 'enabled': True}; cases.append(bad)
        bad = copy.deepcopy(good); del bad['server_id']; cases.append(bad)
        bad = copy.deepcopy(good); bad['core']['webserver']['values']['bind_port'] = 9999; cases.append(bad)
        for bad in cases:
            with self.assertRaises(ValueError): profile.validate_settings(bad, '198.18.100.20')
        self.assertEqual(good, settings())

    def test_inspection_never_rewrites_state_or_follows_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'settings.json'
            data = json.dumps(settings()).encode(); path.write_bytes(data)
            for name in ('library.db', 'auth.db'): (root / name).write_bytes(b'SQLite format 3\x00')
            (root / 'playlists').mkdir()
            profile.check_directory(root, '198.18.100.20')
            self.assertEqual(path.read_bytes(), data)
            original = root / 'original'; path.rename(original); path.symlink_to(original)
            with self.assertRaises((OSError, ValueError)): profile.check_directory(root, '198.18.100.20')


if __name__ == '__main__': unittest.main()
