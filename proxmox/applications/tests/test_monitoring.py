"""A clean monitoring install cannot restore data or weaken agent/API trust."""
import copy
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring
import render
import deploy
from test_deploy import fixture as deploy_fixture


def fixture(root):
    (root / 'password').write_text('synthetic-fixture-password')
    (root / 'ca').write_text('-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n')
    return {'kind': 'monitoring', 'guest_memory_mib': 2048,
            'services': {name: {'image': monitoring.VERSIONS[name], 'memory_mib': memory,
                                'cpus': 1, 'pids_limit': 128, 'restart': 'no'}
                         for name, memory in [('zabbix_server', 768), ('zabbix_web', 512)]},
            'monitoring': {'version': monitoring.VERSIONS['version'],
                           'bind_address': '198.18.30.50', 'postgresql_host': '198.18.30.23',
                           'postgresql_database': 'zabbix', 'postgresql_user': 'zabbix',
                           'secret_files': {'database_password': str(root / 'password'),
                                            'proxmox_ca': str(root / 'ca')}}}


class MonitoringTests(unittest.TestCase):
    def test_renderer_loads_without_application_directory_on_python_path(self):
        program = "import importlib.util,sys; s=importlib.util.spec_from_file_location('standalone_render',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
        result = subprocess.run([sys.executable, '-I', '-c', program,
                                 str(Path(__file__).resolve().parents[1] / 'render.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_clean_stack_uses_file_password_and_trusted_api_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp)); document = render.compose(cfg)
            self.assertEqual(set(document['services']), {'zabbix_server', 'zabbix_web'})
            self.assertNotIn('synthetic-fixture-password', json.dumps(document))
            server = document['services']['zabbix_server']
            self.assertEqual(server['ports'], ['198.18.30.50:10051:10051'])
            self.assertTrue(any(v['target'] == '/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem' and v['read_only'] for v in server['volumes']))
            self.assertNotIn('network_mode', server)
            files = monitoring.files(cfg)
            self.assertTrue(any(f['path'] == 'database-password' and f['uid'] == 1997
                                and f['mode'] == '0400' for f in files))

    def test_no_extra_services_env_socket_or_unpinned_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            for field, value in [('image', 'zabbix/zabbix-server-pgsql:latest'),
                                 ('environment', {'ZBX_DBTLSCONNECT': 'disable'}),
                                 ('extra_mounts', [{'source': '/run/docker.sock'}])]:
                bad = copy.deepcopy(cfg); bad['services']['zabbix_server'][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError): render.compose(bad)
            for address in ('0.0.0.0', '127.0.0.1', '::', 'invalid'):
                bad = copy.deepcopy(cfg); bad['monitoring']['bind_address'] = address
                with self.subTest(address=address), self.assertRaises(ValueError): render.compose(bad)

    def test_agent_is_active_only_and_rejects_injection(self):
        value = {'hostname': 'practice-pve', 'server_active': '198.18.30.50:10051',
                 'psk_identity': 'practice-pve-unique', 'psk_path': '/etc/zabbix/agent.psk'}
        text = monitoring.agent_config(value)
        self.assertNotIn('\nServer=', text)
        self.assertNotIn('Include=', text)
        self.assertIn('TLSConnect=psk\n', text)
        self.assertIn('DenyKey=system.run[*]', text)
        for key in value:
            bad = dict(value); bad[key] += '\nServer=0.0.0.0/0'
            with self.subTest(key=key), self.assertRaises(ValueError): monitoring.agent_config(bad)

    def test_template_hashes_and_full_tls_are_pinned(self):
        monitoring.check_templates()

    def test_clean_application_is_explicit_and_hashes_secret_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = deploy_fixture(root); stack = fixture(root)
            stack['monitoring']['bind_address'] = cfg['app']['address']
            stack['guest_memory_mib'] = cfg['app']['memory_mib']
            path = root / 'stack.json'; path.write_text(json.dumps(stack))
            cfg['app'].update(kind='monitoring', installation='clean', stack_config=str(path))
            self.assertEqual(deploy.validate(cfg), 6101)
            (root / 'ca').write_text('synthetic trusted CA')
            hashes = deploy.input_hashes(cfg)
            (root / 'password').write_text('changed password')
            self.assertNotEqual(deploy.input_hashes(cfg), hashes)
            for field, value in [('installation', 'restore'), ('capture', {})]:
                bad = copy.deepcopy(cfg); bad['app'][field] = value
                with self.subTest(field=field), self.assertRaises(deploy.InputNeeded): deploy.validate(bad)


if __name__ == '__main__':
    unittest.main()
