from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import os
import json
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_profiles as profiles
import monitoring_templates as templates


class ProfileTests(unittest.TestCase):
    def test_only_selected_profiles_and_explicit_docker_access(self):
        self.assertEqual(profiles.templates(['linux', 'docker']),
            ['Linux by Zabbix agent active', 'HomeLab Docker by active agent 2'])
        for value in ([], ['unknown'], ['docker', 'docker']):
            with self.assertRaises(ValueError): profiles.selected(value)
        with self.assertRaises(ValueError): profiles.plugin_config({'docker': {}})
        self.assertIn('Plugins.Docker.Endpoint=unix:///var/run/docker.sock',
                      profiles.plugin_config({'docker': {'socket_access_approved': True}}))

    def test_db_passwords_stay_in_local_named_sessions_not_server_macros(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'password'; path.write_text('synthetic-monitor-password-long-enough'); path.chmod(0o600)
            value = profiles.plugin_config({'postgresql': {'uri': 'tcp://127.0.0.1:5432', 'password_file': str(path)}, 'mysql': {'uri': 'tcp://127.0.0.1:3306', 'password_file': str(path)}})
            self.assertIn('Plugins.PostgreSQL.Sessions.homelab.User=zbx_monitor', value)
            self.assertIn('Plugins.Mysql.Sessions.homelab.Uri=tcp://127.0.0.1:3306', value)
            self.assertNotIn(path.read_text(), str(profiles.host_macros(['postgresql', 'mysql'])))
            path.write_text('x' * 32 + '\nUserParameter=unsafe,anything')
            with self.assertRaises(ValueError): profiles.plugin_config({'mysql': {'uri': 'tcp://127.0.0.1:3306', 'password_file': str(path)}})

    def test_remote_injection_and_http_token_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'password'; path.write_text('x' * 32); path.chmod(0o600)
            for uri in ['tcp://8.8.8.8:5432', 'tcp://0.0.0.0:5432', 'tcp://169.254.1.2:5432',
                        'tcp://127.0.0.1:3306', 'tcp://user:secret@127.0.0.1:5432',
                        'tcp://127.0.0.1:5432/db', 'tcp://127.0.0.1:5432?parameter=value']:
                with self.subTest(uri=uri), self.assertRaises(ValueError):
                    profiles.plugin_config({'postgresql': {'uri':uri, 'password_file':str(path)}})
            with self.assertRaises(ValueError): profiles.host_profile({'profiles':['influxdb'], 'settings':{}})
            with self.assertRaises(ValueError): profiles.host_profile({'profiles':['influxdb'], 'settings':{'influxdb':{'url':'http://db.example.invalid', 'token_file':str(path)}}})
            result = profiles.host_profile({'profiles':['influxdb'], 'settings':{'influxdb':{'url':'https://db.example.invalid', 'token_file':str(path)}}})
            self.assertEqual(result['profile_macros'][-1]['type'], 'secret')
            document = templates.prepared('template_db_influxdb_http.yaml')
            self.assertTrue(list(templates.http_agents(document)))
            self.assertTrue(all(item['verify_peer'] == item['verify_host'] == 'YES' for item in templates.http_agents(document)))

    def test_cli_cannot_print_database_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'password'; path.write_text('synthetic-monitor-password-long-enough'); path.chmod(0o600)
            config = {'postgresql': {'uri':'tcp://127.0.0.1:5432','password_file':str(path)}}
            result = subprocess.run([sys.executable,str(Path(profiles.__file__)),'--plugin-config'],
                input=json.dumps(config),capture_output=True,text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(path.read_text(), result.stdout + result.stderr)

    def test_ansible_renders_private_sessions_in_memory_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); secret=root/'password'; secret.write_text('synthetic-monitor-password-long-enough'); secret.chmod(0o600)
            play=root/'render.json'
            play.write_text(json.dumps([{'hosts':'localhost','gather_facts':False,'tasks':[
                {'ansible.builtin.set_fact':{'rendered':'{{ workloads | homelab_monitoring_plugins }}'},'no_log':True},
                {'ansible.builtin.assert':{'that':["'Plugins.PostgreSQL.Sessions.homelab.User=zbx_monitor' in rendered", "expected in rendered"]},'no_log':True}]}]))
            variables={'expected':secret.read_text(),'workloads':{'postgresql':{'uri':'tcp://127.0.0.1:5432','password_file':str(secret)}}}
            result=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(play),'-e',json.dumps(variables)],
                env=dict(os.environ,ANSIBLE_FILTER_PLUGINS=str(Path(profiles.__file__).parent/'ansible/filter_plugins'),
                         ANSIBLE_LOCAL_TEMP=str(root/'ansible')),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout + result.stderr)
            self.assertNotIn(secret.read_text(), result.stdout + result.stderr)

    def test_postgresql_account_preflight_rejects_lan_before_a_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); play=root/'preflight.json'
            tasks=Path(profiles.__file__).parents[1]/'common/ansible/zabbix-database-account.yml'
            play.write_text(json.dumps([{'hosts':'localhost','gather_facts':False,'tasks':[{'ansible.builtin.import_tasks':str(tasks)}]}]))
            variables={'zabbix_agent':{'manage_database_accounts':True,'workloads':{'postgresql':{'uri':'tcp://198.18.30.21:5432','password_file':'/absent/password'}}}}
            result=subprocess.run(['ansible-playbook','-i','localhost,','-c','local',str(play),'-e',json.dumps(variables)],
                env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(root/'ansible')),capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('PostgreSQL account commissioning requires the preapproved loopback session',result.stdout)
            self.assertNotIn('Inspect the retained database monitoring receipt',result.stdout)

    def test_docker_copy_has_distinct_identity_and_no_passive_collectors(self):
        value = templates.prepared('template_app_docker.yaml')
        original = templates.yaml.safe_load((templates.monitoring.ROOT / 'templates/template_app_docker.yaml').read_text())
        copied = value['zabbix_export']['templates'][0]
        self.assertEqual(copied['template'], 'HomeLab Docker by active agent 2')
        self.assertNotEqual(copied['uuid'], original['zabbix_export']['templates'][0]['uuid'])
        self.assertEqual(uuid.UUID(copied['uuid']).version, 4)
        self.assertNotIn('Docker by Zabbix agent 2', str(value))
        def check(node):
            if isinstance(node, dict):
                for key in ('items', 'item_prototypes', 'discovery_rules'):
                    for item in node.get(key, []):
                        self.assertNotIn(item.get('type', 'ZABBIX_PASSIVE'), ('ZABBIX_PASSIVE',))
                for child in node.values(): check(child)
            elif isinstance(node, list):
                for child in node: check(child)
        check(value)
