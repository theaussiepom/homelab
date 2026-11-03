"""The optional UI cannot publish an unauthenticated port or reconcile the broker."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mqtt_explorer as m
import render
import guest_contract
sys.path.append(str(Path(__file__).resolve().parents[3]/'blueprints'))
import service_bindings
from test_render import fixture
import test_composition_boundaries as composition


def configuration():
    broker = copy.deepcopy(fixture('automation')['services']['mqtt'])
    services = {'mqtt': broker}
    for name in m.SERVICES:
        services[name] = {'image': 'example.invalid/'+name+'@sha256:'+'a'*64,
            'memory_mib': 256 if name == 'mqtt_explorer' else 128, 'cpus': 1, 'pids_limit': 128, 'environment': {}}
    return {'kind': 'mqtt', 'guest_memory_mib': 1024, 'services': services,
        'mqtt': {'credential_file': '/synthetic/probe.json'}, 'mqtt_explorer': {
            'public_url': 'https://explorer.example.invalid', 'bind_address': '198.18.30.37',
            'authentik_outpost_url': 'http://198.18.30.20:9000', 'data_path': m.DATA}}


class ExplorerTests(unittest.TestCase):
    def mqtt_composition(self, root):
        helper=composition.CompositionTests();helper.root=root
        stack=configuration();cfg=helper.configuration('mqtt',stack,'198.18.30.37')
        cfg['app']['service_health_checks']['mqtt_explorer']=[{'argv':['true']}]
        cfg['app']['required_paths'].append({'path':m.DATA,'type':'directory'})
        cfg['app']['published_services']={'mqtt':{'hostname':'broker.example.invalid','addresses':{'clients':'198.18.30.37'},
            'dns_address':'clients','protocol':'tcp','port':1883}}
        cfg['app']['service_connections']={'mqtt_explorer':{'service':'mqtt.mqtt','address':'clients'}}
        stack['mqtt_explorer']['broker_connection']={'name':'Broker','hostname':'broker.example.invalid','port':1883,
            'username':'fixture_gui','credential_id':'fixture-gui','credential_file':'${inputs}/managed-fixture-gui.json',
            'password_file':'/mosquitto/config/selected_passwords','access':'read-write-all'}
        return cfg,stack,{}

    def test_same_guest_saved_connection_is_validated_but_has_no_external_network_edge(self):
        with tempfile.TemporaryDirectory() as directory:
            value=self.mqtt_composition(Path(directory));cfg,stack,_=value
            self.assertEqual(guest_contract.validate(cfg,stack),cfg['guest']['vmid'])
            endpoints=service_bindings.bind({'mqtt':value})
            self.assertEqual(set(endpoints),{'mqtt.mqtt'})
            self.assertEqual(list(service_bindings.connections_for({'mqtt':cfg})),[])
            self.assertEqual(stack['mqtt_explorer']['broker_connection']['hostname'],'broker.example.invalid')
            for mutate in (lambda c,s:c['app']['service_connections'].clear(),
                lambda c,s:c['app']['service_connections']['mqtt_explorer'].update(service='mqtt.mqtt_explorer'),
                lambda c,s:c['app']['published_services']['mqtt'].update(port=1884),
                lambda c,s:s['mqtt_explorer']['broker_connection'].update(hostname='foreign.example.invalid')):
                cfg,stack,files=self.mqtt_composition(Path(directory));mutate(cfg,stack)
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):service_bindings.bind({'mqtt':(cfg,stack,files)})
            from test_database_admin import composition as databases
            resolved=databases();cfg,stack,files=self.mqtt_composition(Path(directory))
            stack['mqtt_explorer']['broker_connection'].update(credential_id='fixture-postgresql',credential_file='${inputs}/managed-fixture-postgresql.json')
            resolved['mqtt']=(cfg,stack,files)
            with self.assertRaisesRegex(ValueError,'independent credentials'):service_bindings.bind(resolved)

    def test_legacy_dedicated_mqtt_omission_keeps_single_application_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            helper=composition.CompositionTests();helper.root=Path(directory)
            stack=configuration();stack.pop('mqtt_explorer');stack['services']={'mqtt':stack['services']['mqtt']}
            cfg=helper.configuration('mqtt',stack,'198.18.30.37')
            self.assertEqual(guest_contract.validate(cfg,stack),cfg['guest']['vmid'])
            self.assertEqual(guest_contract.applications(cfg),['mqtt'])


    def test_managed_broker_credential_is_create_once_and_bound_to_ordinary_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            stack = configuration(); value = stack['mqtt_explorer']
            value['broker_connection'] = {'name': 'Broker', 'hostname': 'broker.example.invalid', 'port': 1883,
                'username': 'explorer_account', 'credential_id': 'explorer-account',
                'credential_file': str(root/'inputs/managed-explorer-account.json'),
                'password_file': '/mosquitto/config/selected_passwords', 'access': 'read-write-all'}
            cfg = {'site': {'node': 'synthetic-node'}, 'guest': {'vmid': 901, 'hostname': 'synthetic-mqtt'},
                'paths': {'state_root': str(root)}}
            first = m.prepare(cfg, stack, root/'inputs')
            self.assertEqual(first, m.prepare(cfg, stack, root/'inputs'))
            record = json.loads(first['managed-explorer-account.json'])
            self.assertEqual(record['owner'], {'node': 'synthetic-node', 'vmid': 901,
                'hostname': 'synthetic-mqtt', 'purpose': 'mqtt-explorer', 'username': 'explorer_account'})
            private = Path(value['broker_connection']['credential_file']); private.parent.mkdir(mode=0o700)
            private.write_bytes(first[private.name]); private.chmod(0o600)
            rows = m.files(stack)
            packet = next(row for row in rows if row['path'] == 'mqtt-explorer-account.json')
            self.assertEqual(packet['mode'], '0600'); self.assertEqual(packet['uid'], 0)
            native = json.loads(packet['content'])
            self.assertEqual(native['credential'], record)
            self.assertEqual(native['image'], stack['services']['mqtt']['image'])
            self.assertNotIn('credential_file', native['connection'])
            record['owner']['username'] = 'foreign_account'; private.write_text(json.dumps(record))
            with self.assertRaises(ValueError): m.files(stack)
            self.assertEqual(m.source_files(stack), [value['broker_connection']['credential_file']])
            self.assertEqual(m.source_files(configuration()), [])
            self.assertEqual(m.prepare(cfg, configuration(), root/'inputs'), {})
            self.assertEqual(m.prepare(cfg, {'kind': 'music'}, root/'inputs'), {})
            value['broker_connection']['credential_file'] = '/elsewhere/managed-explorer-account.json'
            with self.assertRaises(ValueError): m.prepare(cfg, stack, root/'inputs')

    def test_managed_broker_configuration_refuses_foreign_accounts_inputs_and_access(self):
        selected = {'name': 'Broker', 'hostname': 'broker.example.invalid', 'port': 1883,
            'username': 'explorer_account', 'credential_id': 'explorer-account',
            'credential_file': '/synthetic/managed-explorer-account.json',
            'password_file': '/mosquitto/config/selected_passwords', 'access': 'read-write-all'}
        for field, value in [('name', ''), ('name', 'bad\nname'), ('port', True), ('port', 8883),
            ('username', 'root;bad'), ('username', []), ('credential_id', '../foreign'), ('hostname', None),
            ('access', 'admin'), ('password_file', '/mosquitto/config/..'), ('password_file', '/etc/passwd'),
            ('credential_file', 'relative'), ('credential_file', '/synthetic/../managed-explorer-account.json'),
            ('credential_file', '/synthetic/other.json')]:
            cfg = configuration(); cfg['mqtt_explorer']['broker_connection'] = dict(selected, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): m.validate(cfg)
        for value in (None, dict(selected, extra=True)):
            cfg = configuration(); cfg['mqtt_explorer']['broker_connection'] = value
            with self.assertRaises(ValueError): m.validate(cfg)

    def test_omission_preserves_broker_compose_and_has_no_files(self):
        selected = configuration(); legacy = copy.deepcopy(selected)
        legacy.pop('mqtt_explorer')
        legacy['services'] = {'mqtt': legacy['services']['mqtt']}
        before = render.compose(legacy)
        after = render.compose(selected)
        self.assertEqual(before['services']['mqtt'], after['services']['mqtt'])
        self.assertEqual(m.files(legacy), [])
        self.assertEqual(m.configure({'kind': 'music'}, {}), {})
        self.assertIsNone(m.validate({'kind': 'music'}))

    def test_closed_optional_contract_rejects_routes_credentials_and_placement_overrides(self):
        changes = [lambda c: c.update(kind='music'), lambda c: c.update(mqtt_explorer=None),
            lambda c: c['mqtt_explorer'].update(extra=True),
            lambda c: c['mqtt_explorer'].update(data_path='/srv/homelab/data/mqtt'),
            lambda c: c['mqtt_explorer'].update(bind_address='127.0.0.1'),
            lambda c: c['mqtt_explorer'].update(bind_address='0.0.0.0'),
            lambda c: c['mqtt_explorer'].update(bind_address=[]),
            lambda c: c['mqtt_explorer'].update(authentik_outpost_url='https://public.example.invalid'),
            lambda c: c['services'].pop('mqtt'),
            lambda c: c['services'].update(foreign={})]
        for key, value in [('environment', {'OPENAI_API_KEY': 'not-accepted'}), ('ports', []),
                           ('command', []), ('extra_hosts', {}), ('extra_mounts', []), ('user', '0')]:
            changes.append(lambda c, k=key, v=value: c['services']['mqtt_explorer'].update({k: v}))
        for change in changes:
            cfg = configuration(); change(cfg)
            with self.subTest(change=change), self.assertRaises(ValueError): m.validate(cfg)
        for url in (None, 'http://explorer.example.invalid', 'https://user:pass@explorer.example.invalid',
            'https://explorer.example.invalid/path', 'https://explorer.example.invalid:444',
            'https://explorer.example.invalid:bad', 'https://[bad', 'https://explorer.example.invalid?',
            'https://explorer.example.invalid#', 'https://explorer.example.invalid/\\bad', 'https://no-dot'):
            cfg = configuration(); cfg['mqtt_explorer']['public_url'] = url
            with self.subTest(url=url), self.assertRaises(ValueError): m.validate(cfg)

    def test_public_listener_is_only_gateway_and_app_keys_and_network_are_generated(self):
        cfg = configuration(); before = copy.deepcopy(cfg); doc = render.compose(cfg)
        self.assertEqual(cfg, before)
        app = doc['services']['mqtt_explorer']; gateway = doc['services']['explorer_gateway']
        self.assertNotIn('ports', app)
        self.assertEqual(gateway['ports'], ['198.18.30.37:80:4180'])
        self.assertEqual(doc['services']['mqtt']['network_mode'], 'host')
        self.assertEqual(doc['networks'], {'explorer': {}})
        for value in (app, gateway):
            self.assertNotIn('network_mode', value)
            self.assertTrue(value['read_only'])
            self.assertEqual(value['cap_drop'], ['ALL'])
            self.assertEqual(value['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(app['user'], '1001:1001'); self.assertEqual(gateway['user'], '65532:65532')
        self.assertEqual(app['command'], ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"])
        self.assertEqual(app['environment']['MQTT_EXPLORER_SKIP_AUTH'], 'true')
        self.assertFalse(any(name.startswith(('OPENAI_', 'GEMINI_', 'LLM_', 'MQTT_AUTO_CONNECT_')) for name in app['environment']))
        cfg['mqtt_explorer']['public_url'] = 'https://explorer.example.invalid:443/'
        self.assertEqual(render.compose(cfg)['services']['mqtt_explorer']['environment']['ALLOWED_ORIGINS'], 'https://explorer.example.invalid')

    def test_routes_protect_app_socket_and_forwarded_headers_but_callback_has_no_auth_loop(self):
        cfg = configuration(); static, dynamic = m.configuration(cfg['mqtt_explorer'])
        self.assertEqual(static['providers']['file']['filename'], '/etc/traefik/explorer.yml')
        self.assertNotIn('api', static); self.assertNotIn('certificatesResolvers', static)
        self.assertEqual(set(static['providers']), {'file'})
        http = dynamic['http']; app = http['routers']['explorer']; callback = http['routers']['outpost']
        self.assertEqual(app['middlewares'], ['canonical', 'security', 'authentik'])
        self.assertIn('Host(`explorer.example.invalid`)', app['rule'])
        self.assertEqual(http['services']['explorer']['loadBalancer']['servers'], [{'url': 'http://mqtt_explorer:3000'}])
        self.assertEqual(callback['middlewares'], ['canonical', 'security'])
        self.assertGreater(callback['priority'], app['priority'])
        self.assertIn('PathPrefix(`/outpost.goauthentik.io/`)', callback['rule'])
        headers = http['middlewares']['canonical']['headers']['customRequestHeaders']
        self.assertEqual(headers['X-Forwarded-Host'], 'explorer.example.invalid')
        self.assertEqual(headers['X-Forwarded-Proto'], 'https')
        self.assertEqual(headers['X-Forwarded-Uri'], '')
        self.assertEqual(headers['X-Authentik-Username'], '')
        rows = {row['path']: row for row in m.files(cfg)}
        public = json.loads(rows['mqtt-explorer-public.json']['content'])
        for name, expected in public['runtime_sha256'].items():
            self.assertEqual(hashlib.sha256(rows[name]['content'].encode()).hexdigest(), expected)
            self.assertEqual((rows[name]['uid'], rows[name]['gid'], rows[name]['mode']), (65532, 65532, '0400'))

    def test_optional_phase_has_prepared_data_and_helper_is_not_an_extra_application(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = composition.CompositionTests(); helper.root = Path(directory)
            stack = configuration(); cfg = helper.configuration('mqtt', stack, '198.18.30.37')
            cfg['app']['service_health_checks']['mqtt_explorer'] = [{'argv': ['true'], 'expect': ''}]
            cfg['app']['required_paths'].append({'path': m.DATA, 'type': 'directory'})
            self.assertEqual(guest_contract.applications(cfg), ['mqtt', 'mqtt_explorer'])
            self.assertEqual(guest_contract.validate(cfg, stack), cfg['guest']['vmid'])
            cfg['app']['service_health_checks']['explorer_gateway'] = [{'argv': ['true']}]
            with self.assertRaises(ValueError): guest_contract.validate(cfg, stack)
            cfg['app']['service_health_checks'].pop('explorer_gateway')
            stack['mqtt_explorer']['bind_address'] = '198.18.30.38'
            with self.assertRaisesRegex(ValueError, 'assigned backend'): guest_contract.validate(cfg, stack)
            stack['mqtt_explorer']['bind_address'] = '198.18.30.37'
            cfg['app']['service_health_checks'].pop('mqtt_explorer')
            with self.assertRaisesRegex(ValueError, 'optional Explorer'): guest_contract.validate(cfg, stack)

    def test_broker_and_gui_targeting_and_changed_runtime_files_are_separate(self):
        tasks = yaml.safe_load((Path(render.__file__).parent/'ansible/tasks/compose.yml').read_text())
        start = next(task for task in tasks if task['name'] == 'Start exactly this guest stack')
        expression = start['ansible.builtin.command']['argv'][2:-2].strip()
        install = next(task for task in tasks if task['name'] == 'Install only the selected service-readable foundation files')
        file_expression = install['loop'][2:-2].strip()
        environment = Environment(autoescape=True)
        for changed in (False, True):
            for phase in ('mqtt', 'mqtt_explorer'):
                argv = environment.compile_expression(expression)(app={'kind': 'mqtt'},
                    foundation_runtime_install={'changed': changed}, application_service=phase)
                self.assertEqual(argv[-3:] if phase == 'mqtt_explorer' else argv[-2:],
                    ['--no-deps', 'mqtt_explorer', 'explorer_gateway'] if phase == 'mqtt_explorer' else ['--no-deps', 'mqtt'])
                self.assertEqual('--force-recreate' in argv, changed and phase == 'mqtt_explorer')
                self.assertIn('--remove-orphans=false', argv)
                rows = [{'path': name} for name in ('mqtt-probe.json', 'explorer-traefik.json', 'explorer-routes.yml')]
                selected = environment.compile_expression(file_expression)(app={'kind': 'mqtt'},
                    application_service=phase, foundation_runtime_files=rows)
                self.assertEqual([r['path'] for r in selected], ['mqtt-probe.json'] if phase == 'mqtt' else ['explorer-traefik.json', 'explorer-routes.yml'])


if __name__ == '__main__':
    unittest.main()
