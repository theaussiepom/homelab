"""Exercise the retained one-service phase from its static packet through Ansible variables."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'blueprints'))
import application_contract
import component_ansible
import component_checks
import component_foundation_files
import component_inputs
import component_prepare
import component_runtime
import protocol_component_fixtures as services
from private_io import encoded, write_bytes
from test_component_foundation_files import ingress
import test_component_inputs as input_fixtures


class ForwardContractTests(unittest.TestCase):
    def test_header_translation_is_only_on_the_application_backend(self):
        app, _, _, _, plan = ingress()
        plan['middlewares']['console-headers'] = {'type':'cloudbeaver-headers'}
        plan['routes']['managed']['middlewares'].append('console-headers')
        result = component_foundation_files.routing(app,plan)
        headers = result['middlewares']['console-headers']['headers']['customRequestHeaders']
        self.assertEqual(headers['X-Team'], 'user')
        self.assertEqual(headers['X-Role'], '')
        self.assertNotIn('console-headers', result['authentik_callbacks']['managed']['middlewares'])

    def test_only_the_sealed_retirement_selection_reaches_the_single_service_phase(self):
        for retirement in (None, {'project':'tools','gateway':'prior'}):
            with self.subTest(transition=bool(retirement)):
                fixture = input_fixtures.StaticInputTests('test_create_once_repeat_verify_and_separate_app_directory_do_not_rebind_static_inputs')
                fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                image = 'example.invalid/database@sha256:' + 'f'*64
                app = services.cloudbeaver_app({}, {}, image=image, gateway_image=image)
                for roles in (app['containers'],app['identity']['services'],app['software_selection']['images']):
                    del roles['auth_gateway']
                app.update(guest='example',authentication_resolved={'type':'forward-auth'})
                app['identity'].update(phase=app['id'],runtime_id=app['id'],custody_directory='/var/lib/homelab-db-tools')
                app['settings']['auth_headers']['user'] = 'X-authentik-username'
                address = app['settings']['bind_address']
                app['listeners'] = {'web_listener':services._listener('cloudbeaver',8978,address=address)}
                source = {'type':'environment','name':'SYNTHETIC'}
                app['input_sources'] = {'recovery_password':source}
                app['runtime_files'] = {'app':app['id'],'directory':app['identity']['runtime_directory'],
                                        'files':sorted(application_contract.runtime_files(app))}
                runtime = {'schema':component_runtime.SCHEMA, 'guest':{'id':'example','timezone':'Etc/UTC',
                           'os_reserve_mib':256,'memory_mib':2048}, 'applications':{app['id']:app}}
                artifacts = component_runtime.artifacts(runtime)
                compose = json.loads(artifacts[app['project_file']])
                self.assertEqual(list(compose['services']),['cloudbeaver'])
                self.assertEqual(compose['services']['cloudbeaver']['ports'],[address+':8978:8978'])
                checks = component_checks._cloudbeaver(app,app['project_file'])
                self.assertEqual([check['name'] for check in checks], ['CloudBeaver'])
                cfg = fixture.cfg
                cfg['deployment'].update(lifecycle='retained',phases=['preparation',app['id']],
                    payload_phases={app['id']:app['id']}, applications={app['id']:{
                        'id':app['id'],'adapter':'cloudbeaver','lifecycle':'retained','runtime_id':app['id'],
                        'project':app['project_name'],'compose_file':app['project_file'],'services':['cloudbeaver']}})
                cfg['app']['service_health_checks'] = {app['id']:checks}
                fixture.packet['files'] = {'site.json':encoded(cfg).decode(),'component-runtime.json':encoded(runtime).decode(),
                                           **{name:raw.decode() for name,raw in artifacts.items()}}
                write_bytes(fixture.path,encoded(fixture.packet))
                admitted,_ = component_inputs.prepare(fixture.path,fixture.inputs,create=True)
                with patch.object(component_prepare.component_continuity,'verify') as continuity, \
                     patch.object(component_prepare,'cloudbeaver_retirement',return_value=retirement):
                    payload = component_prepare.prepare(admitted,app['id'],
                        {'HOMELAB_APP_SECRET_CLOUDBEAVER_RECOVERY_PASSWORD':'synthetic-input-for-configuration-unit-test'},attempt=object())
                self.assertEqual(continuity.call_args.kwargs,
                                 {'recovery_password':b'synthetic-input-for-configuration-unit-test'})
                variables = component_ansible.variables(admitted,app['id'],payload=payload,previously_owned=True)
                self.assertEqual(variables.get('component_gateway_retirement'),retirement)
                self.assertEqual(variables['component_services'],['cloudbeaver'])
                self.assertFalse((payload.directory/'oauth2.cfg').exists())
                self.assertFalse((payload.directory/'oauth2-alpha.json').exists())
