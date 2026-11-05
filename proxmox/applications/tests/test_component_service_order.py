"""Real JSON/receiver/project wiring; app rendering and private builders are fakes."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import application_contract as contract
import component_ansible
import component_inputs
import component_payload
import component_runtime
from private_io import encoded,write_bytes
import test_component_inputs as fixtures


class ServiceOrderTests(unittest.TestCase):
    def test_every_multi_service_adapter_survives_canonical_json_into_actual_receiver_and_variables(self):
        for adapter in ('cloudbeaver','authentik','mqtt_explorer','zabbix'):
            with self.subTest(adapter=adapter):
                fixture=fixtures.StaticInputTests('test_create_once_repeat_verify_and_separate_app_directory_do_not_rebind_static_inputs')
                fixture.setUp()
                try:
                    roles=contract.ADAPTERS[adapter]['services']
                    names={role:'selected_'+role for role in reversed(roles)}
                    expected=['selected_'+role for role in roles]
                    app={'id':'selected','adapter':adapter,'lifecycle':'retained',
                        'identity':{'phase':'owned','runtime_id':'selected','services':names,
                            'runtime_directory':'/opt/homelab-app/runtime/selected'},
                        'settings':{'broker':{'credential':{'principal':'synthetic'}}} if adapter=='mqtt_explorer' else {},
                        'software_selection':{'images':{role:{'image':'example/'+role+'@sha256:'+'b'*64} for role in roles}},
                        'project_name':'example-project','project_file':'compose-example.yml','storage_paths':{}}
                    runtime={'schema':component_runtime.SCHEMA,'guest':{'id':'example'},'applications':{'selected':app}}
                    # Rendering belongs to app tests. This integration exercises
                    # the real manifest generator, serialization, receiver and caller.
                    with patch.object(component_runtime,'compositions',return_value={
                            'example-project':{'name':'example-project','services':{
                                names[role]:{'image':app['software_selection']['images'][role]['image']}
                                for role in roles}}}):
                        artifacts=component_runtime.artifacts(runtime)
                    cfg=fixture.cfg;cfg['deployment'].update(lifecycle='retained',
                        phases=['preparation','owned'],payload_phases={'owned':'selected'},
                        applications={'owned':{'id':'selected','adapter':adapter,'lifecycle':'retained',
                            'runtime_id':'selected','project':'example-project',
                            'compose_file':'compose-example.yml','services':expected}})
                    cfg['app'].update(service_health_checks={'owned':[{'name':'owned','argv':['true'],'expect':''}]})
                    fixture.packet['files']={'site.json':encoded(cfg).decode(),
                        'component-runtime.json':encoded(runtime).decode(),
                        **{name:raw.decode() for name,raw in artifacts.items()}}
                    write_bytes(fixture.path,encoded(fixture.packet))
                    selected,_=component_inputs.prepare(fixture.path,fixture.inputs,create=True)
                    actual=json.loads(fixture.packet['files']['component-runtime.json'])['applications']['selected']
                    self.assertEqual(list(actual['identity']['services']),sorted(roles))
                    parent=component_inputs.app_directory(selected,create=True)
                    values={'application.json':encoded(actual),'runtime-files.json':b'[]\n'}
                    if adapter=='cloudbeaver':values['cloudbeaver-public.json']=b'{}\n'
                    payload=component_payload.prepare(parent,fixture.identity,'selected',values)
                    values=component_ansible.variables(selected,'owned',payload=payload)
                    self.assertEqual(values['component_services'],expected)
                    self.assertEqual(values['component_preflight']['services'],expected)
                    self.assertEqual(values['component_preflight']['peers'],[])
                    self.assertEqual(values['component_compose_file'],'/opt/homelab-app/compose-example.yml')
                finally:
                    fixture.doCleanups()

    def test_unknown_missing_duplicate_or_unsafe_owned_role_names_refuse(self):
        for names in ({'cloudbeaver':'one'},{'cloudbeaver':'one','auth_gateway':'one'},
                      {'cloudbeaver':'one','auth_gateway':'--option'},
                      {'cloudbeaver':'one','auth_gateway':'two','foreign':'third'}):
            with self.subTest(names=list(names)),self.assertRaises(ValueError):
                contract.ordered_services({'adapter':'cloudbeaver','identity':{'services':names}})


if __name__=='__main__':unittest.main()
