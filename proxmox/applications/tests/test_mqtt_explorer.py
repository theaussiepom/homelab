"""Pure authenticated Explorer gateway/protocol transformations only."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import mqtt_explorer as m


def selected():
    return {'public_url':'https://explorer.example.invalid','bind_address':'198.18.30.37',
        'authentik_outpost_url':'http://198.18.30.20:9000','broker_address':'198.18.31.19',
        'broker_connection':{'hostname':'broker.example.invalid'}}


def services():
    return {name:{'environment':{},'volumes':[]}for name in m.SERVICES}


def mount(source,target):return {'source':'/opt/homelab-app/runtime/'+source,'target':target,'read_only':True}


class ExplorerProtocolTests(unittest.TestCase):
    def test_routes_protect_socket_and_headers_but_callback_has_no_auth_loop(self):
        static,dynamic=m.configuration(selected())
        self.assertEqual(static['providers']['file']['filename'],'/etc/traefik/explorer.yml')
        self.assertNotIn('api',static);self.assertNotIn('certificatesResolvers',static)
        self.assertEqual(set(static['providers']),{'file'})
        http=dynamic['http'];app=http['routers']['explorer'];callback=http['routers']['outpost']
        self.assertEqual(app['middlewares'],['canonical','security','authentik'])
        self.assertIn('Host(`explorer.example.invalid`)',app['rule'])
        self.assertEqual(http['services']['explorer']['loadBalancer']['servers'],[{'url':'http://mqtt_explorer:3000'}])
        self.assertEqual(callback['middlewares'],['canonical','security'])
        self.assertGreater(callback['priority'],app['priority'])
        self.assertIn('PathPrefix(`/outpost.goauthentik.io/`)',callback['rule'])
        headers=http['middlewares']['canonical']['headers']['customRequestHeaders']
        self.assertEqual(headers['X-Forwarded-Host'],'explorer.example.invalid')
        self.assertEqual(headers['X-Forwarded-Proto'],'https')
        self.assertEqual(headers['X-Forwarded-Uri'],'');self.assertEqual(headers['X-Authentik-Username'],'')

    def test_named_service_only_changes_owned_backend_and_bad_service_refuses(self):
        _,before=m.configuration(selected());_,after=m.configuration(selected(),explorer_service='browser-a')
        after['http']['services']['explorer']['loadBalancer']['servers'][0]['url']='http://mqtt_explorer:3000'
        self.assertEqual(after,before)
        for name in ('../peer','foreign/peer','','value\n'):
            with self.subTest(name=name),self.assertRaises(ValueError):m.configuration(selected(),explorer_service=name)

    def test_service_process_identity_limits_headers_and_sole_gateway_publication(self):
        value=selected();result=m.service_configuration(value,services(),mount=mount)
        app,gateway=result['mqtt_explorer'],result['explorer_gateway']
        self.assertEqual(app['user'],'1001:1001');self.assertEqual(gateway['user'],'65532:65532')
        self.assertTrue(app['read_only']);self.assertTrue(gateway['read_only'])
        self.assertEqual(app['cap_drop'],['ALL']);self.assertEqual(gateway['cap_drop'],['ALL'])
        self.assertEqual(app['security_opt'],['no-new-privileges:true'])
        self.assertNotIn('ports',app);self.assertEqual(gateway['ports'],['198.18.30.37:80:4180'])
        self.assertEqual(app['extra_hosts'],{'broker.example.invalid':'198.18.31.19'})
        self.assertNotIn('extra_hosts',gateway)
        self.assertEqual(app['environment']['ALLOWED_ORIGINS'],'https://explorer.example.invalid')
        self.assertFalse(any(key.startswith(('OPENAI_','GEMINI_','LLM_','MQTT_AUTO_CONNECT_'))for key in app['environment']))
        self.assertEqual(gateway['depends_on'],{'mqtt_explorer':{'condition':'service_healthy'}})
        self.assertEqual(app['command'],['node','-e',"process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"])

    def test_saved_hostname_alias_follows_only_selected_backend_and_preserves_inputs(self):
        value=selected();before=copy.deepcopy(value)
        first=m.service_configuration(value,services(),mount=mount)
        value['broker_address']='198.18.32.23'
        second=m.service_configuration(value,services(),mount=mount)
        second['mqtt_explorer']['extra_hosts']=first['mqtt_explorer']['extra_hosts']
        self.assertEqual(second,first)
        value['broker_address']=before['broker_address'];self.assertEqual(value,before)

    def test_nondefault_owned_paths_names_and_origin_normalization_are_explicit(self):
        value=selected();value['public_url']+=':443/'
        result=m.service_configuration(value,services(),mount=mount,data_path='/srv/example/browser',
            explorer_service='browser-a',ports=['198.18.30.38:80:4180'])
        self.assertEqual(result['mqtt_explorer']['environment']['ALLOWED_ORIGINS'],'https://explorer.example.invalid')
        self.assertEqual(result['mqtt_explorer']['volumes'][0]['source'],'/srv/example/browser')
        self.assertEqual(result['explorer_gateway']['depends_on'],{'browser-a':{'condition':'service_healthy'}})
        self.assertEqual(result['explorer_gateway']['ports'],['198.18.30.38:80:4180'])

    def test_protocol_builders_never_open_private_or_state_paths(self):
        with patch('builtins.open',side_effect=AssertionError('Pure protocol only')),patch('pathlib.Path.open',side_effect=AssertionError('Pure protocol only')):
            m.configuration(selected());m.service_configuration(selected(),services(),mount=mount)


class IndependentBrokerIntegration(unittest.TestCase):
    def test_omitting_explorer_does_not_infer_a_gateway_or_extra_application(self):
        import component_runtime
        from protocol_component_fixtures import structural_runtime
        cfg=structural_runtime();broker=cfg['applications']['mqtt']
        cfg['applications']={'mqtt':broker}
        documents=component_runtime.compositions(cfg)
        self.assertEqual(set(documents),{broker['project_name']})
        self.assertEqual(set(documents[broker['project_name']]['services']),{'mqtt'})


if __name__=='__main__':unittest.main()
