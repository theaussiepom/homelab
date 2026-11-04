"""PUBLIC synthetic real source→packet→Explorer late-file integration only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'blueprints'),str(ROOT/'proxmox/applications')]
import compile as compiler
import component_proxy_files
from test_component_plan import library as base_library, site as base_site


def role(*kinds):return {'required':True,'accepts':list(kinds)}
def storage(target):return {'required':True,'target':target,'kind':'directory','read_only':False}
def listener(service,interface,port,*,namespace='host',publish=None,bind='wildcard'):
    result={'service':service,'namespace':namespace,'interface':interface,'bind':bind,'protocol':'tcp','port':port}
    if publish is not None:result['publish']=publish
    return result


def source_fixture(*,existing=False,name='Saved source broker'):
    """Finite authored fixtures, never an old-stack converter or private library."""
    library,site=base_library(),base_site();library['app_profiles']={}
    library['software']={'broker':{'images':{'mqtt':'broker'}},
        'browser':{'images':{'mqtt_explorer':'browser','explorer_gateway':'gateway'}},
        'ingress':{'images':{'traefik':'gateway'}}}
    library['runtime_profiles']={
        'broker':{'containers':{'mqtt':{'memory_mib':256,'pids_limit':128,'cpu_limit':1}}},
        'browser':{'containers':{'mqtt_explorer':{'memory_mib':256,'pids_limit':128,'cpu_limit':1},
            'explorer_gateway':{'memory_mib':128,'pids_limit':128,'cpu_limit':1}}},
        'ingress':{'containers':{'traefik':{'memory_mib':512,'pids_limit':256,'cpu_limit':1}}}}
    common={'health':{'ready':{'type':'adapter','check':'readiness'}}}
    library['app_profiles']['broker']={**copy.deepcopy(common),'adapter':'mqtt','display_name':'Broker',
        'interfaces':{'backend':role('guest-interface'),'frontend':role('guest-interface')},
        'listeners':{'mqtt':listener('mqtt','backend',1883)},
        'endpoints':{'backend':{'listener':'mqtt','protocol':'tcp','via':'backend'}},
        'storage':{n:storage('/mosquitto/'+n)for n in ('config','data','log')},
        'software':['broker'],'runtime':['broker'],'secrets':{'probe':{'required':True}}}
    library['app_profiles']['browser']={**copy.deepcopy(common),'adapter':'mqtt_explorer','display_name':'Browser',
        'interfaces':{'web':role('guest-interface'),'broker':role('guest-interface'),'private':role('app-network')},
        'listeners':{'web':listener('explorer_gateway','private',4180,namespace='app-network',
            publish={'scope':'guest-interface','interface':'web','port':80}),
            'application':listener('mqtt_explorer','private',3000,namespace='app-network')},
        'endpoints':{'web':{'listener':'web','protocol':'http','via':'web'}},
        'connections':{'broker':{'type':'mqtt','required':True,'accounts':['mqtt-client']},
                       'outpost':{'type':'http','required':True}},
        'storage':{'data':storage('/app/data')},'software':['browser'],'runtime':['browser']}
    library['app_profiles']['ingress']={**copy.deepcopy(common),'adapter':'traefik','display_name':'Ingress',
        'interfaces':{'frontend':role('guest-interface')},
        'listeners':{'http':listener('traefik','frontend',80,bind='interface'),'https':listener('traefik','frontend',443,bind='interface')},
        'endpoints':{'https':{'listener':'https','protocol':'https','via':'frontend'}},
        'storage':{'certs':storage('/var/traefik/certs')},'software':['ingress'],'runtime':['ingress'],
        'secrets':{'cloudflare_dns_token':{'required':True},'proxmox_token':{'required':True}}}
    guest=site['guests']['resolver'];guest['resources']={'memory_mib':4096}
    guest['root_paths']={'data':{'path':'/srv/example/apps'}}
    guest['compose_projects']={'broker':{'name':'fixture-broker','file':'compose-broker.yml'}}
    site['secret_sources'].update(probe={'type':'file','path':'/never-read/probe.json'},
        provider={'type':'file','path':'/never-read/provider.json'},
        dns_api={'type':'environment','name':'EXAMPLE_DNS_TOKEN'})
    site['external_endpoints'].update(outpost={'protocol':'http','address':'192.0.2.20','port':9000},
        existing_broker={'protocol':'tcp','address':'192.0.2.77','port':1883})
    site['domains']={'browser':'browser.example.invalid','broker':'broker.example.invalid'}
    site['policies']={'tls':{'public':{'type':'acme','resolver':'letsencrypt'}}}
    site['apps']={
        'broker':{'profile':'broker','guest':'resolver','lifecycle':'retained',
            'identity':{'phase':'broker','runtime_id':'fixture-broker','project':'broker',
                'services':{'mqtt':'owned-broker'},'networks':{},'runtime_directory':'/opt/homelab-app/runtime/broker'},
            'interfaces':{'backend':{'interface':'backend'},'frontend':{'interface':'management'}},
            'storage':{n:{'root_path':'data','subpath':'broker/'+n}for n in ('config','data','log')},
            'secrets':{'probe':'probe'},'properties':{'password_file':'/mosquitto/config/passwords'}},
        'browser':{'profile':'browser','guest':'resolver','lifecycle':'fresh',
            'interfaces':{'web':{'interface':'backend'},'broker':{'interface':'backend'},
                          'private':{'scope':'app-network','network':'explorer'}},
            'storage':{'data':{'root_path':'data','subpath':'browser'}},
            'origin':{'exposure':'browser'},'properties':{'connection_name':name}},
        'ingress':{'profile':'ingress','guest':'resolver','lifecycle':'fresh',
            'interfaces':{'frontend':{'interface':'management'}},
            'storage':{'certs':{'root_path':'data','subpath':'ingress'}},
            'secrets':{'cloudflare_dns_token':'dns_api','proxmox_token':'provider'},
            'properties':{'dashboard':False,'provider':{'context':'lab','token_id':'fixture@pve!discovery'},
                'acme':{'email':'fixture@example.invalid','resolvers':[{'external':'dns'}]}}}}
    site['exposures']={'browser':{'type':'http','endpoint':{'app':'browser','endpoint':'web'},
        'domain':'browser','ingress':{'app':'ingress','endpoint':'https'},'tls':'public'}}
    target={'external':'existing_broker'}if existing else{'app':'broker','endpoint':'backend'}
    site['connections']={'broker':{'consumer':{'app':'browser','connection':'broker'},'target':target,
        'source_interface':'broker','hostname':{'domain':'broker'}},
        'outpost':{'consumer':{'app':'browser','connection':'outpost'},'target':{'external':'outpost'},'source_interface':'web'}}
    if existing:
        site['secret_sources']['existing_password']={'type':'file','path':'/never-read/existing-password'}
        site['connections']['broker']['credential']={'principal':'existing_client','secret':'existing_password'}
    else:
        site['secret_sources']['generated']={'type':'generated','credential_id':'fixture-browser'}
        site['accounts']={'client':{'adapter':'mqtt-client','owner':'browser','target':target,
            'principal':'gui_client','credential':'generated','access':'read-write-all','lifecycle':'create-once'}}
        site['connections']['broker']['account']='client'
    selected=['outpost']+(['existing_broker']if existing else[])
    site['policies']['network']={'selected_external':{'rules':[{
        'direction':'out','proto':'tcp','destination':{'endpoint':key},'port':{'endpoint':key},
        'comment':'Selected synthetic '+key}for key in selected]}}
    guest['network_policy']=[{'policy':'selected_external','endpoints':{
        key:{'external':key}for key in selected}}]
    return library,site


class ExplorerLateFileIntegration(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.stack=self.root/'stack';self.stack.mkdir();self.source=self.root/'site.json'
        images={name:{'repository':'example/'+name,'tag':None,'digest':'sha256:'+'a'*64}
                for name in ('broker','browser','gateway')}
        (self.stack/'images.json').write_text(json.dumps(images))

    def packet_app(self,*,existing=False,name='Saved source broker',change=None):
        library,site=source_fixture(existing=existing,name=name)
        if change is not None:change(site)
        (self.stack/'stack.json').write_text(json.dumps(library));self.source.write_text(json.dumps(site))
        plan=compiler.resolve_plan(self.stack,self.source,admit=False)
        self.assertEqual(plan.resolved['apps']['browser']['properties']['connection_name'],name)
        packet=compiler.lower_plan(plan)['resolver']
        self.assertEqual(packet['schema'],'homelab-component-guest-deployment-v1')
        runtime=json.loads(json.loads(json.dumps(packet,sort_keys=True))['files']['component-runtime.json'])
        app=runtime['applications']['browser']
        self.assertEqual(app['properties']['connection_name'],name)
        self.assertNotIn('connection_name',app['settings'])
        return app

    def rows(self,app,*,existing=False):
        if existing:
            secrets={'broker_password':b'synthetic-existing-password'};records={}
            self.assertEqual(app['input_sources']['broker_password']['path'],'/never-read/existing-password')
        else:
            selected=app['settings']['broker']['managed_credential']
            self.assertEqual(selected['owner'],{'node':'example-node','vmid':610,'hostname':'example-dns',
                'purpose':'mqtt-explorer','username':'gui_client'})
            secrets={};records={selected['credential_id']:{'schema':'homelab-application-account-v1',
                'owner':copy.deepcopy(selected['owner']),'password':'d'*64}}
        with patch.object(Path,'open',side_effect=AssertionError('No declared private input read')):
            rows=component_proxy_files.files(app,secrets=secrets,records=records,public_ca=None)
        return {row['path']:row for row in rows}

    def test_managed_account_source_property_survives_real_packet_and_late_files(self):
        self.assert_names(existing=False)

    def test_existing_password_source_property_survives_real_packet_and_late_files(self):
        self.assert_names(existing=True)

    def assert_names(self,*,existing):
        for name in ('Saved source broker','Renamed source broker'):
            with self.subTest(name=name):
                app=self.packet_app(existing=existing,name=name);rows=self.rows(app,existing=existing)
                leaf='mqtt-explorer-profile.json'if existing else'mqtt-explorer-account.json'
                private=json.loads(rows[leaf]['content']);public=json.loads(rows['mqtt-explorer-public.json']['content'])
                self.assertEqual(private['connection']['name'],name)
                self.assertEqual(public['broker_connection']['name'],name)
                self.assertEqual(rows[leaf]['mode'],'0600');self.assertEqual(rows[leaf]['uid'],0)
                self.assertEqual(public['broker_connection']['hostname'],'broker.example.invalid')
                self.assertNotIn('synthetic-existing-password',rows['mqtt-explorer-public.json']['content'])
                self.assertNotIn('d'*64,rows['mqtt-explorer-public.json']['content'])

    def test_missing_unknown_and_wrong_type_properties_refuse_at_real_source_boundary(self):
        changes=[lambda s:s['apps']['browser']['properties'].pop('connection_name'),
            lambda s:s['apps']['browser']['properties'].update(connection_name=None),
            lambda s:s['apps']['browser']['properties'].update(connection_name=''),
            lambda s:s['apps']['browser']['properties'].update(connection_name='wrong\nname'),
            lambda s:s['apps']['browser']['properties'].update(unknown='not a settings fallback')]
        for existing in (False,True):
            for change in changes:
                with self.subTest(existing=existing,change=changes.index(change)),self.assertRaises(ValueError):
                    self.packet_app(existing=existing,change=change)


if __name__=='__main__':unittest.main()
