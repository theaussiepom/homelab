"""Lowerer units use validated guest/profile/app contracts and no renderer."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from component_errors import ComponentError
import component_lower as lower


def fixture():
    guest={'context':'lab','identity':{'vmid':610,'hostname':'example-guest'},
        'resources':{'cpu_cores':2,'memory_mib':3072,'root_gib':8},
        'startup':{'started':True,'start_on_boot':True,'boot_order':2},
        'security':{'nesting':True,'keyctl':False},'root_storage':'root','template_file_id':'local:debian.tar.zst',
        'dns_servers':['198.18.25.2'],'provider_interfaces':[{'ipv4':'198.18.25.20/24'}],
        'volumes':{'later':{'slot':1,'path':'/srv/example/later','size_gib':8},
                   'data':{'slot':0,'path':'/srv/example/data','size_gib':16}},
        'root_paths':{'retained':{'path':'/srv/example/retained'}},'rules':[],
        'compose_projects':{'project':{'name':'owned-project','file':'compose-owned.yml'}},
        'effective_os_reserve_mib':256,'timezone':'Etc/UTC'}
    return SimpleNamespace(check=Mock(),site={'storage':{'root':{'pool':'local-zfs'}},'devices':{},
        'secret_sources':{'oauth':{'type':'file','path':'/controller/oauth'},
                          'broker-password':{'type':'file','path':'/controller/broker'}}},
        library={'app_profiles':{'profile':{'storage':{'data':{'kind':'directory','target':'/data','read_only':False,
            'initialize':{'type':'directory','uid':1000,'gid':1000,'mode':'0700'}}}}}},
        resolved={'guests':{'one':guest},'contexts':{'lab':{'node':'example-node',
            'api_endpoint':'https://198.18.25.10:8006','ssh_public_keys':['ssh-ed25519 synthetic']}},
            'apps':{},'routes':{},'middlewares':{},'transports':{},'canonical_middlewares':{}})


def app(adapter='node_red',*,guest='one',native=False,name='selected'):
    roles=lower.adapter(adapter)['services']
    identity={'phase':name,'runtime_id':name,'services':{role:name+'-'+role for role in roles},'networks':{}}
    if not native:identity['project']='project'
    return {'id':name,'adapter':adapter,'guest':guest,'profile':'profile','lifecycle':'fresh',
            'identity':identity,'settings':{},'storage':{},'secret_bindings':{}}


class LowerComponentTests(unittest.TestCase):
    def test_provider_fields_keep_slot_order_device_scope_and_explicit_ssh_override(self):
        plan=fixture();first=lower.provider_config(plan,'one')
        self.assertEqual(first['guest']['volume_order'],['data','later'])
        self.assertEqual(list(first['guest']['volumes']),['data','later'])
        self.assertNotIn('serial_device',first['guest'])
        self.assertEqual(first['site']['api_endpoint'],'https://198.18.25.10:8006/')
        self.assertEqual(first['ssh_public_keys'],['ssh-ed25519 synthetic'])
        plan.resolved['guests']['one']['ssh_public_keys']=['ssh-ed25519 selected']
        plan.site['devices']['coordinator']={'path':'/dev/serial/by-id/usb-synthetic'}
        plan.resolved['apps']={'radio':dict(app('zigbee2mqtt'),devices={'coordinator':'coordinator'}),
                               'elsewhere':dict(app(guest='other',name='elsewhere'),devices={'coordinator':'coordinator'})}
        selected=lower.provider_config(plan,'one')
        self.assertEqual(selected['ssh_public_keys'],['ssh-ed25519 selected'])
        self.assertEqual(selected['guest']['serial_device'],{'path':'/dev/serial/by-id/usb-synthetic'})
        plan.resolved['apps']['second']=copy.deepcopy(plan.resolved['apps']['radio'])
        with self.assertRaisesRegex(ComponentError,'component.device-backend'):lower.provider_config(plan,'one')
        with self.assertRaisesRegex(ComponentError,'component.reference'):lower.provider_config(plan,'unknown')

    def test_runtime_init_source_and_retained_rootfs_bindings_preserve_declared_metadata(self):
        plan=fixture();selected=app();selected['storage']={'data':{'volume':'data','subpath':'flows'}}
        plan.resolved['apps']={'selected':selected,'elsewhere':app(guest='other',name='elsewhere')}
        before=copy.deepcopy(plan.resolved)
        result=lower.runtime_config(plan,'one');row=result['applications']['selected']
        self.assertEqual(set(result['applications']),{'selected'})
        self.assertEqual(row['project_name'],'owned-project');self.assertEqual(row['project_file'],'compose-owned.yml')
        self.assertEqual(row['storage_paths']['data']['source'],'/srv/example/data/flows')
        self.assertEqual(row['storage_paths']['data']['volume_root'],'/srv/example/data')
        self.assertEqual(plan.resolved,before)
        selected.update(lifecycle='retained',storage={'data':{'root_path':'retained','subpath':'flows'}})
        row=lower.runtime_config(plan,'one')['applications']['selected']
        self.assertEqual(row['storage_paths']['data']['source'],'/srv/example/retained/flows')
        self.assertNotIn('volume_root',row['storage_paths']['data'])
        selected['lifecycle']='fresh'
        with self.assertRaisesRegex(ComponentError,'component.storage-initialization-volume'):lower.runtime_config(plan,'one')
        selected['storage']={'data':{'volume':'data','subpath':''}}
        with self.assertRaisesRegex(ComponentError,'component.storage-initialization-volume'):lower.runtime_config(plan,'one')

    def test_native_and_unsupported_asset_or_incomplete_runtime_branches_are_explicit(self):
        plan=fixture();plan.resolved['apps']={'selected':app('postgresql',native=True)}
        selected=lower.runtime_config(plan,'one')['applications']['selected']
        self.assertNotIn('project_name',selected)
        plan.resolved['apps']['selected']['adapter']='node_red'
        with self.assertRaisesRegex(ComponentError,'component.runtime-incomplete'):lower.runtime_config(plan,'one')
        plan.resolved['apps']['selected']=dict(app(),storage={'data':{'asset':'unsupported'}})
        with self.assertRaisesRegex(ComponentError,'component.runtime-incomplete'):lower.runtime_config(plan,'one')
        with self.assertRaisesRegex(ComponentError,'component.reference'):lower.runtime_config(plan,'unknown')

    def test_route_plan_and_auth_or_existing_external_secret_refs_are_owned_copies(self):
        plan=fixture();plan.resolved['routes']={'selected':{'route':{'owned':True}}}
        ingress=app('traefik',name='ingress');cloud=app('cloudbeaver',name='cloud');cloud['authentication_resolved']={'client_secret':'oauth'}
        explorer=app('mqtt_explorer',name='explorer');explorer['settings']={'broker':{'credential':{'secret':'broker-password'}}}
        plan.resolved['apps']={'ingress':ingress,'cloud':cloud,'explorer':explorer}
        result=lower.runtime_config(plan,'one')['applications']
        self.assertEqual(result['cloud']['input_sources']['client_secret'],plan.site['secret_sources']['oauth'])
        self.assertEqual(result['explorer']['input_sources']['broker_password'],plan.site['secret_sources']['broker-password'])
        self.assertEqual(set(result['ingress']['route_plan']),{'routes','middlewares','transports','canonical_middlewares'})
        result['cloud']['input_sources']['client_secret']['path']='/modified'
        self.assertEqual(plan.site['secret_sources']['oauth']['path'],'/controller/oauth')

    def test_managed_broker_runtime_uses_selected_producer_project_service_and_data_source(self):
        plan=fixture();producer=app('mqtt',name='producer');producer['identity']['services']={'mqtt':'owned-broker'}
        producer['storage']={'config':{'root_path':'retained','subpath':'broker/config'}}
        explorer=app('mqtt_explorer',name='explorer');explorer['settings']={'broker':{'managed_credential':{
            'credential_id':'selected-reader'},'target':{'app':'producer','endpoint':'mqtt'}}}
        plan.resolved['apps']={'producer':producer,'explorer':explorer}
        plan.library['app_profiles']['profile']['storage']['config']={'kind':'directory','target':'/mosquitto/config','read_only':False}
        row=lower.runtime_config(plan,'one')['applications']['explorer']['settings']['broker']['runtime']
        self.assertEqual(row,{'project':'owned-project','service':'owned-broker',
                              'config_path':'/srv/example/retained/broker/config'})


if __name__=='__main__':unittest.main()
