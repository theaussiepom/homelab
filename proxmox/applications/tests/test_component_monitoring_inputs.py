"""Phase-owned mocks and real synthetic existing credential relationship tests."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

F=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(F/'proxmox/applications'))
import monitoring_inputs as owned
import component_monitoring_inputs as builder


def cfg(root, *, vmid=808, hostname='database', profiles=None):
    return {'site':{'node':'fixture-pve','api_endpoint':'https://198.18.25.10:8006/'},
        'guest':{'vmid':vmid,'hostname':hostname},'paths':{'state_root':str(root),'ca_file':str(root/'public.pem')},
        'deployment':{'applications':{'database':{'id':'pg','adapter':'postgresql'},'server':{'id':'observer','adapter':'zabbix'},'peer':{'id':'vault','adapter':'bitwarden'}}},
        'app':{'monitoring':{'profiles':['linux','postgresql']if profiles is None else profiles,
            'server_active':'198.18.25.36:10051','server_vmid':816,'server_hostname':'zabbix',
            'credential_file':str(root/'payload/monitoring-agent.json'),
            'database_password_file':str(root/'payload/monitoring-database-password'),
            'storage_password_file':str(root/'payload/monitoring-storage-password')}}}


def root_server(root):
    value=cfg(root,vmid=816,hostname='zabbix',profiles=['linux','docker']);value['app']['monitoring'].pop('database_password_file');value['app']['monitoring'].pop('storage_password_file')
    value['app']['monitoring'].update(members=[{'vmid':808,'guest_hostname':'database'},{'vmid':816,'guest_hostname':'zabbix'}],proxmox={'hostname':'fixture-pve','endpoint':value['site']['api_endpoint'],'ca_file':value['paths']['ca_file']},server_file=str(root/'payload/monitoring-server.json'))
    return value


def provider(root,value):
    folder=root/'provider';folder.mkdir(mode=0o700)
    token=folder/'token.json'
    for name,document in [('token.json',{'identity':owned.TOKEN_ID,'token':owned.TOKEN_ID+'=synthetic-token'}),
        ('owner.json',{'schema':'homelab-zabbix-access-v1','endpoint':value['site']['api_endpoint'],'node':value['site']['node'],'address':'198.18.25.36','backup_source':'nas:/synthetic'}),
        ('READY.json',{'identity':owned.TOKEN_ID,'read_only':True})]:
        path=folder/name;path.write_text(json.dumps(document)+'\n');path.chmod(0o600)
    return token


class MonitoringComponentInputsTests(unittest.TestCase):
    def test_absent_feature_and_unselected_peer_do_not_touch_provider_or_keys(self):
        with patch.object(owned,'provider')as admission,patch.object(owned,'credential')as credential:
            self.assertEqual(builder.prepare({'app':{}},agent=True),{})
            self.assertEqual(builder.prepare(cfg(Path('/synthetic')),app={'id':'vault','adapter':'bitwarden'}),{})
        admission.assert_not_called();credential.assert_not_called()
    def test_agent_unit_owns_only_own_psk_and_native_statistics_password(self):
        value=cfg(Path('/synthetic'))
        with patch.object(owned,'provider',return_value={})as admission,patch.object(builder,'private_directory'),patch.object(owned,'agent',return_value='a'*64)as psk,patch.object(owned,'credential',return_value={'password':'b'*64})as password:
            result=builder.prepare(value,agent=True)
        self.assertEqual(set(result),{'monitoring-agent.json','monitoring-database-password'});self.assertEqual(json.loads(result['monitoring-agent.json']),{'psk':'a'*64});self.assertEqual(result['monitoring-database-password'],b'b'*64)
        admission.assert_called_once_with(value);psk.assert_called_once_with(Path('/synthetic/monitoring-credentials'),{'vmid':808,'guest_hostname':'database'},'fixture-pve');self.assertEqual(password.call_args.args[1:3],('database-808.json',owned.identity(value)))
    def test_postgresql_storage_unit_does_not_materialize_agent_or_server_inventory(self):
        value=cfg(Path('/synthetic'))
        with patch.object(owned,'provider',return_value={}),patch.object(builder,'private_directory'),patch.object(owned,'credential',return_value={'database_password':'c'*64,'admin_password':'Zbx!7'+'d'*64})as credential,patch.object(owned,'agent')as agent:
            result=builder.prepare(value,app={'id':'pg','adapter':'postgresql'})
        self.assertEqual(result,{'monitoring-storage-password':b'c'*64});agent.assert_not_called();self.assertEqual(credential.call_args.args[1:3],('server-816.json',{'node':'fixture-pve','vmid':816,'hostname':'zabbix'}))
    def test_storage_not_selected_is_noop_not_inferred_from_every_postgresql_app(self):
        value=cfg(Path('/synthetic'));value['app']['monitoring'].pop('storage_password_file')
        with patch.object(owned,'provider')as admission:self.assertEqual(builder.prepare(value,app={'id':'pg','adapter':'postgresql'}),{})
        admission.assert_not_called()
    def test_root_server_unit_owns_only_database_admin_members_and_ca(self):
        value=root_server(Path('/synthetic'));app={'id':'observer','adapter':'zabbix','settings':{'database_credential':{'type':'monitoring-owned','server':'observer'}}}
        with patch.object(owned,'provider',return_value={'token':owned.TOKEN_ID+'=synthetic-token'}),patch.object(builder,'private_directory'),patch.object(owned,'credential',return_value={'database_password':'c'*64,'admin_password':'Zbx!7'+'d'*64}),patch.object(owned,'agent',return_value='a'*64),patch.object(builder,'regular',return_value=b'public-ca'):
            result=builder.prepare(value,app=app)
        self.assertEqual(set(result),{'database-password','proxmox-ca.pem','monitoring-server.json'});document=json.loads(result['monitoring-server.json']);self.assertEqual(document['proxmox']['token_secret'],'synthetic-token');self.assertEqual(len(document['members']),2);self.assertNotIn('monitoring-agent.json',result)
    def test_nonowned_zabbix_does_not_infer_an_internal_password_source(self):
        value=root_server(Path('/synthetic'));app={'id':'observer','adapter':'zabbix','settings':{}}
        with patch.object(owned,'provider')as admission:self.assertEqual(builder.prepare(value,app=app),{})
        admission.assert_not_called()
    def test_missing_foreign_server_identity_and_wrong_payload_leaf_refuse_before_keys(self):
        for case in ('hostname','vmid','leaf','app','both'):
            value=cfg(Path('/synthetic'));kwargs={'agent':True}
            if case=='hostname':value['app']['monitoring'].pop('server_hostname')
            elif case=='vmid':value['app']['monitoring']['server_vmid']=True
            elif case=='leaf':value['app']['monitoring']['credential_file']='/foreign/private.json'
            elif case=='app':kwargs={'app':{'id':'foreign','adapter':'postgresql'}}
            else:kwargs['app']={'id':'pg','adapter':'postgresql'}
            with self.subTest(case=case),patch.object(owned,'provider')as admission,patch.object(owned,'credential')as keys,self.assertRaises(ValueError):builder.prepare(value,**kwargs)
            admission.assert_not_called();keys.assert_not_called()
    def test_root_server_owner_cannot_be_rebound_by_app_metadata(self):
        value=root_server(Path('/synthetic'));value['guest']['hostname']='foreign';app={'id':'observer','adapter':'zabbix','settings':{'database_credential':{'type':'monitoring-owned','server':'observer'}}}
        with patch.object(owned,'provider')as admission,self.assertRaises(ValueError):builder.prepare(value,app=app)
        admission.assert_not_called()
    def test_provider_admission_failure_precedes_any_create_once_materialization(self):
        with patch.object(owned,'provider',side_effect=ValueError('held')),patch.object(owned,'credential')as keys,patch.object(owned,'agent')as psk,self.assertRaises(ValueError):builder.prepare(cfg(Path('/synthetic')),agent=True)
        keys.assert_not_called();psk.assert_not_called()
    def test_real_synthetic_shared_server_key_matches_old_contract_without_rotation(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);root.chmod(0o700);server=root_server(root);(root/'public.pem').write_bytes(b'synthetic-public-ca');token=provider(root,server)
            legacy=copy.deepcopy(server);legacy['app']['kind']='monitoring';legacy['app']['monitoring'].pop('server_hostname')
            app={'id':'observer','adapter':'zabbix','settings':{'database_credential':{'type':'monitoring-owned','server':'observer'}}}
            with patch.object(owned,'PROVIDER',token):
                old=owned.prepare(legacy,None,root/'legacy-payload')
                before={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()}
                new=builder.prepare(server,app=app);pg=builder.prepare(cfg(root),app={'id':'pg','adapter':'postgresql'});own_agent=builder.prepare(server,agent=True)
                self.assertEqual(new,{name:old[name]for name in ('database-password','proxmox-ca.pem','monitoring-server.json')})
                self.assertEqual(pg['monitoring-storage-password'],new['database-password']);self.assertEqual(own_agent['monitoring-agent.json'],old['monitoring-agent.json'])
                after={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()};self.assertEqual(before,after)
    def test_real_existing_credential_owner_drift_stops_without_rewrite(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);root.chmod(0o700);value=cfg(root);token=provider(root,value)
            with patch.object(owned,'PROVIDER',token):
                builder.prepare(value,app={'id':'pg','adapter':'postgresql'});path=root/'monitoring-credentials/server-816.json';raw=path.read_bytes();value['app']['monitoring']['server_hostname']='different'
                with self.assertRaises(ValueError):builder.prepare(value,app={'id':'pg','adapter':'postgresql'})
                self.assertEqual(path.read_bytes(),raw)
    def test_real_hold_ready_owner_and_token_refuse_without_creating_store(self):
        for case in ('hold','ready','owner','token'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as directory:
                root=Path(directory);root.chmod(0o700);value=cfg(root);token=provider(root,value)
                if case=='hold':(token.parent/'HOLD.json').write_text('{}')
                elif case=='ready':(token.parent/'READY.json').write_text('{}')
                elif case=='owner':(token.parent/'owner.json').write_text('{}')
                else:token.write_text('{}')
                with patch.object(owned,'PROVIDER',token),self.assertRaises(ValueError):builder.prepare(value,agent=True)
                self.assertFalse((root/'monitoring-credentials').exists())

if __name__=='__main__':unittest.main()
