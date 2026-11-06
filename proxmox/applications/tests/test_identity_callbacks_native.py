"""Actual callback implementation with transactional in-memory Django boundaries."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
from uuid import UUID

SOURCE=Path(os.environ.get('IDENTITY_CALLBACKS_MODULE',Path(__file__).resolve().parents[1]/'identity_callbacks.py'))
sys.path.insert(0,str(SOURCE.parent))
SPEC=importlib.util.spec_from_file_location('native_identity_callbacks_under_test',SOURCE)
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)


def canonical(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()


def uid(value):return UUID(int=value)


class Query:
    def __init__(self,db,name,rows):self.db,self.name,self.rows=db,name,rows
    def select_for_update(self):
        if not self.db.active:raise AssertionError('ORM lock outside transaction')
        self.db.events.append(('lock',self.name));return self
    def filter(self,**fields):
        def matches(row):
            for key,value in fields.items():
                if key.endswith('__in'):
                    if row[key[:-4]] not in value:return False
                elif str(row[key])!=str(value):return False
            return True
        return Query(self.db,self.name,[row for row in self.rows if matches(row)])
    def values(self,*fields):
        return Query(self.db,self.name,[{key:row[key]for key in fields}for row in self.rows])
    def values_list(self,*fields,flat=False):
        return [row[fields[0]]if flat else tuple(row[key]for key in fields)for row in self.rows]
    def get(self,**fields):
        selected=self.filter(**fields).rows if fields else self.rows
        if len(selected)!=1:raise LookupError('fixture cardinality')
        return copy.deepcopy(selected[0])
    def __getitem__(self,item):return self.rows[item]
    def __iter__(self):return iter(self.rows)


class Provider:
    def __init__(self,db):
        self.db=db;self.refresh_from_db()
        self.property_mappings=Query(db,'mapping_relation',db.mappings)
    def refresh_from_db(self):
        for key,value in self.db.provider.items():setattr(self,key,copy.deepcopy(value))
    def save(self,*,update_fields):
        if not self.db.active:raise AssertionError('save outside transaction')
        self.db.saved_fields.append(list(update_fields))
        for key in update_fields:self.db.provider[key]=copy.deepcopy(getattr(self,key))
        if self.db.after_save:self.db.after_save(self.db)


class ProviderManager:
    def __init__(self,db):self.db=db
    def select_for_update(self):
        if not self.db.active:raise AssertionError('provider lock outside transaction')
        self.db.events.append(('lock','provider'));return self
    def get(self,*,pk):
        if pk!=self.db.provider['pk']:raise LookupError('foreign provider')
        return Provider(self.db)


class Cursor:
    def __init__(self,db):self.db=db
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def execute(self,statement):self.db.sql.append(statement)


class Atomic:
    def __init__(self,db):self.db=db
    def __enter__(self):
        self.before=copy.deepcopy(self.db.provider);self.db.active=True
    def __exit__(self,kind,value,traceback):
        self.db.active=False
        if kind:
            self.db.provider=self.before;self.db.rollbacks+=1
        else:self.db.commits+=1
        return False


class Database:
    def __init__(self):
        self.active=False;self.events=[];self.saved_fields=[];self.sql=[]
        self.rollbacks=0;self.commits=0;self.after_save=None
        self.provider={'pk':42,'name':'database-tools','client_id':'public-test-client',
            'client_type':'confidential','_redirect_uris':[
                {'matching_mode':'strict','url':'https://old-tools.example.invalid/oauth2/authorize'}],
            'sub_mode':'hashed_user_id','issuer_mode':'per_provider','include_claims_in_id_token':True,
            'authentication_flow_id':None,'authorization_flow_id':uid(1),
            'invalidation_flow_id':uid(2),'signing_key_id':uid(3),'client_secret':'sample'}
        self.app={'pk':uid(4),'name':'Database Tools','slug':'database-tools','provider_id':42,
            'policy_engine_mode':'any','meta_launch_url':''}
        self.bindings=[{'pk':uid(5),'target_id':uid(4),'policy_id':None,'group_id':uid(6),
            'user_id':None,'order':0,'negate':False,'enabled':True,'timeout':30}]
        self.groups=[{'pk':uid(6),'name':'Database users','parent_id':None,'is_superuser':False}]
        self.expression="raise RuntimeError('must never evaluate'); return {'preferred_username': user.username, \"groups\": []}"
        self.mappings=[{'pk':uid(7),'name':'Profile claims','expression':self.expression}]
        self.scopes=[{'pk':uid(7),'scope_name':'profile'}]
        provider_metadata={key:value for key,value in self.provider.items()if key not in ('_redirect_uris','client_secret','client_id')}
        provider_metadata['client_id_sha256']=canonical(self.provider['client_id'])
        binding={key:value for key,value in self.bindings[0].items()if key not in ('target_id','user_id')}
        binding['user_binding_present']=False
        mapping={'pk':str(uid(7)),'name':'Profile claims','scope':'profile',
            'expression_sha256':hashlib.sha256(self.expression.encode()).hexdigest(),
            'claim_labels_present':['preferred_username','groups'],'expression_evaluated':False}
        policy={'policy_bindings':[binding],'bound_groups':self.groups,'property_mappings':[mapping]}
        self.record={'provider_id':42,'application_id':str(uid(4)),
            'client_id_sha256':canonical(self.provider['client_id']),
            'provider_metadata_sha256':canonical(provider_metadata),
            'application_metadata_sha256':canonical(self.app),'policy_metadata_sha256':canonical(policy),
            'existing_redirects':copy.deepcopy(self.provider['_redirect_uris']),
            'additions':['https://db.example.invalid/oauth2/callback']}
    @contextlib.contextmanager
    def installed(self,vendor='postgresql'):
        modules={name:types.ModuleType(name)for name in ('django','django.db','authentik','authentik.core',
            'authentik.core.models','authentik.providers','authentik.providers.oauth2',
            'authentik.providers.oauth2.models','authentik.policies','authentik.policies.models')}
        for module in modules.values():module.__path__=[]
        modules['django.db'].connection=types.SimpleNamespace(vendor=vendor,cursor=lambda:Cursor(self))
        modules['django.db'].transaction=types.SimpleNamespace(atomic=lambda:Atomic(self))
        modules['authentik.core.models'].Application=types.SimpleNamespace(objects=Query(self,'application',[self.app]))
        modules['authentik.core.models'].Group=types.SimpleNamespace(objects=Query(self,'group',self.groups))
        modules['authentik.core.models'].PropertyMapping=types.SimpleNamespace(objects=Query(self,'mapping',self.mappings))
        modules['authentik.providers.oauth2.models'].OAuth2Provider=types.SimpleNamespace(objects=ProviderManager(self))
        modules['authentik.providers.oauth2.models'].ScopeMapping=types.SimpleNamespace(objects=Query(self,'scope',self.scopes))
        modules['authentik.policies.models'].PolicyBinding=types.SimpleNamespace(objects=Query(self,'binding',self.bindings))
        with patch.dict(sys.modules,modules):yield


class CallbackNative(unittest.TestCase):
    def test_real_projection_hashes_claims_and_converts_uuids_without_evaluation(self):
        db=Database();provider={key:value for key,value in db.provider.items()if key!='client_secret'}
        bindings=[{key:value for key,value in db.bindings[0].items()if key!='target_id'}]
        before=copy.deepcopy((provider,db.app,bindings,db.groups,db.mappings))
        value=c.projection(provider,db.app,bindings,db.groups,db.mappings,{str(uid(7)):'profile'})
        self.assertEqual(value['provider']['client_id_sha256'],canonical('public-test-client'))
        self.assertNotIn('client_id',value['provider'])
        self.assertEqual(value['policy']['property_mappings'][0]['expression_sha256'],hashlib.sha256(db.expression.encode()).hexdigest())
        self.assertEqual(value['policy']['property_mappings'][0]['claim_labels_present'],['preferred_username','groups'])
        self.assertFalse(value['policy']['property_mappings'][0]['expression_evaluated'])
        self.assertNotIn('must never evaluate',json.dumps(value))
        self.assertNotIn('user_id',value['policy']['policy_bindings'][0])
        self.assertEqual((provider,db.app,bindings,db.groups,db.mappings),before)
        self.assertEqual(c.check(db.record,value['provider'],value['application'],value['policy'])[-1]['url'],db.record['additions'][0])

    def test_real_projection_user_presence_and_expression_bound(self):
        db=Database();provider={key:value for key,value in db.provider.items()if key!='client_secret'}
        binding={key:value for key,value in db.bindings[0].items()if key!='target_id'};binding['user_id']=uid(99)
        value=c.projection(provider,db.app,[binding],db.groups,db.mappings,{})
        self.assertTrue(value['policy']['policy_bindings'][0]['user_binding_present'])
        self.assertIsNone(value['policy']['property_mappings'][0]['scope'])
        for expression in (None,'x'*65537):
            with self.subTest(kind=type(expression).__name__),self.assertRaises(ValueError):
                c.projection(provider,db.app,[binding],db.groups,[{'pk':uid(7),'name':'Profile','expression':expression}],{})

    def test_exact_apply_changes_only_redirect_field_in_serializable_transaction(self):
        db=Database();before=copy.deepcopy(db.provider)
        with db.installed():result=c.apply_native([db.record])
        self.assertEqual(result,{'callbacks':'verified','providers':1,'changed':1})
        self.assertEqual(db.saved_fields,[['_redirect_uris']])
        self.assertEqual({k:v for k,v in db.provider.items()if k!='_redirect_uris'},
                         {k:v for k,v in before.items()if k!='_redirect_uris'})
        self.assertEqual(db.provider['_redirect_uris'],before['_redirect_uris']+[{'matching_mode':'strict','url':db.record['additions'][0]}])
        self.assertIn('SERIALIZABLE, READ WRITE',db.sql[0]);self.assertIn('statement_timeout',db.sql[1])
        self.assertEqual((db.commits,db.rollbacks),(1,0))

    def test_precondition_refuses_before_any_save_and_rolls_back(self):
        db=Database();before=copy.deepcopy(db.provider);db.app['policy_engine_mode']='all'
        with db.installed(),self.assertRaises(ValueError):c.apply_native([db.record])
        self.assertEqual(db.saved_fields,[]);self.assertEqual(db.provider,before)
        self.assertEqual((db.commits,db.rollbacks),(0,1))

    def test_exact_idempotent_state_does_not_save(self):
        db=Database();db.provider['_redirect_uris'] += [{'matching_mode':'strict','url':db.record['additions'][0]}]
        before=copy.deepcopy(db.provider)
        with db.installed():result=c.apply_native([db.record])
        self.assertEqual(result,{'callbacks':'verified','providers':1,'changed':0})
        self.assertEqual(db.saved_fields,[]);self.assertEqual(db.provider,before)

    def test_post_save_provider_or_secret_drift_raises_and_rolls_back(self):
        for field in ('client_secret','name','client_id'):
            db=Database();before=copy.deepcopy(db.provider)
            db.after_save=lambda value,key=field:value.provider.__setitem__(key,'changed')
            with self.subTest(field=field),db.installed(),self.assertRaises(ValueError):c.apply_native([db.record])
            self.assertEqual(db.provider,before);self.assertEqual(db.rollbacks,1)
            self.assertEqual(db.saved_fields,[['_redirect_uris']])

    def test_invalid_vendor_or_configuration_never_opens_transaction(self):
        db=Database()
        with db.installed(vendor='sqlite'),self.assertRaises(ValueError):c.apply_native([db.record])
        self.assertEqual(db.events,[]);self.assertEqual(db.saved_fields,[])
        bad=copy.deepcopy(db.record);bad['provider_id']=True
        with db.installed(),self.assertRaises(ValueError):c.apply_native([bad])
        self.assertEqual(db.events,[]);self.assertEqual(db.saved_fields,[])

    def test_run_returns_only_typed_result_and_does_not_print_native_logs(self):
        db=Database();stdout=io.StringIO();stderr=io.StringIO()
        result=types.SimpleNamespace(stdout='PRIVATE_STARTUP_LOG\n{"callbacks": "verified", "providers": 1, "changed": 1}\n',stderr='PRIVATE_NATIVE_STDERR')
        with patch.object(c.subprocess,'run',return_value=result) as call,contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            value=c.run([db.record],Path('/private/compose.json'))
        self.assertEqual(value,{'callbacks':'verified','providers':1,'changed':1})
        self.assertEqual(stdout.getvalue()+stderr.getvalue(),'')
        argv=call.call_args.args[0]
        self.assertIn('PGOPTIONS=-c default_transaction_read_only=on',argv)
        self.assertTrue(call.call_args.kwargs['capture_output']);self.assertTrue(call.call_args.kwargs['check'])
        payload=json.loads(call.call_args.kwargs['input'])
        self.assertEqual(payload['configuration'],[db.record]);self.assertIn('def apply_native',payload['source'])

    def test_native_failure_never_echoes_output_in_exception_or_console(self):
        db=Database();stdout=io.StringIO();stderr=io.StringIO()
        failure=subprocess.CalledProcessError(1,['docker','compose'],output='PRIVATE_NATIVE_STDOUT',stderr='PRIVATE_NATIVE_STDERR')
        with patch.object(c.subprocess,'run',side_effect=failure),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr),self.assertRaises(subprocess.CalledProcessError) as caught:
            c.run([db.record],Path('/private/compose.json'))
        self.assertNotIn('PRIVATE_NATIVE',str(caught.exception))
        self.assertEqual(stdout.getvalue()+stderr.getvalue(),'')

    def test_missing_duplicate_unexpected_or_mistyped_native_result_refuses(self):
        db=Database()
        for rows in ['PRIVATE_NATIVE_STDOUT',
            '{"callbacks": "verified", "providers": 1, "changed": 0}\n'*2,
            '{"callbacks": "verified", "providers": 1, "changed": 0, "unexpected": "PRIVATE_NATIVE_OUTPUT"}',
            '{"callbacks": "verified", "providers": true, "changed": 0}',
            '{"callbacks": "verified", "providers": 1, "changed": 2}']:
            result=types.SimpleNamespace(stdout=rows,stderr='PRIVATE_NATIVE_STDERR')
            with self.subTest(kind=rows[:30]),patch.object(c.subprocess,'run',return_value=result),self.assertRaises(ValueError) as caught:
                c.run([db.record],Path('/private/compose.json'))
            self.assertNotIn('PRIVATE_NATIVE',str(caught.exception))


if __name__=='__main__':unittest.main()
