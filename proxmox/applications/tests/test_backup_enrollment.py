"""Real protected records, fake PBS mutations, and no native client execution."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_enrollment as subject
import backup_identity
from private_io import encoded, read_json, write_new
import test_backup_worker as worker_fixture


class API:
    store = 'recovery'
    def __init__(self):
        self.people = []; self.spaces = {''}; self.acls = []; self.calls = []; self.failure = None
    def users(self): return copy.deepcopy(self.people)
    def namespaces(self): return set(self.spaces)
    def permission(self, auth_id):
        return {row['path']:{'Datastore.Backup':True} for row in self.acls if row['ugid']==auth_id}
    def request(self, method, path, fields=None):
        self.calls.append((method,path,copy.deepcopy(fields)))
        if self.failure == (method,path): raise ValueError('synthetic interrupted request')
        if method=='GET': return {'data':copy.deepcopy(self.acls),'digest':'a'*64}
        if path.endswith('/namespace'):
            self.spaces.add('/'.join(filter(None,(fields['parent'],fields['name'])))); return {'data':None}
        if path=='/access/users':
            self.people.append({'userid':fields['userid'],'comment':fields['comment'],'enable':True,'expire':0,'tokens':[]})
        elif path.endswith('/token/backup'):
            user=next(row for row in self.people if row['userid']==path.split('/')[3])
            token={'tokenid':user['userid']+'!backup','comment':fields['comment'],'enable':True,'expire':0}
            user['tokens'].append(token)
            return {'data':{'tokenid':token['tokenid'],'value':'synthetic-token-secret'}}
        elif path=='/access/acl': self.acls.append({'path':fields['path'],'ugid':fields['auth-id']})
        else: raise AssertionError('unexpected fake API operation')
        return {'data':None}


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077); self.addCleanup(os.umask,self.mask)
        temporary=tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve(); self.api=API(); self.keys=[]
        fixture=worker_fixture.WorkerTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        value=fixture.value; self.job=value['job']; self.guest=value['owner']
        self.selected=backup_identity.binding(self.job['destination'],self.guest,self.job['group']['name'],str(self.root))
        self.job['destination']['auth_id']=self.selected['auth_id']; self.job['secrets']=self.selected['secrets']
        self.directory=Path(self.selected['directory'])
    def key(self, *, create):
        self.keys.append(create); return b'synthetic-native-key'
    def run_provision(self, key=None):
        return subject.provision(self.job,self.guest,str(self.root),self.api,key or self.key)

    def test_first_enrollment_then_repeat_preserve_remote_and_local_identity(self):
        self.assertEqual(self.run_provision(),self.selected)
        self.assertEqual(self.keys,[True])
        files={path.name:path.read_bytes() for path in self.directory.iterdir()}
        writes=[row for row in self.api.calls if row[0]!='GET']
        self.run_provision(); self.assertEqual(self.keys,[True,False])
        self.assertEqual([row for row in self.api.calls if row[0]!='GET'],writes)
        self.assertEqual({path.name:path.read_bytes() for path in self.directory.iterdir()},files)
        self.assertEqual(self.directory.stat().st_mode & 0o777,0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.directory.iterdir()))
        self.assertFalse((self.directory/'PENDING.json').exists())

    def test_preexisting_foreign_remote_object_refuses_before_credential_creation(self):
        for kind in ('user','namespace','acl'):
            self.api=API()
            if kind=='user': self.api.people=[{'userid':self.selected['user']}]
            elif kind=='namespace': self.api.spaces.add(self.selected['namespace'])
            else: self.api.acls=[{'ugid':self.selected['auth_id']}]
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'unowned PBS'): self.run_provision()
            self.assertFalse(self.directory.exists()); self.assertEqual(self.keys,[])

    def test_interrupted_native_key_creation_is_preserved_and_cannot_retry(self):
        def failure(**kwargs): raise ValueError('synthetic key failure')
        with self.assertRaisesRegex(ValueError,'key failure'): self.run_provision(failure)
        self.assertTrue((self.directory/'PENDING.json').exists())
        self.assertTrue((self.directory/'pbs-password').exists())
        self.assertEqual(read_json(self.directory/'FAILED.json')['automatic_retry'],False)
        before=copy.deepcopy(self.api.calls)
        with self.assertRaisesRegex(ValueError,'no automatic retry'): self.run_provision()
        self.assertEqual(self.api.calls,before)

    def test_lost_token_response_never_recreates_or_adopts_the_account(self):
        self.api.failure=('POST','/access/users/'+self.selected['user']+'/token/backup')
        with self.assertRaises(ValueError): self.run_provision()
        self.assertEqual(len(self.api.people),1)
        self.assertFalse((self.directory/'pbs-password').exists())
        self.api.failure=None
        with self.assertRaisesRegex(ValueError,'no automatic retry'): self.run_provision()
        self.assertEqual(self.keys,[])

    def test_repeat_refuses_modified_local_or_remote_credentials_without_repair(self):
        self.run_provision(); raw=(self.directory/'pbs-key').read_bytes()
        (self.directory/'pbs-key').write_bytes(b'edited')
        with self.assertRaisesRegex(ValueError,'exact stored'): self.run_provision()
        (self.directory/'pbs-key').write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'deployed PBS encryption key'):
            self.run_provision(lambda **kwargs:b'different')
        self.api.people[0]['comment']='foreign'
        with self.assertRaisesRegex(ValueError,'account owner'): self.run_provision()

    def test_effective_permissions_cannot_expand_to_parent_or_another_namespace(self):
        self.run_provision()
        self.api.acls.append({'ugid':self.selected['auth_id'],'path':'/datastore/recovery'})
        with self.assertRaisesRegex(ValueError,'effective permissions'): self.run_provision()

    def test_complete_record_or_private_path_cannot_be_linked_or_renamed(self):
        self.run_provision()
        target=self.directory/'complete.json'; os.link(target,self.root/'linked')
        with self.assertRaisesRegex(ValueError,'single owned'): self.run_provision()

    def test_disabled_client_has_no_authority_to_create_private_or_remote_objects(self):
        with self.assertRaises(FileNotFoundError):
            subject.provision(self.job,self.guest,str(self.root),self.api,self.key,allow_create=False)
        self.assertFalse(self.directory.parent.exists());self.assertEqual(self.api.calls,[])
        self.directory.parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'disabled guests are read-only'):
            subject.provision(self.job,self.guest,str(self.root),self.api,self.key,allow_create=False)
        self.assertFalse(self.directory.exists());self.assertEqual(self.api.calls,[])
    def test_existing_shared_prefix_is_preserved_and_only_leaf_is_created(self):
        self.api.spaces.add('guests');self.run_provision()
        namespaces=[call for call in self.api.calls if call[0]=='POST' and call[1].endswith('/namespace')]
        self.assertEqual(len(namespaces),1)
        self.assertEqual(namespaces[0][2]['parent'],'guests')
    def test_remote_owner_refuses_expired_disabled_foreign_or_extra_tokens(self):
        self.run_provision();original=copy.deepcopy(self.api.people)
        changes=[lambda u:u.update(expire=1),lambda u:u.update(enable=False),lambda u:u.update(tokens=[]),
                 lambda u:u['tokens'].append(copy.deepcopy(u['tokens'][0])),
                 lambda u:u['tokens'][0].update(comment='foreign'),lambda u:u['tokens'][0].update(expire=1),
                 lambda u:u['tokens'][0].update(enable=False)]
        for change in changes:
            self.api.people=copy.deepcopy(original);change(self.api.people[0])
            with self.subTest(change=changes.index(change)),self.assertRaises(ValueError):self.run_provision()
        self.api.people=original;self.api.spaces.remove(self.selected['namespace'])
        with self.assertRaisesRegex(ValueError,'namespace is missing'):self.run_provision()
    def test_invalid_key_response_preserves_attempt_without_a_complete_record(self):
        with self.assertRaisesRegex(ValueError,'bounded native'):
            self.run_provision(lambda **kwargs:b'')
        self.assertTrue((self.directory/'FAILED.json').exists());self.assertFalse((self.directory/'complete.json').exists())

    def test_compiler_binding_mismatch_is_rejected_before_any_request(self):
        self.job['destination']['auth_id']='other@pbs!backup'
        with self.assertRaisesRegex(ValueError,'compiled PBS owner'): self.run_provision()
        self.assertEqual(self.api.calls,[])


if __name__ == '__main__': unittest.main()
