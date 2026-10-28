"""Disposable SQLite and an exact Docker double; never a native guest test."""
import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import shutil
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pgadmin_database_runtime as runtime
from test_pgadmin_endpoint import profile, SELECTOR


def endpoint_rows(connection):
    return connection.execute('SELECT id,user_id,name,host,port FROM server ORDER BY id').fetchall()


@unittest.skipUnless(hasattr(os,'listxattr'),'Runtime metadata tests require Linux xattr APIs')
class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name).resolve()
        self.paths = dict(COMPOSE=root/'compose.json', IDENTITY=root/'identity.json',
                          CONFIG=root/'config.py', PROFILE=root/'data/pgadmin4.db', BACKUPS=root/'backups')
        for path in self.paths.values(): path.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(patch.stopall)
        patch.multiple(runtime, **self.paths).start()
        self.app = dict(kind='db-tools', vmid=202, hostname='db-tools', address='198.18.25.32', mac='02:00:00:00:00:32')
        identity = {k:self.app[k] for k in ('kind','vmid','hostname','address')}
        self.paths['IDENTITY'].write_text(json.dumps(identity))
        self.paths['CONFIG'].write_bytes(b'# retained OAuth config; never changed\n')
        memory = profile()
        with closing(sqlite3.connect(self.paths['PROFILE'])) as destination: memory.backup(destination)
        memory.close()
        self.image = 'dpage/pgadmin4@sha256:'+'1'*64
        service = dict(image=self.image, user=str(os.getuid()), restart='unless-stopped',
            ports=['198.18.30.32:80:80'], volumes=[
                dict(type='bind',source=str(self.paths['PROFILE'].parent),target='/var/lib/pgadmin'),
                dict(type='bind',source=str(self.paths['CONFIG']),target='/pgadmin4/config_local.py',read_only=True)])
        self.paths['COMPOSE'].write_text(json.dumps(dict(name='homelab-db-tools',services={'pgadmin':service})))
        for name in ('COMPOSE','IDENTITY','CONFIG','PROFILE'): self.paths[name].chmod(0o600)
        self.row = {'Id':'c'*64, 'Image':'sha256:'+'2'*64,'RestartCount':0,
            'Config':{'Image':self.image,'User':str(os.getuid()),'Labels':{
                'com.docker.compose.project':'homelab-db-tools','com.docker.compose.service':'pgadmin'}},
            'HostConfig':{'RestartPolicy':{'Name':'unless-stopped'}},
            'Mounts':[{'Type':'bind','Source':str(self.paths['PROFILE'].parent),'Destination':'/var/lib/pgadmin','RW':True},
                      {'Type':'bind','Source':str(self.paths['CONFIG']),'Destination':'/pgadmin4/config_local.py','RW':False}],
            'State':{'Running':True,'Paused':False,'Restarting':False,'OOMKilled':False,
                     'StartedAt':'2026-01-01T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z'}}
        self.commands = []
        patch.object(runtime,'command',side_effect=self.docker).start()
        patch.object(runtime,'http_ready',return_value=None).start()
        self.inspect_request = dict(compose_sha256=self.sha('COMPOSE'),identity_sha256=self.sha('IDENTITY'),
            config_sha256=self.sha('CONFIG'),image=self.image,http_address='198.18.30.32',selector=SELECTOR,
            target={'address':'198.18.31.23','port':5432})

    def sha(self, key): return hashlib.sha256(self.paths[key].read_bytes()).hexdigest()

    def docker(self, argv):
        self.commands.append(argv)
        args = argv[len(runtime.DOCKER):]
        if args[:1] == ['compose']: return (self.row['Id']+'\n').encode()
        if args[:1] == ['inspect']: return json.dumps([self.row]).encode()
        if args[:1] == ['stop']:
            self.row['State'].update(Running=False,FinishedAt='2026-01-01T01:00:00Z')
            return b''
        if args[:1] == ['start']:
            self.row['State'].update(Running=True,StartedAt='2026-01-01T02:00:00Z')
            return b''
        raise AssertionError('Unexpected Docker operation')

    def prepared(self):
        inspected = runtime.execute('inspect',self.app,self.inspect_request)
        return runtime.prepare({'address':'198.18.31.23','port':5432},inspected,SELECTOR,'198.18.30.23')

    def quiesced(self):
        request = self.prepared()
        result = runtime.execute('quiesce',self.app,request)
        return dict(request,quiesced=result['quiesced'])

    def dump(self):
        with closing(sqlite3.connect(self.paths['PROFILE'])) as connection: return '\n'.join(connection.iterdump())

    def test_inspect_and_preflight_are_read_only_and_return_no_profile_secrets(self):
        before=self.dump(); request=self.prepared()
        result=runtime.execute('preflight',self.app,request)
        self.assertEqual(result['status'],'passed')
        self.assertEqual(self.dump(),before)
        self.assertFalse(self.paths['BACKUPS'].exists())
        self.assertFalse(any(c[len(runtime.DOCKER)] in ('stop','start') for c in self.commands))
        for text in ('retained-role','retained-db','one@example.invalid'):
            self.assertNotIn(text,json.dumps(request))

    def test_backup_and_exact_replacement_resume_preserve_unapproved_profile_values(self):
        before=self.dump(); metadata=runtime.profile_identity(); request=self.quiesced()
        self.assertFalse(self.row['State']['Running'])
        result=runtime.execute('activate',self.app,request)
        self.assertEqual(result['status'],'passed')
        self.assertTrue(self.row['State']['Running'])
        with runtime.database(self.paths['PROFILE']) as connection:
            self.assertEqual(endpoint_rows(connection),[(9,1,'PostgreSQL','198.18.31.23',5432)])
            self.assertEqual(connection.execute('SELECT value FROM setting').fetchone()[0],'retained')
        self.assertEqual(runtime.profile_identity(),metadata)
        verification=runtime.execute('verify',self.app,request)
        self.assertTrue(verification['profile_verified'])
        self.assertFalse(verification['database_verified'])
        self.assertIn('authenticated',verification['database_verification_reason'])
        self.assertEqual(len([c for c in self.commands if c[len(runtime.DOCKER)]=='start']),1)

    def test_observed_hostname_is_bound_independently_from_legacy_network_address(self):
        with closing(sqlite3.connect(self.paths['PROFILE'])) as connection:
            connection.execute('UPDATE server SET host=? WHERE id=? AND user_id=?',
                               ('postgresql',SELECTOR['server_id'],SELECTOR['user_id']))
            connection.commit()
        request=self.quiesced()
        self.assertEqual(request['before'],{'host':'postgresql','port':5432})
        self.assertEqual(runtime.execute('activate',self.app,request)['status'],'passed')
        with runtime.database(self.paths['PROFILE']) as connection:
            self.assertEqual(runtime.selected_row(connection,{'server_id':9,'user_id':1}),{'host':'198.18.31.23','port':5432})

    def test_existing_backup_operation_holds_in_preflight_before_stop(self):
        request=self.prepared()
        runtime.backup_path(request,create=True)
        with self.assertRaises(ValueError): runtime.execute('preflight',self.app,request)
        self.assertTrue(self.row['State']['Running'])
        self.assertFalse(any(c[len(runtime.DOCKER)]=='stop' for c in self.commands))

    def test_restart_or_start_during_provider_cycle_prevents_activation(self):
        request=self.quiesced(); before=self.dump()
        self.row['State'].update(StartedAt='2026-01-01T01:30:00Z',FinishedAt='2026-01-01T01:31:00Z')
        with self.assertRaises(ValueError): runtime.execute('activate',self.app,request)
        self.assertEqual(self.dump(),before)
        self.assertFalse(self.row['State']['Running'])

    def test_changed_compose_image_or_profile_fails_before_stopping(self):
        request=self.prepared();self.paths['COMPOSE'].write_bytes(b'changed')
        with self.assertRaises(ValueError): runtime.execute('preflight',self.app,request)
        with self.assertRaises(ValueError): runtime.execute('quiesce',self.app,request)
        self.assertTrue(self.row['State']['Running'])

    def test_failed_update_never_implicitly_resumes_or_restores(self):
        request=self.quiesced()
        with closing(sqlite3.connect(self.paths['PROFILE'])) as c:
            c.execute("UPDATE setting SET value='external-change'");c.commit()
        before=self.dump()
        with self.assertRaises(ValueError): runtime.execute('activate',self.app,request)
        self.assertFalse(self.row['State']['Running']);self.assertEqual(self.dump(),before)

    def test_packet_cannot_select_commands_source_paths_or_another_owner(self):
        for extra in ({'command':['sh']},{'source':'/etc/shadow'}):
            with self.assertRaises(ValueError): runtime.execute('inspect',self.app,dict(self.inspect_request,**extra))
        inspected=runtime.execute('inspect',self.app,self.inspect_request)
        with self.assertRaises(ValueError): runtime.prepare({'address':'198.18.31.23','port':5432},inspected,{'server_id':7,'user_id':2},'198.18.30.23')

    def test_pure_controller_gate_owns_packet_and_uses_shared_catalogue_validator(self):
        request=self.prepared()
        catalogue={'networks':{'postgresql':{'clients':[{'vmid':202,'hostname':'db-tools'},{'vmid':211,'hostname':'security'}]}}}
        common=types.ModuleType('database_networks');common.validate=lambda value:value
        common.endpoint=lambda value,engine:{'address':'198.18.31.23','port':5432}
        with patch.dict(sys.modules,{'database_networks':common}):
            self.assertTrue(runtime.validate_binding(request,catalogue,[211,202],'198.18.30.23'))
            for field,value in [('target',{'address':'198.18.30.23','port':5432}),('image','mutable:latest'),
                                 ('identity',dict(request['identity'],hostname='foreign')),
                                 ('profile_identity',dict(request['profile_identity'],source='/etc/shadow'))]:
                bad=copy.deepcopy(request);bad[field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):
                    runtime.validate_binding(bad,catalogue,[211,202],'198.18.30.23')
            with self.assertRaises(ValueError): runtime.validate_binding(request,catalogue,[211],'198.18.30.23')
            with self.assertRaises(ValueError): runtime.validate_binding(dict(request,command=['sh']),catalogue,[211,202],'198.18.30.23')

    def test_backup_tampering_and_wrong_restart_policy_hold_without_resume(self):
        self.row['HostConfig']['RestartPolicy']['Name']='always'
        with self.assertRaises(ValueError): self.prepared()
        self.row['HostConfig']['RestartPolicy']['Name']='unless-stopped'
        request=self.quiesced();runtime.backup_path(request).write_bytes(b'changed')
        with self.assertRaises(ValueError): runtime.execute('activate',self.app,request)
        self.assertFalse(self.row['State']['Running'])

    def test_coherent_backup_includes_committed_wal_without_checkpointing_source(self):
        writer=sqlite3.connect(self.paths['PROFILE']);self.addCleanup(writer.close)
        writer.execute('PRAGMA journal_mode=WAL')
        writer.execute("UPDATE setting SET value='committed-in-wal'");writer.commit()
        self.assertTrue(Path(str(self.paths['PROFILE'])+'-wal').exists())
        request=self.quiesced()
        result=runtime.execute('activate',self.app,request)
        self.assertEqual(result['status'],'passed')
        self.assertEqual(writer.execute('SELECT value FROM setting').fetchone()[0],'committed-in-wal')


class PlaybookTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ansible-playbook'),'Ansible syntax is exercised in pinned Linux tools')
    def test_playbook_syntax(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.run(['ansible-playbook','-i','localhost,','--syntax-check',str(root/'ansible/pgadmin-database-network.yml')],
                env=dict(os.environ,ANSIBLE_CONFIG=str(root/'ansible/ansible.cfg'),ANSIBLE_LOCAL_TEMP=directory),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
