"""Accepted service checks use SQLite fixtures and a Docker double, no targets."""
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import ast
import json
import re
import sys
import subprocess
import os
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pgadmin_database_runtime as runtime
import pgadmin_service_binding as builder
import pgadmin_service_verify as service
import test_pgadmin_database_network as fixtures


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RuntimeTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        # Mac lacks Linux xattr APIs. Exercise real device/inode/mode fields
        # while Linux CI also retains the existing native metadata unit tests.
        def metadata():
            s=runtime.file_info(runtime.PROFILE)
            return dict(device=s.st_dev,inode=s.st_ino,uid=s.st_uid,gid=s.st_gid,
                mode=format(s.st_mode&0o777,'04o'),xattrs_sha256=runtime.sha(runtime.encoded([])))
        self.addCleanup(patch.stopall);patch.object(runtime,'profile_identity',side_effect=metadata).start()
        with closing(sqlite3.connect(runtime.PROFILE)) as c:
            c.executescript('''CREATE TABLE query_history(uid INTEGER,sid INTEGER,query_info BLOB);
                CREATE TABLE "database"(id INTEGER,server INTEGER REFERENCES server(id),schema_res TEXT);
                INSERT INTO "database" VALUES(12345,7,'original schema visibility');''')
        self.request=self.f.quiesced()
        self.built=builder.build_binding(self.f.app,self.request)
        self.binding=self.built['binding']
        runtime.execute('activate',self.f.app,self.request)
        self.f.commands.clear()

    def verify(self,binding=None):return service.verify_accepted_service(self.f.app,binding or self.binding)

    def write(self,sql,args=()):
        with closing(sqlite3.connect(runtime.PROFILE)) as c:c.execute(sql,args);c.commit()

    def test_builder_uses_only_bound_backup_and_keeps_full_selected_row_private(self):
        runtime.PROFILE.unlink()
        self.f.commands.clear()
        with patch.object(runtime,'runtime',side_effect=AssertionError('No live adoption')):
            rebuilt=builder.build_binding(self.f.app,self.request)
        self.assertEqual(rebuilt,self.built);self.assertEqual(self.f.commands,[])
        text=str(rebuilt)
        for secret in ('retained-role','retained-db','one@example.invalid','sslmode','070809'):
            self.assertNotIn(secret,text)
        self.assertEqual(rebuilt['derived_from']['runtime_request_sha256'],runtime.sha(runtime.encoded(runtime.base_request(self.request))))

    def test_query_history_and_unrelated_preferences_are_allowed_without_writes(self):
        self.write('INSERT INTO query_history VALUES(?,?,?)',(1,9,b'synthetic SELECT1'))
        self.write('UPDATE setting SET value=?',('new editor preference',))
        before=self.f.dump();result=self.verify()
        self.assertEqual(result,dict(status='passed',kind='pgadmin-accepted-service',changed=False,
            deployment_verified=True,registration_verified=True,http_verified=True,current_sql_tested=False))
        self.assertEqual(self.f.dump(),before)
        self.assertTrue(all(c[len(runtime.DOCKER)] in ('compose','inspect') for c in self.f.commands))
        with self.assertRaisesRegex(ValueError,'Unapproved profile values changed'):
            runtime.execute('verify',self.f.app,self.request)

    def test_same_container_healthy_restart_timestamps_and_count_are_observations(self):
        self.f.row['State']['StartedAt']='later normal start';self.f.row['RestartCount']=7
        self.assertEqual(self.verify()['status'],'passed')

    def test_unrelated_accounts_registrations_and_database_preferences_can_evolve(self):
        self.write('UPDATE "database" SET schema_res=? WHERE server=9',('new visibility',))
        self.write('INSERT INTO user VALUES(?,?,?,?)',(99,'new@example.invalid',b'private new value','oauth2'))
        self.write('INSERT INTO server SELECT 99,99,name,host,port,username,password,maintenance_db,service,use_ssh_tunnel,shared,connection_params FROM server WHERE id=9')
        self.assertEqual(self.verify()['status'],'passed')

    def test_builder_result_cannot_mutate_original_request_by_alias(self):
        original=dict(self.request['profile_identity'])
        self.binding['profile_identity']['inode']=99
        self.assertEqual(self.request['profile_identity'],original)

    def test_credential_tls_or_display_row_edit_requires_reviewed_baseline(self):
        for sql,args in [('UPDATE server SET password=? WHERE id=9',(b'new encrypted value',)),
                         ('UPDATE server SET connection_params=? WHERE id=9',('{"sslmode":"disable"}',)),
                         ('UPDATE server SET name=? WHERE id=9',('new display name',))]:
            with self.subTest(sql=sql):
                with closing(sqlite3.connect(runtime.PROFILE)) as c:
                    old=c.execute('SELECT * FROM server WHERE id=9').fetchone()
                self.write(sql,args)
                with self.assertRaises(ValueError):self.verify()
                with closing(sqlite3.connect(runtime.PROFILE)) as c:
                    names=[r[1] for r in c.execute('PRAGMA table_info(server)')]
                    c.execute('UPDATE server SET '+','.join('"'+n+'"=?' for n in names)+' WHERE id=9',old);c.commit()

    def test_endpoint_owner_and_oauth_auth_source_drift_hold(self):
        for sql,args in [('UPDATE server SET host=? WHERE id=9',('198.18.30.23',)),
                         ('UPDATE server SET user_id=? WHERE id=9',(2,)),
                         ('UPDATE user SET auth_source=? WHERE id=1',('internal',))]:
            with self.subTest(sql=sql):
                self.write(sql,args)
                with self.assertRaises(ValueError):self.verify()
                self.write('UPDATE server SET host=?,user_id=1 WHERE id=9',('198.18.31.23',))
                self.write('UPDATE user SET auth_source=? WHERE id=1',('oauth2',))

    def test_server_schema_drift_holds(self):
        self.write('ALTER TABLE server ADD COLUMN unexpected_setting TEXT')
        with self.assertRaises(ValueError):self.verify()

    def test_profile_file_metadata_and_container_identity_remain_strict(self):
        runtime.PROFILE.chmod(0o644)
        with self.assertRaises(ValueError):self.verify()
        runtime.PROFILE.chmod(0o600);self.f.row['Id']='d'*64
        with self.assertRaises(ValueError):self.verify()

    def test_unsafe_transport_and_inactive_container_hold(self):
        self.write('UPDATE server SET use_ssh_tunnel=1 WHERE id=9')
        with self.assertRaises(ValueError):self.verify()
        self.write('UPDATE server SET use_ssh_tunnel=0 WHERE id=9');self.f.row['State']['Running']=False
        with self.assertRaises(ValueError):self.verify()

    def test_closed_binding_refuses_actions_or_drift_before_runtime(self):
        for bad in (dict(self.binding,action='activate'),dict(self.binding,schema='unknown'),
                    dict(self.binding,selector={'server_id':True,'user_id':1})):
            with patch.object(runtime,'runtime',side_effect=AssertionError('Reject before target read')):
                with self.assertRaises(ValueError):self.verify(bad)

    def test_builder_rejects_backup_or_receipt_tampering_and_closed_request(self):
        for bad in (dict(self.request,command='start'),dict(self.request,quiesced=dict(self.request['quiesced'],backup_sha256='0'*64))):
            with self.assertRaises(ValueError):builder.build_binding(self.f.app,bad)
        runtime.backup_path(self.request).write_bytes(b'changed')
        with self.assertRaises(ValueError):builder.build_binding(self.f.app,self.request)

    def test_http_failure_is_a_hold_and_never_recovers(self):
        with patch.object(runtime,'http_ready',side_effect=ValueError('Unavailable')):
            with self.assertRaises(ValueError):self.verify()
        self.assertFalse(any(c[len(runtime.DOCKER)] in ('start','stop') for c in self.f.commands))


class PlaybookTests(unittest.TestCase):
    def test_actual_embedded_source_payloads_compile_and_cli_rejects_secret_input(self):
        root=Path(__file__).resolve().parents[1]
        lookup=re.compile(r"{{ lookup\('ansible.builtin.file', playbook_dir \+ '/../([^']+)'\) \| to_json }}")
        for name in ('pgadmin-service-binding.yml','pgadmin-service-verify.yml'):
            text=(root/'ansible'/name).read_text()
            blocks=re.findall(r'(?m)^          - \|\n((?:            [^\n]*\n|\n)+)',text)
            self.assertEqual(len(blocks),3)
            for block in blocks:
                payload='\n'.join(line[12:] if line.startswith('            ') else line for line in block.splitlines())
                payload=lookup.sub(lambda m:json.dumps((root/m.group(1)).read_text()),payload)
                ast.parse(payload)
            self.assertNotIn('database_network_action',text)
            self.assertNotIn('          - --action',text)
        for name in ('pgadmin_service_binding.py','pgadmin_service_verify.py'):
            result=subprocess.run([sys.executable,str(root/name)],input=b'{"private-secret":"must-not-escape"}',capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(b'must-not-escape',result.stderr+result.stdout)

    @unittest.skipUnless(shutil.which('ansible-playbook'),'Syntax also runs in hosted Linux tools')
    def test_single_purpose_playbook_syntax(self):
        import tempfile
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            for name in ('pgadmin-service-binding.yml','pgadmin-service-verify.yml'):
                result=subprocess.run(['ansible-playbook','-i','localhost,','--syntax-check',str(root/'ansible'/name)],
                    env=dict(os.environ,ANSIBLE_CONFIG=str(root/'ansible/ansible.cfg'),ANSIBLE_LOCAL_TEMP=directory),capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
