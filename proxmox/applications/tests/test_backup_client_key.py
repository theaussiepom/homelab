"""Native command contract with disposable private files and a fake key generator."""
import base64
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_client_key as subject
import backup_identity
from private_io import encoded, write_new
import test_backup_worker as worker_fixture


class ClientKeyTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077); self.addCleanup(os.umask,self.mask)
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        fixture=worker_fixture.WorkerTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.value=fixture.value
        write_new(self.root/'coverage.json',encoded(self.value))
        self.identity=backup_identity.identity(self.value['job']['destination'],self.value['owner'],self.value['job']['group']['name'])[1]
        self.calls=[]
        self.raw=encoded({'kdf':None,'created':'2026-01-01T00:00:00Z','modified':'2026-01-01T00:00:00Z',
                          'data':base64.b64encode(b'x'*32).decode(),'fingerprint':':'.join(['ab']*32)})
    def native(self,argv):
        self.calls.append(argv)
        if argv[2]=='create': write_new(Path(argv[3]),self.raw)
    def call(self,action='create',identity=None,run=None):
        return subject.client_key({'action':action,'identity':identity or self.identity},root=self.root,run=run or self.native)
    def test_create_and_read_keep_exact_key_and_owner(self):
        self.assertEqual(self.call(),self.raw)
        self.assertEqual(self.calls[0],['/usr/bin/proxmox-backup-client','key','create',str(self.root/'pbs-key'),'--kdf','none'])
        self.assertEqual(self.calls[1][1:3],['key','show'])
        self.assertEqual(self.call('read'),self.raw); self.assertEqual(len(self.calls),2)
        self.assertFalse((self.root/'client-key-pending.json').exists())
        with self.assertRaisesRegex(ValueError,'adoption'): self.call()
    def test_mismatch_or_foreign_key_refuses_before_mutation(self):
        with self.assertRaisesRegex(ValueError,'coverage owner'): self.call(identity='a'*64)
        (self.root/'pbs-key').symlink_to(self.root/'missing')
        with self.assertRaisesRegex(ValueError,'adoption'): self.call()
        self.assertEqual(self.calls,[])
    def test_native_failure_keeps_intent_and_never_retries(self):
        def failed(argv): raise subprocess.CalledProcessError(1,argv)
        with self.assertRaises(subprocess.CalledProcessError): self.call(run=failed)
        self.assertTrue((self.root/'client-key-pending.json').exists())
        for action in ('create','read'):
            with self.assertRaisesRegex(ValueError,'no automatic retry'): self.call(action)
    def test_malformed_encrypted_short_or_linked_key_cannot_be_adopted(self):
        for changes in ({'kdf':{}},{'data':base64.b64encode(b'x').decode()},{'data':'!'}):
            with self.subTest(changes=changes):
                key=self.root/'pbs-key'; data=__import__('json').loads(self.raw); data.update(changes)
                key.write_bytes(encoded(data)); key.chmod(0o600)
                with self.assertRaises(ValueError): subject.key_bytes(key)
                key.unlink()
        write_new(self.root/'pbs-key',self.raw); os.link(self.root/'pbs-key',self.root/'duplicate')
        with self.assertRaisesRegex(ValueError,'single owned'): subject.key_bytes(self.root/'pbs-key')
    def test_modified_key_or_receipt_refuses_without_regeneration(self):
        self.call(); key=self.root/'pbs-key'
        value=__import__('json').loads(self.raw); value['data']=base64.b64encode(b'y'*32).decode()
        key.write_bytes(encoded(value))
        with self.assertRaisesRegex(ValueError,'exact native key'): self.call('read')
        self.assertEqual(len(self.calls),2)
    def test_cli_is_root_only_bounded_and_keeps_key_out_of_diagnostics(self):
        import io
        import runpy
        from types import SimpleNamespace
        for uid,args,raw in ((1000,['helper'],b'{}'),(0,['helper','extra'],b'{}'),(0,['helper'],b'x'*4097)):
            with patch.object(subject.os,'geteuid',return_value=uid),patch.object(sys,'argv',args), \
                 patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),self.assertRaises(ValueError):subject.main()
        output=io.BytesIO()
        with patch.object(subject.os,'geteuid',return_value=0),patch.object(sys,'argv',['helper']), \
             patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'{}'))), \
             patch.object(sys,'stdout',SimpleNamespace(buffer=output)),patch.object(subject,'client_key',return_value=b'synthetic key'):
            subject.main()
        self.assertEqual(output.getvalue(),b'synthetic key')
        with patch.object(subject.os,'geteuid',return_value=1000),patch.object(sys,'argv',['helper']),self.assertRaises(ValueError):
            runpy.run_path(subject.__file__,run_name='__main__')

    def test_native_boundary_drops_inherited_environment_and_all_output(self):
        with patch.object(subject.subprocess,'run') as run:
            subject.native(['fixed','argument'])
        _,kwargs=run.call_args
        self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG'})
        self.assertEqual(kwargs['timeout'],60)
        self.assertEqual(kwargs['stdout'],subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)


if __name__=='__main__': unittest.main()
