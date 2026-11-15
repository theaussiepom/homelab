"""Dedicated bootstrap custody and direct protected-secret delivery, without targets."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import nfs_access
from bootstrap import Refused


class NfsAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.key=self.root/'operator';self.key.write_bytes(b'operator-private')
        self.known=self.root/'hosts';self.known.write_bytes(b'trusted-hosts')
        self.env=patch.dict(os.environ,{'HOMELAB_SSH_KEY':str(self.key),'HOMELAB_KNOWN_HOSTS':str(self.known)})
        self.env.start();self.addCleanup(self.env.stop)
        self.calls=[];self.failure=None;self.raw=b'-----BEGIN OPENSSH PRIVATE KEY-----\nseparate-fixture\n-----END OPENSSH PRIVATE KEY-----\n'
    def execute(self,args,**kwargs):
        self.calls.append((args,kwargs))
        if args[0]=='docker':
            private=next(v[:-len(':/secret-transport')] for v in args if v.endswith(':/secret-transport'))
            (Path(private)/'key').write_bytes(self.raw)
            if self.failure=='custody':(Path(private)/'key').chmod(0o644)
            return subprocess.CompletedProcess(args,1 if self.failure=='bootstrap' else 0)
        self.assertEqual(kwargs['input'],self.raw)
        self.assertNotIn(self.raw.decode(),str(args));self.assertEqual(kwargs['env']['GH_DEBUG'],'')
        return subprocess.CompletedProcess(args,1 if self.failure=='secret' else 0)
    def setup(self,out=None):
        return nfs_access.setup('example/private-site',['apps-camera'],'198.18.25.1','198.18.25.10',out or self.root/'attempt')
    def mocks(self):
        return patch.multiple(nfs_access.cd_access,environment=unittest.mock.DEFAULT,github=unittest.mock.DEFAULT)
    def test_provisions_only_capability_then_delivers_private_key_via_stdin(self):
        with self.mocks()as services,patch.object(nfs_access.subprocess,'run',side_effect=self.execute):
            services['github'].return_value={'name':'PROXMOX_NFS_SSH_KEY'}
            result=self.setup()
            self.assertFalse(result['guest_mounts_changed']);self.assertFalse(result['key_rotated'])
            self.assertEqual([c[0][0] for c in self.calls],['docker','gh'])
            self.assertEqual(services['environment'].call_count,2)
            self.assertEqual(services['environment'].call_args.kwargs,{'create':False,'name':'apps-camera'})
            private=next(v.split(':/secret-transport')[0] for v in self.calls[0][0] if v.endswith(':/secret-transport'))
            self.assertFalse(Path(private).exists())
            self.assertEqual((self.root/'attempt').stat().st_mode&0o777,0o700)
            self.assertNotIn(self.raw.decode(),(self.root/'attempt/inventory.json').read_text())
    def test_bad_scope_existing_output_and_failed_stages_never_retry(self):
        with self.mocks()as services,patch.object(nfs_access.subprocess,'run',side_effect=self.execute)as run:
            for repo,env in [('bad', ['apps-camera']),('example/site',[]),('example/site',['same','same']),('example/site',['bad/route'])]:
                with self.subTest(repo=repo,env=env),self.assertRaises(Refused):
                    nfs_access.setup(repo,env,'198.18.25.1','198.18.25.10',self.root/'bad')
            with self.assertRaises(Refused):self.setup(self.root)
            run.assert_not_called()
            for failure in ('bootstrap','secret','metadata','custody','key'):
                self.failure=failure;self.calls=[]
                services['github'].return_value={'name':'wrong'}
                if failure=='key':self.raw=b'wrong private format'
                with self.subTest(failure=failure),self.assertRaises(Refused):self.setup(self.root/failure)
                self.assertLessEqual(len(self.calls),2)
                self.assertFalse((self.root/failure/'result.json').exists())
    def test_cli_reports_only_safe_result_or_failure(self):
        args=['nfs-access','--repository','example/site','--host','198.18.25.1','--runner','198.18.25.10',
              '--environment','apps-camera','--out',str(self.root/'cli')]
        for failure in (False,True):
            with patch.object(sys,'argv',args),patch.object(nfs_access,'setup',side_effect=ValueError('PRIVATE') if failure else None,return_value={'status':'ready'}), \
                 patch('sys.stdout',new_callable=io.StringIO)as out:
                self.assertEqual(nfs_access.main(),int(failure));self.assertNotIn('PRIVATE',out.getvalue())
    def test_script_entry_requires_explicit_inputs_before_any_action(self):
        import runpy
        with patch.object(sys,'argv',['nfs-access']),patch('sys.stderr',new_callable=io.StringIO),self.assertRaises(SystemExit)as end:
            runpy.run_path(nfs_access.__file__,run_name='__main__')
        self.assertEqual(end.exception.code,2)

    def test_play_uses_separate_reused_key_and_restricted_immutable_helper(self):
        import yaml
        plays=yaml.safe_load((Path(nfs_access.HERE)/'ansible/host-nfs.yml').read_text())
        self.assertEqual([p['hosts']for p in plays],['deploy','pve','deploy'])
        tasks=[t for p in plays for t in p['tasks']]
        keys=[t for t in tasks if t.get('ansible.builtin.command',{}).get('argv',[None])[0]=='ssh-keygen']
        self.assertEqual(len(keys),2);self.assertIn('when',keys[0]);self.assertTrue(keys[0]['no_log'])
        line=plays[1]['vars']['nfs_line'];self.assertIn('restrict,from=',line);self.assertIn('command="/usr/bin/python3 -I',line)
        self.assertNotIn('--policy',line)
        copies=[t['ansible.builtin.copy']for t in tasks if 'ansible.builtin.copy'in t]
        self.assertTrue(all(c['force'] is False for c in copies))
        self.assertTrue(all(t.get('no_log')for t in tasks if 'ansible.builtin.fetch'in t))


if __name__=='__main__':unittest.main()
