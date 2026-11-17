"""Additive host keys preserve Proxmox custody and the existing pinned route."""
import base64
import copy
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import personal_ssh as cli
import host_ssh as host
import component_control as control
import component_ssh as keys

KEY = 'ssh-ed25519 '+base64.b64encode(keys.WIRE_PREFIX+b'\x01'*32).decode()
OTHER = 'ssh-ed25519 '+base64.b64encode(keys.WIRE_PREFIX+b'\x02'*32).decode()
REQUEST = {'node': 'pve-example', 'keys': [KEY]}
SOURCE = 'a'*64


def snapshot(raw):
    return {'exists': True, 'content': base64.b64encode(raw).decode(),
            'sha256': control.fingerprint(raw), 'uid': 0, 'gid': 33, 'mode': 0o600}


class HostTests(unittest.TestCase):
    def setUp(self):
        self.value = snapshot(b'# existing opaque comment\xff\n'+OTHER.encode())
        self.writes = []
        self.enterContext(patch.object(host, 'platform'))
        self.enterContext(patch.object(host, 'locked', side_effect=nullcontext))
        self.enterContext(patch.object(host, 'inspect', side_effect=lambda: (copy.deepcopy(self.value), [1,2,0,0,3])))
        self.enterContext(patch.object(host, 'store', side_effect=self.store))

    def store(self, before, raw):
        self.assertEqual(before, self.value)
        self.writes.append(raw)
        self.value = snapshot(raw)

    def test_plan_apply_repeat_preserve_every_byte_and_metadata(self):
        before = copy.deepcopy(self.value)
        plan = host.run(REQUEST, SOURCE)
        self.assertTrue(plan['changed']);self.assertEqual(plan['key_writes'], 0)
        self.assertEqual(self.value, before)
        result = host.run(REQUEST, SOURCE, plan['plan_sha256'])
        self.assertTrue(result['applied']);self.assertEqual(result['key_writes'], 1)
        self.assertEqual(control.validate_file(self.value), control.validate_file(before)+b'\n'+KEY.encode()+b'\n')
        repeated = host.run(REQUEST, SOURCE)
        self.assertFalse(repeated['changed'])
        self.assertEqual(host.run(REQUEST, SOURCE, repeated['plan_sha256'])['key_writes'], 0)
        self.assertEqual(len(self.writes), 1)

    def test_existing_constrained_key_never_becomes_unrestricted(self):
        self.value = snapshot(b'from="198.18.0.0/24",restrict '+KEY.encode()+b' comment"\xff\n')
        self.assertFalse(host.run(REQUEST, SOURCE)['changed'])
        with self.assertRaises(ValueError):keys.append('not bytes', [KEY])

    def test_changed_preimage_source_and_link_refuse_before_write(self):
        plan = host.run(REQUEST, SOURCE)
        before=copy.deepcopy(self.value)
        for mutation in ['source','content']:
            with self.subTest(mutation=mutation):
                self.value = snapshot(b'changed') if mutation=='content' else copy.deepcopy(before)
                with self.assertRaises(ValueError):host.run(REQUEST, 'b'*64 if mutation=='source' else SOURCE, plan['plan_sha256'])
        self.assertFalse(self.writes)
        with patch.object(host,'inspect',return_value=(before,[9])),self.assertRaises(ValueError):host.run(REQUEST,SOURCE,plan['plan_sha256'])
        with self.assertRaises(ValueError):host.run(REQUEST, 'wrong')

    def test_unexpected_readback_is_not_success(self):
        plan=host.run(REQUEST,SOURCE)
        with patch.object(host,'store'):
            with self.assertRaises(ValueError):host.run(REQUEST,SOURCE,plan['plan_sha256'])
        with patch.object(host,'inspect',side_effect=[(copy.deepcopy(self.value),[1]),(copy.deepcopy(self.value),[2])]):
            with self.assertRaises(ValueError):host.run(REQUEST,SOURCE)

    def test_closed_request_rejects_credentials_invalid_and_duplicate_keys(self):
        for value in [None,{},dict(REQUEST,private_key='never'),dict(REQUEST,node='../pve'),
                      dict(REQUEST,keys=[]),dict(REQUEST,keys=[KEY]*65),dict(REQUEST,keys=['bad']),dict(REQUEST,keys=[KEY,KEY])]:
            with self.subTest(value=value),self.assertRaises(ValueError):host.request(value)


class CustodyTests(unittest.TestCase):
    def test_platform_requires_root_correct_node_and_one_existing_node(self):
        with patch.object(host.os,'geteuid',return_value=0),patch.object(host.socket,'gethostname',return_value='pve-example'),\
                patch.object(host.os.path,'ismount',return_value=True),\
                patch.object(host.Path,'resolve',return_value=Path('/etc/pve/nodes/pve-example')),\
                patch.object(host.Path,'iterdir',return_value=iter([Path('/etc/pve/nodes/pve-example')])):
            host.platform('pve-example')
        with patch.object(host.os,'geteuid',return_value=1000),self.assertRaises(ValueError):host.platform('pve-example')
        with patch.object(host.os,'geteuid',return_value=0),patch.object(host.socket,'gethostname',return_value='pve-example'),\
                patch.object(host.os.path,'ismount',return_value=True),\
                patch.object(host.Path,'resolve',return_value=Path('/etc/pve/nodes/pve-example')),\
                patch.object(host.Path,'iterdir',return_value=iter([Path('/etc/pve/nodes/pve-example'),Path('/etc/pve/nodes/another-node')])),self.assertRaises(ValueError):
            host.platform('pve-example')

    def test_only_the_canonical_pve_symlink_and_metadata_are_supported(self):
        def info(path):
            if str(path)==host.LINK:return os.stat_result((stat.S_IFLNK|0o777,2,1,1,0,0,29,0,0,0))
            gid=33 if str(path).startswith('/etc/pve')else 0
            mode=0o755 if str(path)=='/etc/pve'else 0o700
            return os.stat_result((stat.S_IFDIR|mode,2,1,1,0,gid,0,0,0,0))
        with patch.object(host.os,'lstat',side_effect=info),patch.object(host.os,'readlink',return_value=host.TARGET),\
                patch.object(control,'capture_file',return_value=snapshot(b'public')):
            captured,link=host.inspect();self.assertEqual(captured['gid'],33);self.assertEqual(len(link),5)
            with patch.object(host.os,'readlink',return_value='/another/place'),self.assertRaises(ValueError):host.inspect()
            with patch.object(control,'capture_file',return_value=snapshot(b'public')|{'mode':0o644}),self.assertRaises(ValueError):host.inspect()
            with patch.object(host.os,'lstat',return_value=os.stat_result((stat.S_IFREG|0o600,2,1,1,0,0,0,0,0,0))),self.assertRaises(ValueError):host.inspect()

    def test_lock_serializes_supported_writers_and_refuses_foreign_metadata(self):
        with tempfile.TemporaryDirectory()as tmp:
            path=str(Path(tmp)/'lock')
            with patch.object(host,'LOCK',path),patch.object(host.os,'fstat',return_value=os.stat_result((stat.S_IFREG|0o600,2,1,1,0,0,0,0,0,0))):
                with host.locked():
                    with self.assertRaises(BlockingIOError):
                        with host.locked():pass
                with patch.object(host.os,'fstat',return_value=os.stat_result((stat.S_IFREG|0o644,2,1,1,0,0,0,0,0,0))),self.assertRaises(ValueError):
                    with host.locked():pass

    def test_cluster_writer_receives_only_exact_before_hash_and_additive_public_bytes(self):
        with patch.object(host.subprocess,'run',return_value=subprocess.CompletedProcess([],0))as run:
            host.store(snapshot(b'old'),b'old\n'+KEY.encode())
        argv=run.call_args.args[0];self.assertEqual(argv[:2],['perl','-e'])
        value=json.loads(run.call_args.kwargs['input']);self.assertEqual(value['before'],control.fingerprint(b'old'))
        self.assertIn('PVE::Tools::file_set_contents',argv[2])
        self.assertNotIn('pvecm',argv)
        with patch.object(host.subprocess,'run',return_value=subprocess.CompletedProcess([],1)),self.assertRaises(ValueError):host.store(snapshot(b'old'),b'old\n')


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.work=self.root/'work';self.path=self.root/'request.json'
        self.path.write_text(json.dumps(REQUEST));self.value=snapshot(b'original\n')

    def remote(self,host_name,request,source,apply,modules):
        def store(before,raw):self.value=snapshot(raw)
        with patch.object(host,'platform'),patch.object(host,'locked',side_effect=nullcontext),\
                patch.object(host,'inspect',side_effect=lambda:(copy.deepcopy(self.value),[1,2,0,0,3])),patch.object(host,'store',side_effect=store):
            return host.run(request,source,apply)

    def invoke(self,apply=''):
        with patch.object(cli,'remote',side_effect=self.remote):return cli.run(self.work,self.path,'pve-example',apply)

    def test_real_plan_apply_repeat_and_wrong_hash(self):
        plan=self.invoke();result=self.invoke(plan['plan_sha256']);self.assertTrue(result['changed'])
        repeated=self.invoke();self.assertFalse(repeated['changed']);self.assertEqual(self.invoke(repeated['plan_sha256'])['key_writes'],0)
        with self.assertRaises(cli.Refused):self.invoke('wrong')
        self.assertFalse((self.work/'SSH-UNKNOWN.json').exists())

    def test_uncertain_apply_retains_exact_attempt_and_prevents_another_write(self):
        plan=self.invoke()
        with patch.object(cli,'remote',side_effect=subprocess.TimeoutExpired('ssh',45)),self.assertRaises(subprocess.TimeoutExpired):
            cli.run(self.work,self.path,'pve-example',plan['plan_sha256'])
        self.assertTrue((self.work/'SSH-UNKNOWN.json').is_file())
        with self.assertRaises(cli.Refused):self.invoke()

    def test_bad_result_is_preserved_without_false_success(self):
        plan=self.invoke()
        with patch.object(cli,'remote',return_value={'status':'unknown'}),self.assertRaises(cli.Refused):
            cli.run(self.work,self.path,'pve-example',plan['plan_sha256'])
        self.assertTrue(list(self.work.glob('apply-*/result.json')))

    def test_transport_pins_exact_host_and_never_opens_private_key_contents(self):
        key=self.root/'key';known=self.root/'known';key.touch();known.touch()
        modules=tuple((m.__name__,base64.b64encode(Path(m.__file__).read_bytes()).decode())for m in (control,keys,host))
        with patch.dict(os.environ,{'HOMELAB_SSH_KEY':str(key),'HOMELAB_KNOWN_HOSTS':str(known)}),\
                patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'{"status":"ready"}'))as call:
            self.assertEqual(cli.remote('pve-example',REQUEST,SOURCE,'',modules),{'status':'ready'})
            argv=call.call_args.args[0]
            self.assertEqual(argv[-2:],['root@pve-example','env PYTHONDONTWRITEBYTECODE=1 python3 -'])
            self.assertIn('StrictHostKeyChecking=yes',argv);self.assertIn('ControlMaster=no',argv)
            self.assertIn('UserKnownHostsFile='+str(known),argv)
            compile(call.call_args.kwargs['input'],'<packed-bootstrap>','exec')
            with patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],1)),self.assertRaises(cli.Refused):cli.remote('pve-example',REQUEST,SOURCE,'',modules)
            with self.assertRaises(cli.Refused):cli.remote('bad;host',REQUEST,SOURCE,'',modules)
            known.unlink()
            with self.assertRaises(cli.Refused):cli.remote('pve-example',REQUEST,SOURCE,'',modules)

    def test_apply_sends_hashed_snapshot_when_a_module_changes_before_packing(self):
        module=self.root/'module.py'
        before=Path(host.__file__).read_bytes()+b'\n# Original owned fixture\n'
        changed=before+b'# Concurrent fixture change\n';module.write_bytes(before)
        key=self.root/'key';known=self.root/'known';key.touch();known.touch()
        transmit=cli.remote
        def racing(host_name,request,source,apply,modules):
            module.write_bytes(changed)
            self.assertEqual(source,cli.digest([Path(cli.__file__).read_text(),modules]))
            def transport(argv,**kwargs):
                program=kwargs['input']
                self.assertIn(base64.b64encode(before).decode(),program)
                self.assertNotIn(base64.b64encode(changed).decode(),program)
                result=self.remote(host_name,request,source,apply,modules)
                return subprocess.CompletedProcess(argv,0,json.dumps(result))
            with patch.object(cli.subprocess,'run',side_effect=transport):
                return transmit(host_name,request,source,apply,modules)
        with patch.object(host,'__file__',str(module)),\
                patch.dict(os.environ,{'HOMELAB_SSH_KEY':str(key),'HOMELAB_KNOWN_HOSTS':str(known)}):
            plan=self.invoke()
            with patch.object(cli,'remote',side_effect=racing):
                result=cli.run(self.work,self.path,'pve-example',plan['plan_sha256'])
        self.assertEqual(result['key_writes'],1)
        self.assertEqual(module.read_bytes(),changed)

    def test_dangling_unknown_marker_prevents_contact(self):
        self.work.mkdir();(self.work/'SSH-UNKNOWN.json').symlink_to(self.root/'absent')
        with patch.object(cli,'remote',side_effect=AssertionError('no contact')),self.assertRaises(cli.Refused):self.invoke()

    def test_public_example_is_a_complete_request(self):
        example=Path(cli.__file__).with_name('personal-ssh.example.json')
        host.request(json.loads(example.read_text()))

    def test_main_reports_success_and_stopped_without_native_contact(self):
        args=['personal_ssh.py','--work',str(self.work),'--request',str(self.path),'--host','pve-example']
        with patch.object(sys,'argv',args),patch.object(cli,'run',return_value={'status':'ready'}),patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(cli.main(),0)
        with patch.object(sys,'argv',args),patch.object(cli,'run',side_effect=ValueError('fixture')),patch('sys.stdout',new_callable=io.StringIO):self.assertEqual(cli.main(),2)
        with patch.object(sys,'argv',['personal_ssh.py','--help']),patch('sys.stdout',new_callable=io.StringIO),self.assertRaises(SystemExit)as caught:
            runpy.run_path(cli.__file__,run_name='__main__')
        self.assertEqual(caught.exception.code,0)


if __name__=='__main__':unittest.main()
