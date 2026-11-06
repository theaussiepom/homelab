"""Owned scratch I/O and exact helper entrypoints; native processes stay inert."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3])).resolve()
APP=F/'proxmox/applications'
sys.path[:0]=[str(APP),str(APP/'tests')]
import test_identity_callbacks_contract as callback_fixtures


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,APP/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


data=load('helper_boundary_data','component-data.py')
callbacks=load('helper_boundary_callbacks','identity_callbacks.py')
account=load('helper_boundary_account','mqtt-explorer-account.py')
health=load('helper_boundary_health','automation-health.py')


class ScratchCase(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)

    def cli(self,filename,argv,raw=None):
        output=io.StringIO();errors=io.StringIO()
        self.last_output,self.last_errors=output,errors
        stream=io.TextIOWrapper(io.BytesIO(raw or b''),encoding='utf-8')
        self.addCleanup(stream.close)
        with patch.object(sys,'argv',[str(APP/filename),*argv]), \
             patch.object(sys,'stdin',stream),patch.object(sys,'stdout',output),patch.object(sys,'stderr',errors):
            runpy.run_path(str(APP/filename),run_name='__main__')
        return output.getvalue(),errors.getvalue()


class MountAndStorageCLI(ScratchCase):
    def test_exact_provider_mount_is_required_not_ancestor_or_string_prefix(self):
        selected='/srv/fixture-data'
        raw=('31 20 8:1 / / rw - ext4 /dev/fixture rw\n'
             '32 31 8:2 / '+selected+' rw - ext4 /dev/provider rw\n').encode()
        source=self.root/'mountinfo';source.write_bytes(raw);source.chmod(0o600)
        original_open=open
        def mounted(path,mode):
            self.assertEqual((path,mode),('/proc/self/mountinfo','rb'))
            return original_open(source,mode)
        with patch('builtins.open',side_effect=mounted):
            self.assertTrue(data.mount(selected))
            self.assertFalse(data.mount(selected+'/apps'))
            self.assertFalse(data.mount('/srv/fixture'))
        self.assertEqual(source.read_bytes(),raw)

    def test_invalid_or_oversized_mount_projection_refuses_before_directory_creation(self):
        source=self.root/'mountinfo';original_open=open
        for raw in (b'too few fields\n',b'31 20 8:1 / /srv/data rw ext4 /dev/provider rw extra\n',
                    b'\xff\n',b'x'*(2*1024*1024+1)):
            source.write_bytes(raw)
            with self.subTest(shape=len(raw)),patch('builtins.open',side_effect=lambda *a:original_open(source,'rb')), \
                 patch.object(data.os,'mkdir') as create,self.assertRaises((ValueError,UnicodeError)):
                data.mount('/srv/data')
            create.assert_not_called()
        source.write_bytes(b'')
        with patch('builtins.open',side_effect=lambda *a:original_open(source,'rb')):
            self.assertFalse(data.mount('/srv/data'))

    def test_actual_storage_cli_noop_and_invalid_dispatch_never_open_native_paths(self):
        # A valid empty selection exercises the entrypoint without authorizing
        # any data directory; real creation/owner races have separate FS tests.
        with patch.object(os,'geteuid',return_value=0),patch.object(os,'open',
                side_effect=AssertionError('No unselected directory access')):
            out,error=self.cli('component-data.py',[],json.dumps({'directories':[],
                'previously_owned':False}).encode())
        self.assertEqual(json.loads(out),{'initialized':0,'verified':0,'created_directories':[]})
        self.assertEqual(error,'')
        cases=[([],b'{'),([],b'x'*(1024*1024+1)),(['unknown'],b'{}'),
               (['runtime'],b'{}'),([],b'{"directories":[],"previously_owned":1}')]
        for argv,raw in cases:
            with self.subTest(argv=argv,size=len(raw)),patch.object(os,'geteuid',return_value=0), \
                 patch.object(os,'open',side_effect=AssertionError('No invalid directory access')), \
                 self.assertRaises(SystemExit) as raised:
                self.cli('component-data.py',argv,raw)
            self.assertEqual(str(raised.exception),'Component storage preparation held; preserve existing data.')
        self.assertEqual(list(self.root.iterdir()),[])


class CallbackCLI(ScratchCase):
    def test_invalid_callback_port_is_redacted_and_never_reaches_native_process(self):
        for port in ('65536','invalid','-1'):
            value,*_=callback_fixtures.fixture()
            value['additions']=['https://db.example.invalid:'+port+'/oauth2/callback']
            with self.subTest(port=port),patch.object(callbacks.subprocess,'run') as native, \
                 self.assertRaisesRegex(ValueError,'^Retained identity callback guard refused$'):
                callbacks.run([value],self.root/'compose.yml','owned-server')
            native.assert_not_called()
        callbacks.uri('https://db.example.invalid:65535/oauth2/callback',True)

    def test_actual_callback_cli_binds_exact_config_compose_service_and_projects_safe_result(self):
        value,*_=callback_fixtures.fixture();path=self.root/'callbacks.json'
        path.write_text(json.dumps([value]));path.chmod(0o600)
        original=(path.stat().st_ino,path.read_bytes());compose=self.root/'compose-owned.yml'
        result={'callbacks':'verified','providers':1,'changed':1}
        response=SimpleNamespace(stdout='private SDK startup detail\n'+json.dumps(result)+'\n')
        with patch.object(subprocess,'run',return_value=response) as native:
            out,error=self.cli('identity_callbacks.py',['--config',str(path),'--compose',str(compose),
                '--service','owned-auth-server'])
        self.assertEqual(json.loads(out),result);self.assertEqual(error,'')
        self.assertNotIn('private SDK',out)
        self.assertEqual((path.stat().st_ino,path.read_bytes()),original)
        argv=native.call_args.args[0]
        self.assertEqual(argv[:10],['docker','compose','-f',str(compose),'exec','-T',
            '-e','PGOPTIONS=-c default_transaction_read_only=on','owned-auth-server','python'])
        self.assertEqual(native.call_args.kwargs['timeout'],60)
        self.assertTrue(native.call_args.kwargs['check']);self.assertTrue(native.call_args.kwargs['capture_output'])
        payload=json.loads(native.call_args.kwargs['input'])
        self.assertEqual(payload['configuration'],[value]);self.assertEqual(payload['source'],(APP/'identity_callbacks.py').read_text())

    def test_actual_callback_cli_bad_metadata_or_service_refuses_without_native_and_bad_result_never_prints(self):
        value,*_=callback_fixtures.fixture();path=self.root/'callbacks.json';compose=self.root/'compose.yml'
        for bad,service in [([dict(value,provider_id=0)],'server'),([value],'../peer'),([], 'server')]:
            path.write_text(json.dumps(bad));path.chmod(0o600)
            with self.subTest(service=service,count=len(bad)),patch.object(subprocess,'run') as native,self.assertRaises(ValueError):
                self.cli('identity_callbacks.py',['--config',str(path),'--compose',str(compose),'--service',service])
            native.assert_not_called()
        path.write_text(json.dumps([value]))
        response=SimpleNamespace(stdout='{"callbacks":"verified","providers":2,"changed":1}\n')
        with patch.object(subprocess,'run',return_value=response),self.assertRaisesRegex(ValueError,'callback guard refused'):
            self.cli('identity_callbacks.py',['--config',str(path),'--compose',str(compose)])
        self.assertEqual(self.last_output.getvalue(),'');self.assertEqual(self.last_errors.getvalue(),'')
        self.assertEqual(json.loads(path.read_text()),[value])


class BrokerDirectoryDurability(ScratchCase):
    def test_sync_fsyncs_only_the_anchored_directory_and_closes_the_fd(self):
        selected=self.root/'configuration';selected.mkdir(mode=0o700)
        retained=selected/'passwd';retained.write_bytes(b'unchanged synthetic verifier\n')
        original=(retained.stat().st_ino,retained.read_bytes());called=[];real_sync=os.fsync
        def synced(fd):
            info=os.fstat(fd);called.append((fd,info.st_dev,info.st_ino));real_sync(fd)
        with patch.object(account.os,'fsync',side_effect=synced),patch.object(account,'docker') as native:
            account.sync(selected)
        native.assert_not_called();self.assertEqual(len(called),1)
        fd,device,inode=called[0];self.assertEqual((device,inode),(selected.stat().st_dev,selected.stat().st_ino))
        with self.assertRaises(OSError):os.fstat(fd)
        self.assertEqual((retained.stat().st_ino,retained.read_bytes()),original)

    def test_sync_failure_or_link_refuses_without_broker_or_data_mutation(self):
        selected=self.root/'configuration';selected.mkdir(mode=0o700)
        retained=selected/'passwd';retained.write_bytes(b'unchanged retained state')
        before=(selected.stat().st_ino,retained.stat().st_ino,retained.read_bytes());descriptors=[]
        def failed(fd):descriptors.append(fd);raise OSError('synthetic fsync failure')
        with patch.object(account.os,'fsync',side_effect=failed),patch.object(account,'docker') as native,self.assertRaises(OSError):
            account.sync(selected)
        native.assert_not_called()
        with self.assertRaises(OSError):os.fstat(descriptors[0])
        link=self.root/'link';link.symlink_to(selected,target_is_directory=True)
        with patch.object(account.os,'fsync') as sync,patch.object(account,'docker') as native,self.assertRaises(OSError):
            account.sync(link)
        sync.assert_not_called();native.assert_not_called()
        self.assertEqual((selected.stat().st_ino,retained.stat().st_ino,retained.read_bytes()),before)


class SelectedBrokerProbe(unittest.TestCase):
    def test_bound_broker_probe_retries_same_selected_path_without_other_app_or_protocol_calls(self):
        path=Path('/opt/homelab-app/runtime/broker_a/mqtt-probe.json')
        with patch.object(health,'mqtt',side_effect=[OSError('private transport detail'),None]) as mqtt, \
             patch.object(health,'http') as http,patch.object(health.time,'monotonic',side_effect=[0,1]), \
             patch.object(health.time,'sleep') as sleep:
            self.assertEqual(health.run('mqtt-broker',path),{'service':'mqtt-broker','read_only_probe':'passed'})
        self.assertEqual(mqtt.call_args_list,[call(path,standalone=True),call(path,standalone=True)])
        http.assert_not_called();sleep.assert_called_once_with(2)

    def test_bound_broker_timeout_is_redacted_and_foreign_mode_or_path_refuses_before_probe(self):
        path=Path('/opt/homelab-app/runtime/broker_a/mqtt-probe.json')
        with patch.object(health,'mqtt',side_effect=ValueError('synthetic-private-password')), \
             patch.object(health.time,'monotonic',side_effect=[0,180]),patch.object(health.time,'sleep') as sleep, \
             self.assertRaisesRegex(ValueError,'^Application probe did not pass; inspect its private logs$'):
            health.run('mqtt-broker',path)
        sleep.assert_not_called()
        for service,selected in [('node_red',path),('mqtt-broker',Path('/tmp/peer.json'))]:
            with self.subTest(service=service),patch.object(health,'mqtt') as mqtt, \
                 patch.object(health.time,'monotonic') as clock,self.assertRaises(ValueError):health.run(service,selected)
            mqtt.assert_not_called();clock.assert_not_called()


if __name__=='__main__':unittest.main()
