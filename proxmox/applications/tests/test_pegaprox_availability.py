"""Enforce the commissioned guest's actual startup policy and immutable identity."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest

import pegaprox_availability as availability


class PegaProxAvailabilityTests(unittest.TestCase):
    def setUp(self):
        """Prepare an admitted commissioned runtime and its exact identities."""
        self.policy = {'schema':'homelab-pegaprox-availability-v1','vmid':214,
            'completion_sha256':'a'*64,'container_id':'b'*64,'image_id':'sha256:'+'c'*64,
            'compose_sha256':'d'*64,'restart_policy':'unless-stopped',
            'commissioning_binding':{'schema':'homelab-pegaprox-cd-v1','guest':'pegaprox','vmid':214,
                'prepared_sha256':'e'*64,'source_sha256':'f'*64,'input_hashes':{'/original/stack.json':'0'*64}}}
        self.cfg = {'guest':{'vmid':214,'hostname':'pegaprox','started':True,'start_on_boot':True},
            'app':{'vmid':214,'kind':'pegaprox'}}
        self.host = {'hostname':'pegaprox','protection':1,'unprivileged':1,'onboot':1}
        self.status = {'status':'running'}
        self.runtime = {'id':'b'*64,'image_id':'sha256:'+'c'*64,'running':True,
            'restart_policy':{'Name':'unless-stopped','MaximumRetryCount':0},
            'compose_sha256':'d'*64,'docker_enabled':True,'mounts':sorted([
                ['/srv/homelab/data/pegaprox/config','/app/config',True],
                ['/srv/homelab/data/pegaprox/logs','/app/logs',True],
                ['/opt/homelab-app/runtime/pegaprox-db-key','/run/secrets/pegaprox-db-key',False]])}

    def check(self):
        """Apply the pure availability comparison to this test fixture."""
        return availability.check(self.policy,self.cfg,self.host,self.status,self.runtime)

    def test_admitted_runtime_passes_without_mutation(self):
        """Accept only the matching runtime without changing the supplied facts."""
        original=copy.deepcopy((self.policy,self.cfg,self.host,self.status,self.runtime))
        self.assertEqual(self.check(),{'status':'passed','vmid':214,'guest_autostart':True,
            'container_restart':'unless-stopped','changed':False})
        self.assertEqual(original,(self.policy,self.cfg,self.host,self.status,self.runtime))

    def test_stopped_guest_and_disabled_autostart_are_real_failures(self):
        """Reject loss of availability and weakening of the guest identity or protection."""
        for field,value in [('onboot',0),('protection',0),('unprivileged',0),('hostname','other'),('lock','backup')]:
            with self.subTest(field=field):
                old=self.host.copy();self.host[field]=value
                with self.assertRaises(ValueError):self.check()
                self.host=old
        self.status['status']='stopped'
        with self.assertRaises(ValueError):self.check()

    def test_container_policy_image_identity_and_compose_drift_refuse(self):
        """Reject a stopped or changed container and missing persistent startup policy."""
        for field,value in [('id','e'*64),('image_id','sha256:'+'f'*64),('running',False),
                ('restart_policy',{'Name':'no','MaximumRetryCount':0}),('compose_sha256','0'*64),('docker_enabled',False)]:
            with self.subTest(field=field):
                old=copy.deepcopy(self.runtime);self.runtime[field]=value
                with self.assertRaises(ValueError):self.check()
                self.runtime=old

    def test_database_key_and_data_mounts_cannot_be_changed(self):
        """Keep each preserved application and key mount at its original source."""
        for index in range(3):
            old=copy.deepcopy(self.runtime);self.runtime['mounts'][index][0]='/different'
            with self.assertRaises(ValueError):self.check()
            self.runtime=old

    def test_policy_cannot_supply_start_or_installation_authority(self):
        """Keep runtime verification separate from lifecycle and account actions."""
        self.policy['start']=True
        with self.assertRaises(ValueError):self.check()
        del self.policy['start'];self.cfg['guest']['start_on_boot']=False
        with self.assertRaises(ValueError):self.check()

    def test_closed_policy_rejects_wrong_guest_and_invalid_fingerprints(self):
        """Require the exact guest and complete immutable identity fingerprints."""
        for field,value in [('vmid',215),('vmid',True),('completion_sha256','short'),
                ('container_id','b'*63),('image_id','latest'),('compose_sha256',None)]:
            with self.subTest(field=field,value=value):
                old=self.policy.copy();self.policy[field]=value
                with self.assertRaises(ValueError):self.check()
                self.policy=old


    def test_missing_original_ssh_binding_refuses_before_any_native_call(self):
        """Read-only verification cannot create or rebind SSH trust."""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);work=root/'214';work.mkdir(mode=0o700)
            raw=json.dumps({'status':'passed'}).encode();completion=work/'pegaprox-complete.json'
            completion.write_bytes(raw);completion.chmod(0o600)
            self.policy['completion_sha256']=hashlib.sha256(raw).hexdigest()
            self.cfg['paths']={'state_root':str(root)}
            self.cfg['site']={'node':'benbeastproxmox'}
            with patch.object(availability.deploy,'api_get',side_effect=AssertionError('no API call')), \
                    patch.object(availability.deploy,'guest_trust',side_effect=AssertionError('no trust adoption')):
                with self.assertRaises(ValueError):availability.verify(self.policy,self.cfg)
            self.assertFalse((work/'ssh-trust.json').exists())


    def test_verify_forwards_native_observations_and_refuses_runtime_policy_drift(self):
        """Exercise receipt and input checks through SSH observation and the final comparison."""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);work=root/'214';work.mkdir(mode=0o700)
            prepared=root/'prepared.json';prepared.write_bytes(b'original prepared manifest');prepared.chmod(0o600)
            stack=root/'stack.json';stack.write_bytes(b'original stack');stack.chmod(0o600)
            binding=self.policy['commissioning_binding']
            binding['prepared_sha256']=hashlib.sha256(prepared.read_bytes()).hexdigest()
            binding['input_hashes']={str(stack):hashlib.sha256(stack.read_bytes()).hexdigest()}
            raw=json.dumps({'status':'passed','binding':binding}).encode()
            completion=work/'pegaprox-complete.json';completion.write_bytes(raw);completion.chmod(0o600)
            trust=work/'ssh-trust.json';trust.write_text('{}');trust.chmod(0o600)
            self.policy['completion_sha256']=hashlib.sha256(raw).hexdigest()
            self.cfg['app'].update(stack_config=str(stack),address='10.0.0.214')
            self.cfg['paths']={'state_root':str(root),'private_key':'/original/key','known_hosts':'/original/hosts'}
            self.cfg['site']={'node':'fixture'}
            with patch.object(availability.deploy,'input_hashes',return_value=binding['input_hashes']), \
                    patch.object(availability.deploy,'api_get',side_effect=[self.host,self.status]*2), \
                    patch.object(availability.deploy,'guest_trust') as trust_check, \
                    patch.object(availability.subprocess,'run') as ssh:
                ssh.return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.runtime))
                self.assertEqual(availability.verify(self.policy,self.cfg)['status'],'passed')
                self.assertEqual(trust_check.call_count,1)
                self.runtime['restart_policy']={'Name':'no','MaximumRetryCount':0}
                ssh.return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.runtime))
                with self.assertRaises(ValueError):availability.verify(self.policy,self.cfg)
            stack.write_bytes(b'changed original input')
            with patch.object(availability.deploy,'api_get') as api, \
                    patch.object(availability.deploy,'input_hashes',return_value=binding['input_hashes']):
                with self.assertRaises(ValueError):availability.verify(self.policy,self.cfg)
                api.assert_not_called()

    def test_foreign_commissioning_receipt_refuses_before_native_access(self):
        """A matching raw receipt hash cannot admit a receipt for another guest."""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);work=root/'214';work.mkdir(mode=0o700)
            foreign=copy.deepcopy(self.policy['commissioning_binding']);foreign['vmid']=215
            raw=json.dumps({'status':'passed','binding':foreign}).encode()
            for name,body in [('pegaprox-complete.json',raw),('ssh-trust.json',b'{}')]:
                path=work/name;path.write_bytes(body);path.chmod(0o600)
            self.policy['completion_sha256']=hashlib.sha256(raw).hexdigest()
            self.cfg['paths']={'state_root':str(root)}
            with patch.object(availability.deploy,'api_get') as api:
                with self.assertRaises(ValueError):availability.verify(self.policy,self.cfg)
                api.assert_not_called()


if __name__=='__main__':unittest.main()
