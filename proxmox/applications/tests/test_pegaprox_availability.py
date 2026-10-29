"""Enforce the commissioned guest's actual startup policy and immutable identity."""
import copy
import unittest

import pegaprox_availability as availability


class PegaProxAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.policy = {'schema':'homelab-pegaprox-availability-v1','vmid':214,
            'completion_sha256':'a'*64,'container_id':'b'*64,'image_id':'sha256:'+'c'*64,
            'compose_sha256':'d'*64,'restart_policy':'unless-stopped'}
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
        return availability.check(self.policy,self.cfg,self.host,self.status,self.runtime)

    def test_admitted_runtime_passes_without_mutation(self):
        original=copy.deepcopy((self.policy,self.cfg,self.host,self.status,self.runtime))
        self.assertEqual(self.check(),{'status':'passed','vmid':214,'guest_autostart':True,
            'container_restart':'unless-stopped','changed':False})
        self.assertEqual(original,(self.policy,self.cfg,self.host,self.status,self.runtime))

    def test_stopped_guest_and_disabled_autostart_are_real_failures(self):
        for field,value in [('onboot',0),('protection',0),('unprivileged',0),('hostname','other'),('lock','backup')]:
            with self.subTest(field=field):
                old=self.host.copy();self.host[field]=value
                with self.assertRaises(ValueError):self.check()
                self.host=old
        self.status['status']='stopped'
        with self.assertRaises(ValueError):self.check()

    def test_container_policy_image_identity_and_compose_drift_refuse(self):
        for field,value in [('id','e'*64),('image_id','sha256:'+'f'*64),('running',False),
                ('restart_policy',{'Name':'no','MaximumRetryCount':0}),('compose_sha256','0'*64),('docker_enabled',False)]:
            with self.subTest(field=field):
                old=copy.deepcopy(self.runtime);self.runtime[field]=value
                with self.assertRaises(ValueError):self.check()
                self.runtime=old

    def test_database_key_and_data_mounts_cannot_be_changed(self):
        for index in range(3):
            old=copy.deepcopy(self.runtime);self.runtime['mounts'][index][0]='/different'
            with self.assertRaises(ValueError):self.check()
            self.runtime=old

    def test_policy_cannot_supply_start_or_installation_authority(self):
        self.policy['start']=True
        with self.assertRaises(ValueError):self.check()
        del self.policy['start'];self.cfg['guest']['start_on_boot']=False
        with self.assertRaises(ValueError):self.check()

    def test_closed_policy_rejects_wrong_guest_and_invalid_fingerprints(self):
        for field,value in [('vmid',215),('vmid',True),('completion_sha256','short'),
                ('container_id','b'*63),('image_id','latest'),('compose_sha256',None)]:
            with self.subTest(field=field,value=value):
                old=self.policy.copy();self.policy[field]=value
                with self.assertRaises(ValueError):self.check()
                self.policy=old


if __name__=='__main__':unittest.main()
