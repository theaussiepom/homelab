"""Exercise actual private-file handling and one container recreation only."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_acme as component
import component_image as shared
from ingress_acme import candidate


@unittest.skipUnless(os.geteuid()==0,'Ownership checks run in the Linux test container')
class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);self.config=root/'traefik.yml';self.compose=root/'compose.yml'
        identity=root/'identity.json'
        self.original=json.dumps({'providers':{'token':'synthetic-private'},'certificatesResolvers':{
            'letsencrypt':{'acme':{'dnsChallenge':{'provider':'cloudflare','resolvers':['198.18.40.2:53'],
            'propagation':{'disableANSChecks':True,'requireAllRNS':True}}}}}}).encode()
        self.config.write_bytes(self.original);self.config.chmod(0o400)
        self.image='traefik@sha256:'+'a'*64
        self.compose.write_text(json.dumps({'name':'homelab-ingress','services':{'traefik':{
            'image':self.image,'volumes':[{'source':str(self.config),'target':'/etc/traefik/traefik.yml','read_only':True}]}}}))
        self.compose.chmod(0o600);identity.write_text('{"vmid":712,"kind":"ingress"}');identity.chmod(0o600)
        self.settings={'vmid':712,'before':['198.18.40.2:53'],'after':['1.1.1.1:53','1.0.0.1:53'],
            'image':self.image,'runtime_sha256':hashlib.sha256(self.original).hexdigest(),
            'compose_sha256':hashlib.sha256(self.compose.read_bytes()).hexdigest()}
        self.commands=[];self.fail=False;self.starting=False;self.ready=True
        p=patch.multiple(component,CONFIG=self.config,STATE=root/'state');p.start();self.addCleanup(p.stop)
        p=patch.multiple(shared,COMPOSE=self.compose,IDENTITY=identity,command=self.command);p.start();self.addCleanup(p.stop)

    def command(self,argv,**kwargs):
        self.commands.append(argv)
        if 'up' in argv:
            if self.fail:raise RuntimeError('synthetic failed recreation')
            if self.starting:self.ready=False
        if argv[0]=='curl':
            self.ready=True
            return b'OK'
        if 'ps' in argv:return ('a'*64+'\n').encode() if self.ready else b''
        if argv[:2]==['docker','inspect']:return json.dumps({'State':{'Running':True},'Config':{'Image':self.image}}).encode()
        return b''

    def test_success_keeps_private_file_metadata_and_compose_and_does_not_replay(self):
        before=self.config.stat();compose=self.compose.read_bytes()
        self.assertTrue(component.run(self.settings)['changed'])
        after=self.config.stat()
        self.assertEqual((after.st_ino,after.st_mode,after.st_uid,after.st_gid),(before.st_ino,before.st_mode,before.st_uid,before.st_gid))
        self.assertEqual(self.config.read_bytes(),candidate(self.original,self.settings['before'],self.settings['after']))
        self.assertEqual(self.compose.read_bytes(),compose)
        self.assertEqual(len([c for c in self.commands if 'up' in c]),1)
        start=len(self.commands)
        self.assertFalse(component.run(self.settings,True)['changed'])
        self.assertFalse(any('up' in c or 'pull' in c for c in self.commands[start:]))
        with self.assertRaises(FileExistsError):component.run(self.settings)

    def test_failure_preserves_private_backup_and_hold_and_refuses_replay(self):
        self.fail=True
        with self.assertRaises(RuntimeError):component.run(self.settings)
        self.assertEqual(next(component.STATE.glob('*/traefik-before.json')).read_bytes(),self.original)
        self.assertTrue(list(component.STATE.glob('*/HOLD.json')))
        self.assertEqual(self.config.stat().st_mode & 0o777,0o400)
        self.fail=False
        with self.assertRaises(ValueError):component.run(self.settings)
        with self.assertRaises(OSError):component.run(self.settings,True)
        self.assertEqual(len([c for c in self.commands if 'up' in c]),1)

    def test_source_revision_change_does_not_grant_another_failed_attempt(self):
        self.fail=True
        with self.assertRaises(RuntimeError):component.run(self.settings)
        self.settings['revision']='d'*40
        with self.assertRaises(ValueError):component.run(self.settings)
        self.assertEqual(len([c for c in self.commands if 'up' in c]),1)

    def test_recreated_container_waits_for_existing_health_check_before_runtime_assertion(self):
        self.starting=True
        self.assertTrue(component.run(self.settings)['changed'])
        recreate=next(i for i,c in enumerate(self.commands) if 'up' in c)
        health=next(i for i,c in enumerate(self.commands) if c[0]=='curl')
        inspect=next(i for i,c in enumerate(self.commands[recreate+1:],recreate+1) if 'ps' in c)
        self.assertLess(health,inspect)
        self.assertIn('--retry-all-errors',self.commands[health])
        self.assertIn('180',self.commands[health])

    def test_runtime_drift_stops_before_container_actions(self):
        self.settings['runtime_sha256']='b'*64
        with self.assertRaises(ValueError):component.run(self.settings)
        self.assertEqual(self.commands,[])

    def confirmation(self):
        self.fail=True
        with self.assertRaises(RuntimeError):component.run(self.settings)
        self.fail=False;self.commands=[]
        self.operation=next(component.STATE.iterdir())
        # Synthetic partial application: runtime is already changed, health was not checked.
        return {'update':self.settings,'revision':'c'*40,
                'runtime_sha256':hashlib.sha256(self.config.read_bytes()).hexdigest(),
                'guest_hold_sha256':hashlib.sha256((self.operation/'HOLD.json').read_bytes()).hexdigest()}

    def test_confirmation_only_checks_running_service_and_archives_exact_failed_hold(self):
        selected=self.confirmation()
        original={p.name:p.read_bytes() for p in self.operation.iterdir()}
        runtime=self.config.read_bytes();compose=self.compose.read_bytes()
        self.assertFalse(component.run(self.settings,confirmation=selected)['changed'])
        self.assertFalse(any(any(v in c for v in ('up','pull','restart','stop')) for c in self.commands))
        self.assertEqual(self.config.read_bytes(),runtime);self.assertEqual(self.compose.read_bytes(),compose)
        for name,data in original.items():
            self.assertEqual((self.operation/('failed-HOLD.json' if name=='HOLD.json' else name)).read_bytes(),data)
        self.assertFalse(component.run(self.settings,True)['changed'])

    def test_failed_confirmation_is_one_use_even_after_source_revision_change(self):
        selected=self.confirmation()
        with patch.object(component,'ready',side_effect=RuntimeError('synthetic unhealthy service')):
            with self.assertRaises(RuntimeError):component.run(self.settings,confirmation=selected)
        self.assertTrue((self.operation/'HOLD.json').is_file())
        self.assertFalse((self.operation/'complete.json').exists())
        selected['revision']='d'*40
        with self.assertRaises(FileExistsError):component.run(self.settings,confirmation=selected)
        self.assertIn('RuntimeError',(self.operation/'confirmation-failure.json').read_text())

    def test_confirmation_rejects_changed_runtime_before_health_or_claim(self):
        selected=self.confirmation();selected['runtime_sha256']='f'*64
        with self.assertRaises(ValueError):component.run(self.settings,confirmation=selected)
        self.assertEqual(self.commands,[])
        self.assertFalse((self.operation/'confirmation-claim.json').exists())

    def test_readiness_matches_commissioned_profile(self):
        profile=json.loads((Path(component.__file__).parent/'foundation-profiles/ingress.site.json').read_text())
        self.assertEqual(component.HEALTH,profile['app']['health_checks'][0]['argv'])


if __name__=='__main__':unittest.main()
