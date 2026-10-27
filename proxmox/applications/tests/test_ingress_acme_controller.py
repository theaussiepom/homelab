"""The controller keeps one canonical state and never repeats a failed apply."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import foundation_cd as fc
import ingress_acme as acme
import test_foundation_maintenance as maintenance_fixtures
import test_ingress_acme as acme_fixtures


class ControllerTests(unittest.TestCase):
    def setUp(self):
        maintenance_fixtures.ImageMaintenanceTests.setUp(self)
        self.cfg['site']={'node':'test-pve'};self.cfg['guest']['rules']=[];self.cfg['ssh_public_keys']=[]
        token=self.root/'token';token.write_text('synthetic-private')
        self.cfg['paths'].update(ca_file='/private/ca',api_token=str(token))
        self.deployment.application_address.return_value=self.cfg['app']['address']
        self.deployment.discovery.labels.return_value={}
        self.selected={k:self.selected[k] for k in ('revision','vmid','plan_sha256','compose_sha256','foundation_complete_sha256')}
        self.selected.update(schema='homelab-ingress-acme-update-v1',before=['198.18.40.2:53'],after=['1.1.1.1:53','1.0.0.1:53'],
            image='traefik@sha256:'+'a'*64,runtime_sha256='a'*64,state_sha256=fc.digest((self.work/'terraform.tfstate').read_bytes()))
        self.native=acme_fixtures.AcmeTests().fixture()
        for row in self.native['resource_changes']:
            for side in ('before','after'):row['change'][side][acme.RESOURCES[row['address']]]=702
        self.fail=False;self.calls=[]
        self.deployment.quiet.side_effect=self.command
        self.original={n:(self.work/n).read_bytes() for n in ('plan.json','applied.json','started.json','foundation-complete.json')}
        p=patch('foundation_maintenance.expected',return_value=self.plan);p.start();self.addCleanup(p.stop)
        p=patch.object(acme.subprocess,'check_output',side_effect=lambda *a,**k:json.dumps(self.native).encode());p.start();self.addCleanup(p.stop)

    def command(self,argv,env,log):
        self.calls.append(argv)
        self.assertNotIn('synthetic-private',repr(argv))
        if 'plan' in argv:
            path=next(a[5:] for a in argv if a.startswith('-out='));Path(path).write_bytes(b'synthetic saved plan')
        if 'apply' in argv:
            if self.fail:raise RuntimeError('synthetic apply failure')
            (self.work/'terraform.tfstate').write_bytes(b'updated canonical state')

    def run_update(self):
        return acme.run(self.deployment,fc,self.cfg,self.site,Path(acme.__file__).parent,self.selected,self.state)

    def test_one_apply_uses_canonical_state_and_does_not_replace_installation_receipts(self):
        self.assertTrue(self.run_update()['changed'])
        self.assertEqual(len([c for c in self.calls if 'apply' in c]),1)
        self.assertTrue(any('-backend-config=path='+str(self.work/'terraform.tfstate') in c for c in self.calls))
        for n,data in self.original.items():self.assertEqual((self.work/n).read_bytes(),data)
        for row in self.native['resource_changes']:
            row['change']['before']=copy.deepcopy(row['change']['after']);row['change']['actions']=['no-op']
        old=len(self.calls)
        self.assertFalse(self.run_update()['changed'])
        self.assertFalse(any('apply' in c for c in self.calls[old:]))

    def test_failed_apply_leaves_claim_and_cannot_run_ansible_or_replay(self):
        self.fail=True
        with self.assertRaises(RuntimeError):self.run_update()
        self.assertFalse(any('ansible-playbook' in c for c in self.calls))
        with self.assertRaises(FileNotFoundError):self.run_update()
        self.assertEqual(len([c for c in self.calls if 'apply' in c]),1)

    def test_new_source_revision_cannot_replay_a_failed_correction(self):
        self.fail=True
        with self.assertRaises(RuntimeError):self.run_update()
        self.selected['revision']='d'*40
        with self.assertRaises(FileNotFoundError):self.run_update()
        self.assertEqual(len([c for c in self.calls if 'apply' in c]),1)

    def test_unexpected_guest_change_stops_before_apply(self):
        self.native['resource_changes'][0]['change']['actions']=['update']
        with self.assertRaises(ValueError):self.run_update()
        self.assertFalse(any('apply' in c or 'ansible-playbook' in c for c in self.calls))


if __name__=='__main__':unittest.main()
