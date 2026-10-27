"""Confirm partial application without applying or recreating anything."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import foundation_cd as fc
import foundation_maintenance as maintenance
import ingress_acme as acme
import test_ingress_acme_controller as fixtures


class ConfirmationTests(unittest.TestCase):
    def setUp(self):
        fixtures.ControllerTests.setUp(self)
        def fail_after_apply(argv,env,log):
            self.command(argv,env,log)
            if argv[0]=='ansible-playbook':raise RuntimeError('synthetic post-start failure')
        self.deployment.quiet.side_effect=fail_after_apply
        with self.assertRaises(RuntimeError):
            acme.run(self.deployment,fc,self.cfg,self.site,Path(acme.__file__).parent,self.selected,self.state)
        self.operation=next(self.work.glob('acme-resolvers-*'))
        for name in acme.FAILURE_FILES:
            p=self.operation/name
            if not p.exists():fc.write_new(p,b'synthetic failed evidence')
        self.confirmation={
            'schema':'homelab-ingress-acme-confirmation-v1','revision':'e'*40,
            'vmid':self.selected['vmid'],'plan_sha256':self.selected['plan_sha256'],
            'update':copy.deepcopy(self.selected),'runtime_sha256':'f'*64,'guest_hold_sha256':'d'*64,
            'state_sha256':fc.digest((self.work/'terraform.tfstate').read_bytes()),
            'failure_hashes':{n:fc.digest((self.operation/n).read_bytes()) for n in acme.FAILURE_FILES}}
        self.original={n:(self.operation/n).read_bytes() for n in acme.FAILURE_FILES}
        self.deployment.quiet.reset_mock(side_effect=True)
        self.deployment.execute.reset_mock()

    def run_confirmation(self):
        return acme.confirm(self.deployment,fc,self.cfg,self.site,Path(acme.__file__).parent,
                            maintenance.packet(self.confirmation),self.state)

    def test_confirmation_has_one_ansible_check_and_preserves_all_failed_evidence(self):
        self.assertFalse(self.run_confirmation()['changed'])
        self.deployment.quiet.assert_called_once()
        args=self.deployment.quiet.call_args.args[0]
        self.assertEqual(args[0],'ansible-playbook')
        variables=json.loads(Path(args[-1][1:]).read_bytes())
        self.assertEqual(variables['acme_confirmation'],self.confirmation)
        self.deployment.execute.assert_not_called()
        for name,data in self.original.items():self.assertEqual((self.operation/name).read_bytes(),data)
        complete=json.loads((self.operation/'complete.json').read_bytes())
        self.assertEqual(complete,{'packet':self.selected,'state_sha256':self.confirmation['state_sha256']})
        self.assertFalse(self.run_confirmation()['changed'])
        self.deployment.quiet.assert_called_once()
        for row in self.native['resource_changes']:
            row['change']['before']=copy.deepcopy(row['change']['after']);row['change']['actions']=['no-op']
        self.calls=[];self.deployment.quiet.side_effect=self.command
        self.assertFalse(acme.run(self.deployment,fc,self.cfg,self.site,Path(acme.__file__).parent,self.selected,self.state)['changed'])
        self.assertFalse(any('apply' in c for c in self.calls))

    command=fixtures.ControllerTests.command

    def test_failed_confirmation_cannot_replay_with_a_changed_source_revision(self):
        self.deployment.quiet.side_effect=RuntimeError('synthetic failed readiness')
        with self.assertRaises(RuntimeError):self.run_confirmation()
        self.confirmation['revision']='f'*40
        with self.assertRaises(FileExistsError):self.run_confirmation()
        self.deployment.quiet.assert_called_once()
        self.assertFalse((self.operation/'complete.json').exists())

    def test_failed_evidence_or_state_drift_stops_before_guest_command(self):
        (self.operation/'attempt/ansible.log').write_bytes(b'drift')
        with self.assertRaises(ValueError):self.run_confirmation()
        self.deployment.quiet.assert_not_called()
        self.assertFalse((self.operation/'confirmation-claim.json').exists())

    def test_confirmation_schema_refuses_other_guests_unknown_fields_or_moving_original_packet(self):
        for value in ({**self.confirmation,'vmid':900},{**self.confirmation,'extra':True},
                      {**self.confirmation,'update':self.confirmation},
                      {**self.confirmation,'failure_hashes':{}},
                      {**self.confirmation,'update':{**self.selected,'vmid':703}}):
            with self.subTest(value=value),self.assertRaises(ValueError):maintenance.packet(value)


if __name__=='__main__':unittest.main()
