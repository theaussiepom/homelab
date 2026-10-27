"""A prerequisite operation is claimed once and cannot replay a partial failure."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from test_deploy import deploy,fixture
import foundation_cd as fc
import automation_maintenance as maintenance


def setup(root):
    cfg=fixture(root);cfg['guest']['vmid']=cfg['app']['vmid']=211
    work=root/'state/211';work.mkdir(parents=True)
    site=root/'site.json';site.write_text(json.dumps(cfg));site.chmod(0o600)
    (work/'terraform.tfstate').write_text('synthetic state')
    proofs={}
    for name in ('plan.json','foundation-complete.json','rollout-complete.json'):
        (work/name).write_text('{}');proofs[name]=deploy.sha(work/name)
    nas=root/'nas/backups/211';nas.mkdir(parents=True);nas.chmod(0o700)
    common={'vmid':211,'source_revision':'a'*40,'plan_sha256':'b'*64,'state_sha256':deploy.sha(work/'terraform.tfstate'),'proofs':proofs}
    identity=dict(common,oidc={'vmid':211,'hostname':'security','provider_id':21,'client_id':'retained-client','slug':'nodered',
        'before':[{'matching_mode':'strict','url':'https://old.example.org/auth/strategy/callback/'}],
        'callback':'https://new.example.org/auth/strategy/callback/'})
    ingress=dict(common,vmid=212,retained_rules=[{}]*4,additions=[{'direction':'out','proto':'tcp','port':'8123,1880',
        'destination':'10.88.30.21/32','comment':'Selected automation backend'}],runtime_sha256='c'*64,compose_sha256='d'*64)
    packet={'schema':'homelab-automation-maintenance-v1','ingress':ingress,'identity':identity}
    deployment=Mock(wraps=deploy);deployment.backup=Mock()
    return cfg,work,site,packet,deployment,nas


class MaintenanceTests(unittest.TestCase):
    def test_success_then_repeat_only_verifies_and_keeps_original_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,work,site,packet,deployment,nas=setup(Path(tmp))
            with patch.object(maintenance,'ansible') as native:
                result=maintenance.run('identity',packet,deployment,fc,Mock(),site)
                self.assertTrue(result['changed'])
                original=(work/'automation-200-prerequisite/claim.json').read_bytes()
                result=maintenance.run('identity',packet,deployment,fc,Mock(),site)
                self.assertFalse(result['changed'])
                self.assertEqual([call.args[-1] for call in native.call_args_list],[False,True])
                self.assertEqual((work/'automation-200-prerequisite/claim.json').read_bytes(),original)
                self.assertFalse((work/'CONTINUATION-HOLD.json').exists())
                self.assertEqual((work/'automation-200-prerequisite/complete.json').read_bytes(),(nas/'automation-200-complete.json').read_bytes())

    def test_failure_leaves_native_hold_and_cannot_replay_under_a_new_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,work,site,packet,deployment,nas=setup(Path(tmp))
            def fail(*args):
                self.assertTrue((work/'CONTINUATION-HOLD.json').is_file())
                self.assertTrue((nas/'automation-200-claim.json').is_file())
                raise ValueError('synthetic operation failure')
            with patch.object(maintenance,'ansible',side_effect=fail) as native:
                with self.assertRaises(ValueError):maintenance.run('identity',packet,deployment,fc,Mock(),site)
                with patch.object(maintenance,'source_hash',return_value='f'*64),self.assertRaises(ValueError):
                    maintenance.run('identity',packet,deployment,fc,Mock(),site)
                self.assertEqual(native.call_count,1)

    def test_changed_original_proof_refuses_before_claim_or_native_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,work,site,packet,deployment,nas=setup(Path(tmp))
            (work/'plan.json').write_text('changed')
            with patch.object(maintenance,'ansible') as native,self.assertRaises(ValueError):
                maintenance.run('identity',packet,deployment,fc,Mock(),site)
            native.assert_not_called();self.assertFalse((work/'automation-200-prerequisite').exists())
