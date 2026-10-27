"""Continuation admission binds existing evidence and never replays installation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation_cd as fc
import foundation_maintenance as maintenance
from test_component_image import OLD, NEW


class AdmissionTests(unittest.TestCase):
    def test_packet_refuses_unknown_fields_mutable_images_and_protected_guests(self):
        value = {'schema': 'homelab-ingress-image-update-v1', 'revision': 'a'*40, 'vmid': 712,
            'plan_sha256': 'b'*64, 'before': OLD, 'after': NEW, 'compose_sha256': 'c'*64,
            'foundation_complete_sha256': 'd'*64}
        self.assertEqual(maintenance.packet(value), value)
        for altered in ({**value, 'extra': True}, {**value, 'vmid': 900}, {**value, 'after': 'traefik:latest'},
                        {**value, 'revision': 'main'}, {**value, 'before': NEW}):
            with self.assertRaises(ValueError): maintenance.packet(altered)


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.work = self.state / '702'; self.work.mkdir(mode=0o700)
        self.inputs = self.root / 'foundation-db-tools'; self.inputs.mkdir(mode=0o700)
        self.site = self.inputs / 'site.json'
        self.cfg = {'guest': {'vmid':702}, 'app': {'vmid':702,'kind':'db-tools','stack_config':str(self.inputs/'stack.json')},
                    'paths': {'state_root':str(self.state),'backup_directory':str(self.root/'nas')}}
        self.nas = self.root / 'nas/702'; self.nas.mkdir(parents=True, mode=0o700)
        self.plan = {'plan_sha256':'a'*64, 'source_sha256':'b'*64, 'input_hashes':{}, 'site_sha256':'unused'}
        fc.write_new(self.site, fc.encoded(self.cfg)); self.plan['site_sha256'] = fc.digest(self.site.read_bytes())
        for name in ('plan.json','applied.json','started.json'): fc.write_new(self.work/name, fc.encoded(self.plan))
        for name in ('guest.tfplan','guest.tfplan.json','ssh-trust.json','terraform.tfstate','123-verify.log'):
            fc.write_new(self.work/name, b'original '+name.encode())
        for name in ('prepared.json','stack.json'): fc.write_new(self.inputs/name, b'original '+name.encode())
        self.binding={'schema':fc.SCHEMA,'guest':'db-tools','vmid':702,
            'source_sha256':self.plan['source_sha256'],'input_hashes':{},
            'prepared_sha256':fc.digest((self.inputs/'prepared.json').read_bytes())}
        fc.write_new(self.work/'FOUNDATION-HOLD.json',fc.encoded({**self.binding,'step':'deploy',
            'automatic_retry':False,'plan_sha256':self.plan['plan_sha256']}))
        fc.write_new(self.work/'ROLLOUT-HOLD.json',fc.encoded({'step':'verify','vmid':702,
            'automatic_retry':False,'plan_sha256':self.plan['plan_sha256']}))
        self.paths={'foundation_hold':self.work/'FOUNDATION-HOLD.json','rollout_hold':self.work/'ROLLOUT-HOLD.json',
            'plan':self.work/'plan.json','plan_file':self.work/'guest.tfplan','plan_json':self.work/'guest.tfplan.json',
            'applied':self.work/'applied.json','started':self.work/'started.json','prepared':self.inputs/'prepared.json',
            'site':self.site,'stack':self.inputs/'stack.json','trust':self.work/'ssh-trust.json',
            'state':self.work/'terraform.tfstate','verify_log':self.work/'123-verify.log'}
        self.selected={'schema':'homelab-foundation-verify-continuation-v1','revision':'c'*40,'vmid':702,
            'plan_sha256':self.plan['plan_sha256'],'verify_log':'123-verify.log',
            'hashes':{k:fc.digest(p.read_bytes()) for k,p in self.paths.items()}}
        self.original={p:p.read_bytes() for p in self.paths.values()}
        self.deployment=Mock()
        self.deployment.sha.side_effect=lambda p:fc.digest(p.read_bytes())
        self.deployment.source_hash.return_value=self.plan['source_sha256']
        self.deployment.input_hashes.return_value={}
        self.deployment.application_address.return_value='10.88.25.32'
        self.deployment.execute.return_value={'step':'verify','vmid':702,'status':'passed'}
        self.patches=patch.object(maintenance,'STATE',self.state);self.patches.start();self.addCleanup(self.patches.stop)

    def run_continuation(self):
        return maintenance.continue_verification(self.deployment,fc,self.cfg,self.site,
                                                 maintenance.packet(self.selected),self.root/'bundles')

    def test_success_only_verifies_and_preserves_each_original_failed_file(self):
        self.assertEqual(self.run_continuation()['status'],'passed')
        self.deployment.execute.assert_called_once_with('verify',self.site)
        archive=self.work/('foundation-verification-'+self.plan['plan_sha256'][:12])
        for p,data in self.original.items():
            self.assertEqual((archive/p.name if p.name in {'FOUNDATION-HOLD.json','ROLLOUT-HOLD.json'} else p).read_bytes(),data)
        complete=json.loads((self.work/'foundation-complete.json').read_bytes())
        self.assertEqual(complete['binding'],self.binding)
        self.assertFalse((self.work/'CONTINUATION-HOLD.json').exists())
        self.assertEqual((self.work/'foundation-verification-complete.json').read_bytes(),
                         (self.nas/'foundation-verification-complete.json').read_bytes())

    def test_failed_verification_remains_held_and_cannot_replay(self):
        self.deployment.execute.side_effect=RuntimeError('synthetic verification failure')
        with self.assertRaises(RuntimeError):self.run_continuation()
        self.assertTrue((self.work/'CONTINUATION-HOLD.json').is_file())
        self.assertTrue((self.work/'foundation-verification-claim.json').is_file())
        self.assertFalse((self.work/'foundation-complete.json').exists())
        with self.assertRaises(ValueError):self.run_continuation()
        self.deployment.execute.assert_called_once()

    def test_evidence_drift_is_refused_before_claim_or_target_command(self):
        (self.work/'123-verify.log').write_bytes(b'drift')
        with self.assertRaises(ValueError):self.run_continuation()
        self.deployment.execute.assert_not_called()
        self.assertFalse((self.work/'foundation-verification-claim.json').exists())
        self.assertTrue((self.work/'FOUNDATION-HOLD.json').exists())

    def test_wrong_phase_is_not_a_verification_continuation(self):
        p=self.work/'ROLLOUT-HOLD.json';v=json.loads(p.read_bytes());v['step']='start';p.write_bytes(fc.encoded(v))
        self.selected['hashes']['rollout_hold']=fc.digest(p.read_bytes())
        with self.assertRaises(ValueError):self.run_continuation()
        self.deployment.execute.assert_not_called()
        self.assertFalse((self.work/'foundation-verification-claim.json').exists())

    def test_second_push_uses_the_ordinary_completed_guest_path(self):
        self.run_continuation()
        with patch.object(fc,'run',return_value={'status':'ordinary-readonly-verification'}) as normal:
            self.assertEqual(self.run_continuation(),{'status':'ordinary-readonly-verification'})
            normal.assert_called_once_with('db-tools',self.deployment,self.root/'bundles')
        self.deployment.execute.assert_called_once()

    def test_partial_claim_cannot_be_adopted_or_replayed(self):
        fc.write_new(self.work/'foundation-verification-claim.json',fc.encoded(self.selected))
        with self.assertRaises(FileExistsError):self.run_continuation()
        self.deployment.execute.assert_not_called()
        self.assertTrue((self.work/'ROLLOUT-HOLD.json').exists())

    def test_log_name_is_literal_and_cannot_select_a_subdirectory(self):
        for name in ('1-verify/log','1-verifyXlog','../1-verify.log','1-verify.log/extra'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                maintenance.packet({**self.selected,'verify_log':name})


class ImageMaintenanceTests(unittest.TestCase):
    # Reuse only the input/receipt fixture, not its continuation tests.
    def setUp(self):
        ContinuationTests.setUp(self)
        self.cfg['app'].update(kind='ingress',hostname='proxy',address='10.88.25.33')
        self.cfg['paths'].update(private_key='/private/key',known_hosts='/private/known_hosts')
        self.site.write_bytes(fc.encoded(self.cfg));self.plan['site_sha256']=fc.digest(self.site.read_bytes())
        for name in ('plan.json','applied.json','started.json'):(self.work/name).write_bytes(fc.encoded(self.plan))
        self.binding.update(guest='ingress')
        for name in ('FOUNDATION-HOLD.json','ROLLOUT-HOLD.json'):(self.work/name).unlink()
        public={'status':'passed','vmid':702,'plan_sha256':self.plan['plan_sha256']}
        fc.write_new(self.work/'rollout-complete.json',fc.encoded(public))
        fc.write_new(self.work/'foundation-complete.json',fc.encoded({'status':'passed','binding':self.binding,
            'plan_sha256':self.plan['plan_sha256'],'public_receipt_sha256':fc.digest(fc.encoded(public))}))
        self.selected={'schema':'homelab-ingress-image-update-v1','revision':'c'*40,'vmid':702,
            'plan_sha256':self.plan['plan_sha256'],'before':OLD,'after':NEW,'compose_sha256':'d'*64,
            'foundation_complete_sha256':fc.digest((self.work/'foundation-complete.json').read_bytes())}
        self.deployment.application_address.return_value='10.88.25.33'

    def run_update(self):
        return maintenance.image_update(self.deployment,fc,self.cfg,self.site,self.root/'maintenance-source',
                                        maintenance.packet(self.selected))

    def test_image_update_preserves_installation_and_second_push_only_verifies(self):
        originals={p:p.read_bytes() for p in self.work.iterdir() if p.is_file()}
        self.assertTrue(self.run_update()['changed'])
        self.assertFalse(self.run_update()['changed'])
        for p,data in originals.items():self.assertEqual(p.read_bytes(),data)
        self.deployment.execute.assert_not_called()
        self.assertEqual(self.deployment.quiet.call_count,2)
        modes=[]
        for call in self.deployment.quiet.call_args_list:
            variables=Path(call.args[0][-1][1:]);modes.append(json.loads(variables.read_bytes())['component_verify_only'])
        self.assertEqual(modes,[False,True])

    def test_failed_image_attempt_cannot_be_replayed(self):
        self.deployment.quiet.side_effect=RuntimeError('synthetic component failure')
        with self.assertRaises(RuntimeError):self.run_update()
        with self.assertRaises(FileExistsError):self.run_update()
        self.deployment.quiet.assert_called_once()
        self.deployment.execute.assert_not_called()

    def test_completed_input_binding_drift_stops_before_claim(self):
        self.binding['input_hashes']={'foreign':'f'*64}
        complete=json.loads((self.work/'foundation-complete.json').read_bytes());complete['binding']=self.binding
        (self.work/'foundation-complete.json').write_bytes(fc.encoded(complete))
        self.selected['foundation_complete_sha256']=fc.digest((self.work/'foundation-complete.json').read_bytes())
        with self.assertRaises(ValueError):self.run_update()
        self.deployment.quiet.assert_not_called()
        self.assertFalse(list(self.work.glob('image-update-*-claim.json')))


if __name__=='__main__':unittest.main()
