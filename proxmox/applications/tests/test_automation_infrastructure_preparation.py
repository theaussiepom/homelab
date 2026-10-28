"""Exercise two legitimate runs; no targets, restoration, hold repair or replay."""
import copy,json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import test_ordinary_cd as lifecycle
ordinary=lifecycle.ordinary

class PreparationBoundaryTests(unittest.TestCase):
    setUp=lifecycle.LifecycleTests.setUp
    def automation(self):self.cfg['app']['kind']='automation'
    def result(self):return {'changed':False,'created':False,'state_sha256':ordinary.deploy.sha(self.work/'terraform.tfstate')}
    def test_preparation_completes_only_itself_and_matching_repeat_contacts_no_target(self):
        self.automation()
        with patch.object(ordinary,'infrastructure',return_value=self.result()) as infra,patch.object(ordinary,'application') as app:
            result=ordinary.run('infrastructure',self.site,infrastructure_only=True)
            self.assertEqual(result['readiness'],'infrastructure-ready');self.assertFalse(result['application_ready'])
            self.assertFalse((self.work/'ORDINARY-HOLD.json').exists());self.assertFalse((self.work/'ordinary-complete.json').exists())
            self.assertTrue((self.work/'ordinary-infrastructure-ready.json').exists());app.assert_not_called()
            with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}):
                self.assertFalse(ordinary.run('infrastructure',self.site,infrastructure_only=True)['target_contacted'])
            self.assertEqual(infra.call_count,1)
    def test_next_merge_replans_same_backend_then_runs_all_apps_without_adoption_or_restore(self):
        self.automation()
        with patch.object(ordinary,'infrastructure',return_value=self.result()) as infra,patch.object(ordinary,'application',return_value={'status':'passed','changed':False}) as app:
            ordinary.run('infrastructure',self.site,infrastructure_only=True)
            with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}):
                ordinary.run('infrastructure',self.site)
                self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
                for phase in ('mqtt','homeassistant','node_red'):ordinary.run(phase,self.site)
            self.assertEqual(infra.call_count,2);self.assertEqual(app.call_count,3)
            self.assertFalse((self.work/'ORDINARY-HOLD.json').exists());self.assertTrue((self.work/'ordinary-complete.json').exists())
            self.assertFalse((self.work/'prepare-complete.json').exists());self.assertFalse((self.work/'rollout-complete.json').exists())
            self.assertFalse(ordinary.run('infrastructure',self.site)['target_contacted']);self.assertEqual(infra.call_count,2)
    def test_failed_preparation_retains_hold_and_cannot_be_retried_or_relabelled(self):
        self.automation()
        with patch.object(ordinary,'infrastructure',side_effect=ValueError('synthetic fail')) as infra:
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site,infrastructure_only=True)
            before=(self.work/'ORDINARY-HOLD.json').read_bytes()
            for mode in (True,False):
                with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}),self.assertRaises((ValueError,FileNotFoundError)):
                    ordinary.run('infrastructure',self.site,infrastructure_only=mode)
            self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(),before);self.assertEqual(infra.call_count,1)
            self.assertFalse((self.work/'ordinary-infrastructure-ready.json').exists());self.assertFalse((self.work/'ordinary-complete.json').exists())
    def test_changed_or_unknown_hold_is_never_closed_as_success(self):
        self.automation()
        def changed(*args,**kwargs):
            (self.work/'ORDINARY-HOLD.json').write_text('unknown owner');return self.result()
        with patch.object(ordinary,'infrastructure',side_effect=changed),self.assertRaises(ValueError):
            ordinary.run('infrastructure',self.site,infrastructure_only=True)
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_text(),'unknown owner');self.assertFalse((self.work/'ordinary-infrastructure-ready.json').exists())
    def test_ready_receipt_never_clears_an_interrupted_hold(self):
        self.automation()
        with patch.object(ordinary,'infrastructure',return_value=self.result()) as infra:
            ordinary.run('infrastructure',self.site,infrastructure_only=True)
            hold=self.work/'ORDINARY-HOLD.json';hold.write_text('interrupted');hold.chmod(0o600)
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site,infrastructure_only=True)
            self.assertEqual(hold.read_text(),'interrupted');self.assertEqual(infra.call_count,1)
    def test_first_apps_require_preparation_and_exact_current_prepared_state(self):
        self.automation()
        with patch.object(ordinary,'infrastructure',return_value=self.result()) as infra:
            with self.assertRaises(FileNotFoundError):ordinary.run('infrastructure',self.site)
            infra.assert_not_called();ordinary.run('infrastructure',self.site,infrastructure_only=True)
            (self.work/'terraform.tfstate').write_text('unexpected changed state')
            with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}),self.assertRaises(ValueError):ordinary.run('infrastructure',self.site)
            self.assertEqual(infra.call_count,1);self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
    def test_partial_or_changed_preparation_binding_refuses_before_native_work(self):
        self.automation()
        self.expected.update(source_sha256='b'*64,input_hashes={'stack.json':'c'*64})
        with patch.object(ordinary,'infrastructure',return_value=self.result()) as infra:
            ordinary.run('infrastructure',self.site,infrastructure_only=True)
            path=self.work/'ordinary-infrastructure-ready.json';original=json.loads(path.read_text())
            for change in ('partial','source','input','site'):
                receipt=copy.deepcopy(original)
                if change=='partial':receipt['binding']={'vmid':self.cfg['guest']['vmid']}
                elif change=='source':receipt['binding']['source_sha256']='d'*64
                elif change=='input':receipt['binding']['input_hashes']['stack.json']='d'*64
                else:receipt['binding']['site_sha256']='d'*64
                ordinary.deploy.write(path,receipt)
                with self.subTest(change=change),patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}),self.assertRaisesRegex(ValueError,'exact prepared'):
                    ordinary.run('infrastructure',self.site)
                self.assertEqual(infra.call_count,1);self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
            ordinary.deploy.write(path,original)
            with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}):ordinary.run('infrastructure',self.site)
            self.assertEqual(infra.call_count,2)
    def test_preparation_is_automation_guest_only_and_never_retires_completed_apps(self):
        with patch.object(ordinary,'infrastructure') as infra:
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site,infrastructure_only=True)
            self.automation()
            with self.assertRaises(ValueError):ordinary.run('mqtt',self.site,infrastructure_only=True)
            ordinary.deploy.write(self.work/'ordinary-complete.json',{'status':'passed'})
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site,infrastructure_only=True)
            infra.assert_not_called()
