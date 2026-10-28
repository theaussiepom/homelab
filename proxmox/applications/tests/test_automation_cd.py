"""Bind immutable private settings before one create-only guest preparation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_deploy import deploy, fixture, ROOT
import automation_cd
from test_automation_maintenance import setup as maintenance_setup
import automation_maintenance
import foundation_cd


class AutomationCDTests(unittest.TestCase):
    def test_permanent_job_uses_common_reconciliation_and_never_restores_its_capture(self):
        import ordinary_cd
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'config.json'
            cfg={'app':{'kind':'automation','exclusive_writer_confirmed':True,'capture':{'path':'/historical/capture'},
                        'stack_config':'/historical/stack.json','prerequisite_packet_sha256':'a'*64},'guest':{'vmid':200}}
            value={'schema':'homelab-automation-deployment-v1','enabled':True,'site':cfg,
                   'stack':{'kind':'automation'},'discovery_previous_guests':[202,211,212]}
            config.write_text(json.dumps(value))
            observed=[]
            def run(phase,path):
                packet=json.loads(path.read_text());site=json.loads(packet['files']['site.json'])
                self.assertNotIn('capture',site['app'])
                self.assertNotIn('prerequisite_packet_sha256',site['app'])
                self.assertIn('/ordinary/automation/',site['app']['stack_config'])
                observed.append((phase,packet))
                return {'status':'passed'}
            with patch.object(automation_cd,'prerequisites') as prerequisites,patch.object(ordinary_cd,'run',side_effect=run), \
                 patch('automation_configuration.compile_config') as compiler, \
                 patch('automation_configuration.validate_inputs') as validator, \
                 patch('automation_configuration.site_config.read',return_value={}):
                automation_cd.ordinary('guest',config,None,root/'foundation.json')
                automation_cd.ordinary('mqtt',config,None,root/'foundation.json')
            self.assertEqual([p for p,_ in observed],['infrastructure','mqtt'])
            self.assertEqual(observed[0][1],observed[1][1])
            prerequisites.assert_not_called()
            self.assertEqual(validator.call_count,2)
            compiler.assert_not_called()
            self.assertIn('capture',json.loads(config.read_text())['site']['app'])


    def test_guest_requires_exact_completed_prerequisites_and_unchanged_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg, work, site, packet, _, nas = maintenance_setup(root)
            cfg['app'].update(kind='automation',node_red_authentication='authentik-oidc',discovery_routes=[
                {'name':'homeassistant','host':'hass.example.org','url':'http://10.88.30.21:8123','login':'own'},
                {'name':'node-red','host':'nr.example.org','url':'http://10.88.30.21:1880','login':'oidc'}])
            cfg['guest']['interfaces'].append({'ipv4':'10.88.30.21/24','mac':'02:88:00:c8:1e:01'})
            selected = root / 'maintenance.json'
            selected.write_text(json.dumps(packet))
            cfg['app']['prerequisite_packet_sha256'] = deploy.sha(selected)
            for phase in ('ingress', 'identity'):
                row = packet[phase]
                state = root / 'state' / str(row['vmid'])
                state.mkdir(parents=True, exist_ok=True)
                (state / 'terraform.tfstate').write_text('synthetic state')
                operation = state / 'automation-200-prerequisite'
                operation.mkdir(mode=0o700)
                receipt = {'binding': {'packet': row, 'maintenance_source_sha256': automation_maintenance.source_hash()},
                           'state_sha256': deploy.sha(state / 'terraform.tfstate')}
                target = root / 'nas/backups' / str(row['vmid'])
                target.mkdir(parents=True, exist_ok=True)
                foundation_cd.write_new(operation / 'complete.json', foundation_cd.encoded(receipt))
                foundation_cd.write_new(target / 'automation-200-complete.json', foundation_cd.encoded(receipt))
            automation_cd.prerequisites(cfg, selected)
            native=packet['identity']['oidc']
            oidc={'client_id':native['client_id'],'provider_slug':native['slug'],
                  'node_red_url':native['callback'].removesuffix('/auth/strategy/callback/')}
            automation_cd.prerequisites(cfg,selected,oidc)
            for key in ('client_id','provider_slug','node_red_url'):
                wrong_oidc=dict(oidc);wrong_oidc[key]+='-other'
                with self.subTest(oidc=key),self.assertRaisesRegex(ValueError,'native client and routed callback'):
                    automation_cd.prerequisites(cfg,selected,wrong_oidc)
            wrong=json.loads(selected.read_text())
            wrong['ingress']['additions'][0]['destination']='10.88.30.99/32'
            changed=root/'other-packet.json';changed.write_text(json.dumps(wrong))
            cfg['app']['prerequisite_packet_sha256']=deploy.sha(changed)
            with self.assertRaisesRegex(ValueError,'this automation guest backend'):
                automation_cd.prerequisites(cfg,changed)
            cfg['app']['prerequisite_packet_sha256']=deploy.sha(selected)
            with self.assertRaisesRegex(ValueError, 'exact reviewed'):
                automation_cd.prerequisites(cfg, None)
            (work / 'CONTINUATION-HOLD.json').write_text('held')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)
            (work / 'CONTINUATION-HOLD.json').unlink()
            (work / 'terraform.tfstate').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)
            (work / 'terraform.tfstate').write_text('synthetic state')
            (nas / 'automation-200-complete.json').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)

    def setup(self, root):
        inputs = root / 'inputs'; inputs.mkdir(mode=0o700)
        destination = inputs / 'automation'
        cfg = fixture(root)
        cfg['app'].update(kind='automation', stack_config=str(destination / 'stack.json'))
        cfg['app']['prerequisite_packet_sha256']='a'*64
        stack = json.loads((ROOT / 'examples/automation.stack.example.json').read_text())
        config = root / 'deployment.json'
        config.write_text(json.dumps({'schema': 'homelab-automation-deployment-v1', 'enabled': True,
                                     'discovery_previous_guests': [202, 211, 212], 'site': cfg, 'stack': stack}))
        return config, destination, cfg

    def test_enabled_packet_without_prerequisite_digest_stops_before_input_or_guest_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config,destination,cfg=self.setup(Path(tmp))
            value=json.loads(config.read_text());value['site']['app'].pop('prerequisite_packet_sha256')
            config.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'prerequisite digest'):
                automation_cd.prepare_inputs(config,destination,{'NODE_RED_API_TOKEN':'synthetic-token'})
            self.assertFalse(destination.exists())
            with self.assertRaises(ValueError):automation_cd.prerequisites(value['site'],None)

    def test_secret_is_bound_privately_and_cannot_be_changed_on_the_next_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            original = config.read_bytes()
            automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            self.assertEqual(config.read_bytes(), original)
            for path in destination.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            stack = json.loads((destination / 'stack.json').read_text())
            self.assertEqual(stack['services']['node_red']['environment']['NODE_RED_API_TOKEN'], 'synthetic-token')
            automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            with self.assertRaisesRegex(ValueError, 'changed'):
                automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'different-token'})

    def test_missing_secret_or_token_in_git_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            with self.assertRaises(ValueError): automation_cd.prepare_inputs(config, destination, {})
            self.assertFalse(destination.exists())
            value = json.loads(config.read_text())
            value['stack']['services']['node_red']['environment']['NODE_RED_API_TOKEN'] = 'wrong-place'
            config.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            self.assertFalse(destination.exists())

    def test_failed_plan_is_held_and_cannot_be_started_again(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(automation_cd,'prerequisites'):
            root = Path(tmp); config, destination, cfg = self.setup(root)
            runner = Mock(wraps=deploy)
            runner.execute.side_effect = ValueError('synthetic plan failure')
            with self.assertRaises(ValueError):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertTrue((root / 'state/6101/AUTOMATION-CD-HOLD.json').exists())
            self.assertEqual(runner.execute.call_count, 1)
            with self.assertRaises(ValueError):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertEqual(runner.execute.call_count, 1)

    def test_completed_guest_uses_bound_preparation_and_never_plans_or_applies_again(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(automation_cd,'prerequisites'):
            root = Path(tmp); config, destination, cfg = self.setup(root)
            work = root / 'state/6101'; work.mkdir(parents=True)
            (work / 'prepare-complete.json').write_text('synthetic verified receipt')
            runner = Mock(wraps=deploy)
            runner.automation_binding.return_value = {'vmid': 6101}
            result = automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertTrue(result['already_prepared'])
            runner.execute.assert_not_called()

    def test_original_image_missing_stops_before_the_plan_or_hold(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(automation_cd,'prerequisites'):
            root = Path(tmp); config, destination, cfg = self.setup(root)
            value = json.loads(config.read_text())
            value['stack']['services']['homeassistant'].update(image='sha256:' + '1'*64,
                archive=str(root / 'missing-image.tar'), archive_sha256='2'*64)
            config.write_text(json.dumps(value))
            runner = Mock(wraps=deploy)
            with self.assertRaisesRegex(ValueError, 'image archive'):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            runner.execute.assert_not_called()
            self.assertFalse((root / 'state/6101/AUTOMATION-CD-HOLD.json').exists())


if __name__ == '__main__': unittest.main()
