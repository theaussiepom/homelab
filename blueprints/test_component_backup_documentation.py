"""The complete documented composition exercises real compiler boundaries."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import yaml

import component_plan
import component_packet
from component_errors import ComponentError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / 'docs/examples/backup'


class BackupDocumentation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'example'
        shutil.copytree(EXAMPLE, self.root)
        self.path = self.root / 'site.yaml'
        self.site = yaml.safe_load(self.path.read_text())

    def plan(self, disabled=None):
        self.path.write_text(yaml.safe_dump(self.site))
        return component_plan.resolve(self.root, self.path, disabled)

    def test_complete_example_resolves_management_public_key_and_guest_packet(self):
        plan = self.plan()
        packet = component_packet.lower_plan(plan)['resolver']
        cfg = json.loads(packet['files']['site.json'])
        job = cfg['app']['backup']['job']
        self.assertFalse(cfg['guest']['volumes']['backup-stage']['backup'])
        self.assertEqual(job['destination']['backup_id'], 'guest-610')
        self.assertEqual(job['destination']['datastore'], 'recovery')
        self.assertEqual(cfg['deployment']['phases'][-1], 'pbs-agent')
        self.assertEqual(plan.resolved['backup']['management']['credential']['name'], 'PBS_API_TOKEN')
        self.assertNotIn('PBS_API_TOKEN', json.dumps(packet))
        public = (self.root / 'assets/master-public.pem.fixture').read_text()
        self.assertEqual(job['recovery_public_key']['pem'], public)
        self.assertEqual(plan.pins['site']['assets/master-public.pem.fixture'], hashlib.sha256(public.encode()).hexdigest())
        self.assertEqual(component_packet.lower_plan(self.plan())['resolver'], packet)
        disabled = self.plan(['resolver'])
        self.assertEqual(disabled.resolved['enabled'], [])
        self.assertEqual(set(disabled.resolved['backup']['group']['group']['members']), {'guest-610'})

    def test_actual_backup_example_generates_separate_management_job(self):
        import workflows
        import component_workflows
        import private_workflows
        from unittest.mock import patch
        directory=self.root/'.github/workflows';directory.mkdir(parents=True)
        (directory/'phase.yml').write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@'+'1'*40+'\n')
        plan=self.plan();graph=component_workflows.model(plan)
        self.assertEqual(graph['backup']['needs'],['selection','resolver'])
        model=workflows.models(self.root,site_source=self.path)
        self.assertEqual(model['backup.yml']['jobs']['deploy']['environment'],'backup')
        self.assertNotIn('PBS_API_TOKEN',json.dumps(model['guest-resolver.yml']))
        env={'HOMELAB_ENVIRONMENT_PREFIX':'example','HOMELAB_REPOSITORY':'example/private'}
        with patch.object(private_workflows,'settings',return_value=(env,['self-hosted'])), \
             patch.object(private_workflows,'validation_workflow',return_value={'name':'Validate'}), \
             patch.object(private_workflows.compiler,'workflow_selection',return_value={'revision':'a'*40,'repository':'example/framework'}), \
             patch.object(private_workflows.compiler,'check_revision'), \
             patch.object(private_workflows.compiler,'workflow_disabled',return_value=[]), \
             patch.object(private_workflows.subprocess,'check_output',return_value=''):
            (directory/'deploy.yml').write_text('synthetic private source')
            private=private_workflows.model(self.root,self.root)
        self.assertEqual(private['jobs']['_backup']['environment'],'backup')
        self.assertEqual(private['jobs']['_backup']['needs'],['selection','resolver'])
        self.assertNotIn('inputs.',json.dumps(private['jobs']['_backup']))

    def test_documented_shared_only_variation_does_not_enroll_guests(self):
        self.site['guests']['resolver'].pop('backup')
        with self.assertRaisesRegex(ComponentError, 'backup-client-coverage'): self.plan()
        self.site['backup'] = {}
        cfg = json.loads(component_packet.lower_plan(self.plan())['resolver']['files']['site.json'])
        self.assertNotIn('backup', cfg['app'])
        self.assertNotIn('pbs-agent', cfg['deployment']['phases'])

    def test_new_fields_fail_at_the_documented_component_boundary(self):
        original = copy.deepcopy(self.site)
        cases = [
            (lambda s: s['backup'].pop('management'), 'backup-recovery-key'),
            (lambda s: s['backup']['management'].update(datastore_path='/'), 'backup-datastore-path'),
            (lambda s: s['backup']['management'].update(credential='missing'), 'backup-management-credential'),
            (lambda s: s['backup']['recovery_public_key'].update(source='missing.pem'), 'source'),
            (lambda s: s['backup']['job']['clients']['resolver'].update(password='obsolete'), 'fields'),
        ]
        for mutate, code in cases:
            self.site = copy.deepcopy(original); mutate(self.site)
            with self.subTest(code=code), self.assertRaisesRegex(ComponentError, code): self.plan()


if __name__ == '__main__': unittest.main()
