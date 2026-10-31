"""Plain guest names retain the actual recipe, DAG and isolated secret subsets."""
import copy
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch
import yaml

import private_workflows as p
import workflows


class PrivateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack, self.site = self.root/'stack', self.root/'site'
        for root in (self.stack, self.site):
            (root/'.github/workflows').mkdir(parents=True)
        self.catalogue = {name: {'name': title, 'applications': ['service'], 'application_names': {'service': title}}
                          for name, title in [('database','Database'),('web','Web')]}
        self.spec = {'schema':'homelab-stack-v2','routes':{},'values':{},'guests':{
            'database':{'depends_on':[],'prerequisites':[]},'web':{'depends_on':['database'],'prerequisites':[]}}}
        self.env = {'HOMELAB_STACK_SOURCE':'owner/stack/.github/workflows/deploy.yml@'+'a'*40,
                    'HOMELAB_ENVIRONMENT_PREFIX':'private-apps','HOMELAB_RUNNER_LABELS':'["self-hosted","linux"]',
                    'HOMELAB_REPOSITORY':'owner/site'}
        (self.stack/'.github/workflows/phase.yml').write_text('jobs:\n  run:\n    uses: owner/framework/.github/workflows/guest-phase.yml@'+'b'*40+'\n')
        (self.site/'site.json').write_text('{}')
        (self.stack/'stack.json').write_text(json.dumps(self.spec))
        self.write()
        mock = patch.object(workflows.compiler,'CATALOGUE',self.catalogue)
        mock.start();self.addCleanup(mock.stop)

    def write(self):
        (self.site/'.github/workflows/deploy.yml').write_text(yaml.safe_dump({'env':self.env},sort_keys=False))

    def test_native_jobs_use_only_guest_names_and_preserve_operations(self):
        value=p.model(self.stack,self.site);public=workflows.models(self.stack)
        self.assertEqual(set(value['jobs']),{'validate','selection','database','web'})
        self.assertEqual(value['concurrency'],{'group':'homelab-private-deployment','cancel-in-progress':False,'queue':'max'})
        for guest,title in [('database','Database'),('web','Web')]:
            job=value['jobs'][guest];old=public['guest-'+guest+'.yml']['jobs']['deploy']
            self.assertEqual(job['name'],title)
            self.assertEqual(job['environment'],'private-apps-'+guest)
            self.assertEqual(job['runs-on'],['self-hosted','linux'])
            self.assertEqual(job['needs'],public['deploy.yml']['jobs'][guest]['needs'])
            self.assertEqual(job['timeout-minutes'],old['timeout-minutes'])
            for actual,expected in zip(job['steps'],old['steps']):
                if actual['name']=='Choose services':
                    self.assertEqual(actual['run'],p.CHOOSE_STACK)
                else:self.assertEqual(actual,p.bind(expected,'[]'))
            self.assertIn("github.repository == 'owner/site'",job['if'])
            self.assertNotIn('inputs.',json.dumps(job))
        self.assertEqual(value['jobs']['selection']['needs'],['validate'])

    def test_disabled_defaults_and_valid_leaf_exclusion_are_literal(self):
        self.env['HOMELAB_DISABLED']='["web"]';self.write()
        value=p.model(self.stack,self.site)
        self.assertIn("fromJSON('[\"web\"]')",value['jobs']['web']['if'])
        self.assertTrue(any(s.get('env',{}).get('DISABLED')=='["web"]' for s in value['jobs']['web']['steps']))
        self.env['HOMELAB_DISABLED']='';self.write();p.model(self.stack,self.site)
        self.env['HOMELAB_DISABLED']='["database"]';self.write()
        with self.assertRaises(ValueError):p.model(self.stack,self.site)

    def test_optional_server_absent_adds_no_box_and_present_is_coherent(self):
        self.catalogue['monitoring']={'name':'Zabbix','applications':['service'],'application_names':{'service':'Zabbix'}}
        self.spec['guests']['monitoring']={'depends_on':['database'],'prerequisites':[]}
        (self.stack/'stack.json').write_text(json.dumps(self.spec))
        self.assertNotIn('monitoring',p.model(self.stack,self.site)['jobs'])
        (self.site/'site.json').write_text('{"zabbix":null}')
        self.assertEqual(p.model(self.stack,self.site)['jobs']['monitoring']['name'],'Zabbix')
        self.env['HOMELAB_DISABLED']='["monitoring"]';self.write()
        with self.assertRaises(ValueError):p.model(self.stack,self.site)

    def test_literal_settings_refuse_unknown_keys_expressions_unsafe_scope_and_runner_changes(self):
        original=copy.deepcopy(self.env)
        for key,value in [('EXTRA','x'),('HOMELAB_REPOSITORY','not-a-repo'),('HOMELAB_ENVIRONMENT_PREFIX','../elsewhere'),
                          ('HOMELAB_STACK_SOURCE','owner/stack@main'),('HOMELAB_RUNNER_LABELS','[]'),
                          ('HOMELAB_RUNNER_LABELS','["ubuntu-latest"]'),('HOMELAB_RUNNER_LABELS','["self-hosted","self-hosted"]'),
                          ('HOMELAB_RUNNER_LABELS','["self-hosted",3]'),('HOMELAB_RUNNER_LABELS','["self-hosted","bad label"]'),
                          ('HOMELAB_REPOSITORY','${{ github.repository }}'),('HOMELAB_REPOSITORY',False),('HOMELAB_REPOSITORY','a\nb')]:
            with self.subTest(key=key,value=value):
                self.env=copy.deepcopy(original);self.env[key]=value;self.write()
                with self.assertRaises(ValueError):p.settings(self.site)
        self.env=original;self.write()
        path=self.site/'.github/workflows/deploy.yml'
        for raw in ['[]','{}','env: []\n']:
            path.write_text(raw)
            with self.assertRaises(ValueError):p.settings(self.site)

    def test_foreign_secret_and_unbound_input_cannot_enter_generated_jobs(self):
        original=workflows.models
        for expression in ['${{ secrets.FOREIGN }}','${{ inputs.extra }}']:
            def changed(stack):
                models=original(stack)
                models['guest-web.yml']['jobs']['deploy']['env']['FORGED']=expression
                return models
            with self.subTest(expression=expression),patch.object(workflows,'models',changed):
                with self.assertRaises(ValueError):p.model(self.stack,self.site)

    def test_exact_source_check_refuses_drift_and_write_is_explicit(self):
        self.assertTrue(p.synchronize(self.stack,self.site,check=False))
        self.assertFalse(p.synchronize(self.stack,self.site,check=False))
        self.assertFalse(p.synchronize(self.stack,self.site,check=True))
        path=self.site/'.github/workflows/deploy.yml';path.write_text(path.read_text()+'\n')
        with self.assertRaises(ValueError):p.synchronize(self.stack,self.site,check=True)
        p.synchronize(self.stack,self.site,check=False)
        argv=['private_workflows.py','--stack',str(self.stack),'--site',str(self.site),'--check']
        with patch('sys.argv',argv),patch('sys.stdout',new=io.StringIO()) as output:
            runpy.run_path(str(Path(p.__file__)),run_name='__main__')
        self.assertFalse(json.loads(output.getvalue())['targets_contacted'])

    def test_metadata_source_selection_rejects_two_pins(self):
        path=self.site/'.github/workflows/deploy.yml'
        self.assertEqual(p.compiler.workflow_selection(path,'deploy.yml')['revision'],'a'*40)
        path.write_text(path.read_text()+'jobs:\n  other:\n    uses: owner/stack/.github/workflows/deploy.yml@'+'c'*40+'\n')
        with self.assertRaises(ValueError):p.compiler.workflow_selection(path,'deploy.yml')
