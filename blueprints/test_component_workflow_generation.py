"""Workflow-owner units plus focused actual selector/Plan integrations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

FRAMEWORK = Path(Path(__file__).resolve().parents[1]).resolve()
sys.path[:0] = [str(FRAMEWORK / 'blueprints'), str(FRAMEWORK / 'proxmox/applications')]
import authored_config
import component_workflows
import component_input_secrets
import yaml
import workflows as w
import private_workflows as pw
from test_component_plan import library, site


def graph():
    empty = lambda ident, title: {'id': ident, 'name': title, 'application': None, 'inputs': {}}
    return {'guest_order': ['store', 'viewer'], 'dependencies': {'store': [], 'viewer': ['store']},
        'monitoring_guest': None, 'guests': {
            'store': {'name': 'Database', 'needs': ['selection'], 'workflow_secrets': [],
                'phases': [empty('infrastructure', 'Infrastructure'), empty('preparation', 'Prepare'),
                           empty('database', 'Database')]},
            'viewer': {'name': 'Tools', 'needs': ['selection', 'store'],
                'workflow_secrets': ['EXAMPLE_OIDC_SECRET'], 'phases': [
                    empty('infrastructure', 'Infrastructure'), empty('preparation', 'Prepare'),
                    {'id': 'browser', 'name': 'Database tools', 'application': 'browser',
                     'inputs': {'cloudbeaver_client_secret': {'environment': 'EXAMPLE_CLIENT_SECRET',
                                                           'workflow_secret': 'EXAMPLE_OIDC_SECRET'}}}]}}}


class WorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.stack = self.root / 'stack'
        directory = self.stack / '.github/workflows'; directory.mkdir(parents=True)
        (directory / 'phase.yml').write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@' + '1' * 40 + '\n')
        self.site = self.root / 'site.yaml'; self.site.write_text('kind: site\n')

    def model(self, value=None):
        with patch.object(w.compiler, 'resolve_plan', return_value=object()) as resolver, \
             patch.object(w.component_workflows, 'model', return_value=value or graph()):
            result = w.models(self.stack, site_source=self.site)
        resolver.assert_called_once_with(self.stack, self.site, None)
        return result

    def test_phase_recipe_and_composites_preserve_setup_and_separate_credential_scopes(self):
        job, defaults = w.phase_recipe()
        import hashlib
        self.assertEqual(hashlib.sha256(json.dumps(job['steps'][:7],sort_keys=True).encode()).hexdigest(),w.SHARED_SETUP_SHA256)
        self.assertEqual(set(job['steps'][7]['env']),{'GUEST','PHASE','DISABLED'})
        self.assertEqual(set(job['steps'][8]['env']),{'GUEST','PHASE',*w.COMMON_SECRETS})
        self.assertEqual(defaults, {'run': {'shell': 'bash'}})
        actions = w.composite_actions(job)
        actual_setup = yaml.safe_load((w.PHASE_RECIPE.parents[1] / 'actions/guest-setup/action.yml').read_text())
        self.assertEqual(actions['guest-setup'], actual_setup)
        phase = actions['guest-phase']; self.assertEqual(len(phase['runs']['steps']), 4)
        for step in phase['runs']['steps'][:3]:
            self.assertFalse(any(key.startswith(component_input_secrets.PREFIX) for key in step.get('env', {})))
        deploy = phase['runs']['steps'][-1]
        self.assertEqual(set(deploy['env']), {'GUEST', 'PHASE', *[component_input_secrets.PREFIX+s.upper() for s in w.SCALAR_SLOTS]})
        self.assertNotIn('PROXMOX_APP_TOKEN', deploy['env']); self.assertNotIn('APPLICATION_SSH_KEY', deploy['env'])
        self.assertNotIn('secrets: inherit', json.dumps(phase))
        self.assertNotIn('toJSON', json.dumps(phase)); self.assertNotIn('fromJSON(secrets', json.dumps(phase))
        for slot in w.SCALAR_SLOTS:
            self.assertEqual(deploy['env'][component_input_secrets.PREFIX+slot.upper()], '${{ inputs.'+slot+' }}')

    def test_actual_graph_names_edges_app_order_and_per_phase_scalars_are_preserved(self):
        result = self.model(); deploy = result['deploy.yml']
        self.assertEqual(list(deploy['jobs']), ['selection', 'store', 'viewer'])
        self.assertEqual(deploy['jobs']['viewer']['needs'], ['selection', 'store'])
        self.assertEqual(deploy['jobs']['viewer']['name'], 'Tools')
        self.assertNotIn('uses', result['guest-viewer.yml']['jobs']['deploy'])
        for guest, name in [('store', 'Database'), ('viewer', 'Tools')]:
            job = result['guest-'+guest+'.yml']['jobs']['deploy']
            self.assertEqual(job['name'], name); self.assertEqual(job['timeout-minutes'], 135)
            self.assertEqual([s['with']['phase'] for s in job['steps'][1:]],
                             ['infrastructure','preparation','database' if guest=='store' else 'browser'])
            self.assertTrue(all(s['timeout-minutes']==45 for s in job['steps']))
            self.assertTrue(all('continue-on-error' not in s and 'if' not in s for s in job['steps']))
            for step in job['steps'][1:3]: self.assertEqual(set(step['with']), {'guest','phase','disabled',*w.COMMON_SECRETS})
        final = result['guest-viewer.yml']['jobs']['deploy']['steps'][-1]
        self.assertEqual(final['with']['cloudbeaver_client_secret'], '${{ secrets.EXAMPLE_OIDC_SECRET }}')
        self.assertNotIn('${{ secrets.EXAMPLE_CLIENT_SECRET }}', json.dumps(result))
        self.assertEqual(set(result['guest-store.yml']['on']['workflow_call']['secrets']), set(w.COMMON_SECRETS))
        self.assertEqual(set(result['phase.yml']['on']['workflow_call']['secrets']), {*w.COMMON_SECRETS,*w.SCALAR_SLOTS})

    def test_no_implicit_source_and_expression_labels_or_excess_budget_refuse(self):
        with self.assertRaises(TypeError): w.models(self.stack)
        for label in ('${{ secrets.X }}', 'a}}b', 'bad\tlabel', 'bad\x7flabel', '', 'bad\nlabel'):
            with self.subTest(label=repr(label)):
                bad=graph();bad['guests']['viewer']['name']=label
                with self.assertRaises(ValueError):self.model(bad)
        value=graph();value['guests']['viewer']['phases']*=3
        with self.assertRaisesRegex(ValueError,'360-minute'): self.model(value)

    def test_recipe_mutations_cannot_expand_context_or_change_setup(self):
        original=w.PHASE_RECIPE
        for mutate in (lambda v:v['jobs']['run']['steps'][0].update(run='true'),
                       lambda v:v['jobs']['run']['steps'][-1]['env'].update(UNDECLARED='${{ secrets.X }}'),
                       lambda v:v['jobs']['run'].update(environment='${{ vars.OTHER }}')):
            value=yaml.safe_load(original.read_text());mutate(value)
            target=self.root/'changed.yml';target.write_text(yaml.safe_dump(value,sort_keys=False))
            with self.subTest(mutation=repr(mutate)),patch.object(w,'PHASE_RECIPE',target),self.assertRaises(ValueError): w.phase_recipe(check_actions=False)

    def test_owned_generated_files_detect_drift_and_refuse_obsolete_or_symlink_paths(self):
        with patch.object(w.compiler,'resolve_plan',return_value=object()),patch.object(w.component_workflows,'model',return_value=graph()):
            with self.assertRaisesRegex(ValueError,'stale'): w.synchronize(self.stack,site_source=self.site,check=True)
            self.assertEqual(w.synchronize(self.stack,site_source=self.site,check=False),{'workflows':4,'changed':4})
            self.assertEqual(w.synchronize(self.stack,site_source=self.site,check=True)['changed'],0)
            p=self.stack/'.github/workflows/guest-viewer.yml';p.write_text('changed\n');before=p.read_bytes()
            with self.assertRaisesRegex(ValueError,'stale'):w.synchronize(self.stack,site_source=self.site,check=True)
            self.assertEqual(p.read_bytes(),before)
            old=self.stack/'.github/workflows/guest-obsolete.yml';old.write_text('keep\n')
            with self.assertRaisesRegex(ValueError,'obsolete'):w.synchronize(self.stack,site_source=self.site,check=False)
            self.assertTrue(old.exists());old.unlink();p.unlink();p.symlink_to(self.site)
            with self.assertRaisesRegex(ValueError,'regular files'):w.synchronize(self.stack,site_source=self.site,check=False)
            self.assertEqual(self.site.read_text(),'kind: site\n')

    def _source_fixture(self, *, duplicate=False, remote=False):
        stack=self.root/'stack-source';stack.mkdir()
        (stack/'.github/workflows').mkdir(parents=True)
        (stack/'.github/workflows/phase.yml').write_bytes((self.stack/'.github/workflows/phase.yml').read_bytes())
        spec=library()
        spec['software']={'unbound':{'images':{'unbound':'unbound'}}}
        spec['runtime_profiles']={'unbound':{'containers':{'unbound':{'memory_mib':256,'cpu_limit':1,'pids_limit':128}}}}
        spec['app_profiles']['recursive'].update(software=['unbound'],runtime=['unbound'])
        source=site()
        if duplicate:
            source['guests']['resolver']['resources']={'memory_mib':1024}
            source['apps']['backup']=copy.deepcopy(source['apps']['recursive_a'])
            source['apps']['backup']['properties']={'publish_port':5336}
        if remote:
            spec['app_profiles']['published']=copy.deepcopy(spec['app_profiles']['recursive'])
            profile=spec['app_profiles']['published']
            profile['interfaces']['local']['accepts']=['guest-interface']
            profile['listeners']['udp']['publish']={'scope':'guest-interface','interface':'local','port':5335}
            source['guests']['remote']=copy.deepcopy(source['guests']['resolver'])
            guest=source['guests']['remote'];guest['identity']={'vmid':611,'hostname':'example-remote'}
            for index,(key,nic) in enumerate(guest['interfaces'].items()):
                nic['mac']='02:00:00:'+str(20+index)+':00:11'
                nic['address']['value']='198.18.'+str(20+index)+'.11'
            source['apps']['remote_dns']=copy.deepcopy(source['apps']['recursive_a'])
            source['apps']['remote_dns'].update(profile='published',guest='remote')
            source['apps']['remote_dns']['interfaces']['local']={'interface':'backend'}
            source['guests']['resolver']['readiness']=[{'stage':'preparation','target':{'app':'remote_dns','endpoint':'dns'}}]
            # This fixture requests real cross-guest preparation, so explicitly
            # declare both DNS transports on each owned guest firewall.
            source['policies']={'network':{direction:{'rules':[
                {'direction':direction,'source':'198.18.20.10/32','destination':'198.18.21.11/32',
                 'proto':protocol,'port':'5335','comment':'Synthetic preparation DNS'}for protocol in ('tcp','udp')]}
                for direction in ('out','in')}}
            source['guests']['resolver']['network_policy']=['out']
            source['guests']['remote']['network_policy']=['in']
        (stack/'stack.json').write_text(json.dumps(spec))
        (stack/'images.json').write_text(json.dumps({'unbound':{'repository':'example/unbound','tag':'1','digest':'sha256:'+'a'*64}}))
        framework=self.root/'framework-source';framework.mkdir()
        shutil.copytree(FRAMEWORK/'blueprints',framework/'blueprints',ignore=shutil.ignore_patterns('__pycache__'))
        (framework/'proxmox').mkdir();shutil.copytree(FRAMEWORK/'proxmox/applications',framework/'proxmox/applications',ignore=shutil.ignore_patterns('__pycache__'))
        (self.root/'site.yaml').write_text(yaml.safe_dump(source,sort_keys=False))
        return stack,source

    def test_real_minimal_plan_has_no_implicit_guest_or_peer_application(self):
        stack,source=self._source_fixture()
        result=w.models(stack,site_source=self.root/'site.yaml')
        self.assertEqual(set(result),{'deploy.yml','phase.yml','guest-resolver.yml'})
        self.assertEqual(result['deploy.yml']['jobs']['resolver']['needs'],['selection'])
        self.assertEqual([s['with']['phase'] for s in result['guest-resolver.yml']['jobs']['deploy']['steps'][1:]],
                         ['infrastructure','preparation','recursive_a'])

    def test_real_duplicate_and_guest_stage_plans_reach_generator(self):
        stack,source=self._source_fixture(duplicate=True,remote=True)
        result=w.models(stack,site_source=self.root/'site.yaml')
        self.assertEqual(set(result),{'deploy.yml','phase.yml','guest-resolver.yml','guest-remote.yml'})
        self.assertEqual(result['deploy.yml']['jobs']['resolver']['needs'],['selection','remote'])
        self.assertEqual(result['guest-resolver.yml']['jobs']['deploy']['name'],source['guests']['resolver']['identity']['hostname'])
        self.assertEqual([s['with']['phase'] for s in result['guest-resolver.yml']['jobs']['deploy']['steps'][1:]],
                         ['infrastructure','preparation','recursive_a','backup'])
        self.assertEqual(len(result['guest-remote.yml']['jobs']['deploy']['steps']),4)

    def test_actual_generated_selector_checks_sources_closure_and_exact_metadata(self):
        stack,source=self._source_fixture(remote=True);result=w.models(stack,site_source=self.root/'site.yaml')
        gate=result['deploy.yml']['jobs']['selection'];self.assertEqual(gate['timeout-minutes'],2)
        self.assertEqual(len(gate['steps']),7);self.assertNotIn('environment',gate)
        self.assertNotIn('secrets',gate);self.assertTrue(all('secrets.' not in json.dumps(s) for s in gate['steps']))
        step=gate['steps'][-1]
        for disabled,ok in [('',True),('[]',True),('["resolver"]',True),('["resolver","remote"]',True),
                            ('["remote"]',False),('["unknown"]',False),('["remote","remote"]',False),('[1]',False),('broken',False)]:
            with self.subTest(disabled=disabled):
                env=dict(os.environ,**step['env'],HOMELAB_CONFIG_PYTHON=sys.executable);env['DISABLED']=disabled
                actual=subprocess.run(['bash','-e','-c',step['run']],cwd=self.root,env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(actual.returncode==0,ok,actual.stderr)
        source['guests']['remote']['display_name']='Changed name'
        (self.root/'site.yaml').write_text(yaml.safe_dump(source,sort_keys=False))
        env=dict(os.environ,**step['env'],HOMELAB_CONFIG_PYTHON=sys.executable);env['DISABLED']='[]'
        actual=subprocess.run(['bash','-e','-c',step['run']],cwd=self.root,env=env,capture_output=True,text=True,timeout=30)
        self.assertNotEqual(actual.returncode,0);self.assertIn('Regenerate',actual.stderr)

    def test_final_deploy_process_elides_only_empty_finite_defaults(self):
        actions=w.composite_actions(w.phase_recipe()[0]);step=actions['guest-phase']['runs']['steps'][-1]
        exe=self.root/'bin';exe.mkdir();python=exe/'python3';receipt=self.root/'process.json'
        code='#!'+sys.executable+'\nimport json,os,sys\nfrom pathlib import Path\n'
        code+="p='HOMELAB_APP_SECRET_'\nv={k:v for k,v in os.environ.items() if k.startswith(p)}\n"
        code+="result={'argv':sys.argv[1:],'slots':sorted(v),'value_unchanged':v.get(p+'CLOUDBEAVER_CLIENT_SECRET')=='fixture $value `literal`'}\n"
        code+="fd=os.open(os.environ['MOCK_RECEIPT'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\nwith os.fdopen(fd,'w') as s:json.dump(result,s)\n"
        python.write_text(code);python.chmod(0o700)
        env=dict(os.environ,PATH=str(exe)+os.pathsep+os.environ['PATH'],MOCK_RECEIPT=str(receipt),GUEST='viewer',PHASE='browser',RUNNER_TEMP=str(self.root),GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        for slot in w.SCALAR_SLOTS:env[component_input_secrets.PREFIX+slot.upper()]=''
        env[component_input_secrets.PREFIX+'CLOUDBEAVER_CLIENT_SECRET']='fixture $value `literal`'
        env[component_input_secrets.PREFIX+'FOREIGN']='fixture-other'
        actual=subprocess.run(['bash','-e','-c',step['run']],env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(actual.returncode,0,actual.stderr);self.assertEqual(actual.stdout,'');self.assertEqual(actual.stderr,'')
        value=json.loads(receipt.read_text());self.assertTrue(value['value_unchanged'])
        self.assertEqual(value['slots'],[component_input_secrets.PREFIX+'CLOUDBEAVER_CLIENT_SECRET',component_input_secrets.PREFIX+'FOREIGN'])
        self.assertEqual(value['argv'],['framework-source/proxmox/applications/deploy.py','--phase','browser','--packet',str(self.root/'guest-1-1-viewer-browser.json')])

    def test_private_materialization_uses_actual_site_and_retains_queue_and_scalar_scope(self):
        site=self.root/'consumer';(site/'.github/workflows').mkdir(parents=True)
        locator='example/stack/.github/workflows/deploy.yml@'+'2'*40
        env={'HOMELAB_STACK_SOURCE':locator,'HOMELAB_ENVIRONMENT_PREFIX':'fixture','HOMELAB_RUNNER_LABELS':'["self-hosted"]','HOMELAB_REPOSITORY':'example/consumer','HOMELAB_DISABLED':'[]'}
        doc={'env':env,'jobs':{}}
        (site/'.github/workflows/deploy.yml').write_text(yaml.safe_dump(doc,sort_keys=False).replace("HOMELAB_DISABLED: '[]'","HOMELAB_DISABLED: '[]'"))
        (site/'site.yaml').write_text('schema: homelab-components-v1\nkind: site\n')
        source=self.model()
        with patch.object(pw,'settings',return_value=(env,['self-hosted'])),patch.object(pw,'validation_workflow',return_value={'name':'Validate','steps':[]}), \
             patch.object(pw.compiler,'workflow_selection',return_value={'repository':'example/stack','revision':'2'*40}), \
             patch.object(pw.compiler,'check_revision') as revision,patch.object(pw.subprocess,'check_output',return_value=''), \
             patch.object(w,'models',return_value=source) as models:
            result=pw.model(self.stack,site)
        models.assert_called_once_with(self.stack,site_source=site/'site.yaml',disabled=[])
        revision.assert_called_once_with(self.stack,'2'*40)
        self.assertEqual(result['concurrency'],{'group':'homelab-private-deployment','cancel-in-progress':False,'queue':'max'})
        self.assertEqual(result['jobs']['selection']['needs'],['validate'])
        viewer=result['jobs']['viewer'];self.assertEqual(viewer['environment'],'fixture-viewer')
        self.assertEqual(viewer['needs'],['selection','store']);self.assertEqual(viewer['runs-on'],['self-hosted'])
        self.assertNotIn('inputs.',json.dumps(viewer));self.assertNotIn('secrets: inherit',json.dumps(result))
        self.assertEqual(viewer['steps'][-1]['with']['cloudbeaver_client_secret'],'${{ secrets.EXAMPLE_OIDC_SECRET }}')


if __name__=='__main__':unittest.main()
