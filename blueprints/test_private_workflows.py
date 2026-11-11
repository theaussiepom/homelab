"""Plain guest names retain the actual recipe, DAG and isolated secret subsets."""
import copy
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml

import private_workflows as p
import workflows
from test_component_plan import library, site

CI_JOBS = 'jobs:\n  source:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo synthetic\n'


def composition():
    """Actual typed source/Plan fixture; initialized native data is not exercised."""
    spec, source = library(), site()
    spec['app_profiles'] = {'resolver': {
        'adapter': 'pihole', 'display_name': 'Pi-hole',
        'interfaces': {role: {'required': True, 'accepts': ['guest-interface']}
                       for role in ('service_interface', 'upstream_interface')},
        'listeners': {name: {'service': 'pihole', 'namespace': 'host', 'interface': 'service_interface',
                            'bind': 'wildcard', 'protocol': protocol, 'port': port}
                      for name, protocol, port in (('udp_listener', 'udp', 53), ('tcp_listener', 'tcp', 53), ('web_listener', 'tcp', 80))},
        'endpoints': {'dns_endpoint': {'listener': 'udp_listener', 'protocol': 'udp', 'via': 'service_interface'}},
        'storage': {'config': {'target': '/etc/pihole', 'kind': 'directory',
                               'required': True, 'read_only': False}},
        'connections': {'upstream': {'type': 'dns', 'required': True, 'readiness': ['start']}},
        'software': ['resolver'], 'runtime': ['resolver']}}
    spec['software'] = {'resolver': {'images': {'pihole': 'pihole'}}}
    spec['runtime_profiles'] = {'resolver': {'containers': {'pihole': {
        'memory_mib': 128, 'cpu_limit': 1, 'pids_limit': 128}}}}
    base = source['guests'].pop('resolver'); source['apps'] = {}
    for index, (name, title) in enumerate((('database', 'Database'), ('web', 'Web'))):
        guest = copy.deepcopy(base); guest['display_name'] = title
        guest['identity'].update(vmid=610 + index, hostname='example-' + name)
        for slot, nic in enumerate(guest['interfaces'].values()):
            nic['mac'] = '02:00:00:' + str(20 + slot) + ':00:' + str(10 + index)
            nic['address']['value'] = '198.18.' + str(20 + slot) + '.' + str(10 + index)
        guest['volumes'] = {'data': {'storage': 'local', 'slot': 0,
                                     'path': '/srv/example/data', 'size_gib': 2}}
        source['guests'][name] = guest
        source['apps'][name + '_dns'] = {'guest': name, 'profile': 'resolver', 'lifecycle': 'fresh',
            'interfaces': {'service_interface': {'interface': 'management'}, 'upstream_interface': {'interface': 'management'}},
            'storage': {'config': {'volume': 'data', 'subpath': 'pihole'}}}
    source['connections'] = {
        'database_upstream': {'consumer': {'app': 'database_dns', 'connection': 'upstream'},
            'target': {'external': 'dns'}, 'source_interface': 'upstream_interface'},
        'web_upstream': {'consumer': {'app': 'web_dns', 'connection': 'upstream'},
            'target': {'app': 'database_dns', 'endpoint': 'dns_endpoint'}, 'source_interface': 'upstream_interface',
            'readiness': 'start'}}
    # These finite grants are source intent in this synthetic fixture. The actual
    # resolver checks both sides; a connection never installs a policy itself.
    source['policies'] = {'network': {
        'dns_out': {'rules': [{'direction': 'out', 'proto': protocol, 'port': '53',
            'source': {'interface': 'local'}, 'destination': {'endpoint': 'peer'},
            'interface': 'local', 'comment': 'Selected DNS egress'} for protocol in ('tcp', 'udp')]},
        'dns_in': {'rules': [{'direction': 'in', 'proto': protocol, 'port': '53',
            'source': {'interface': 'client'}, 'destination': {'interface': 'local'},
            'interface': 'local', 'comment': 'Selected DNS ingress'} for protocol in ('tcp', 'udp')]}}}
    source['guests']['database']['network_policy'] = [
        {'policy': 'dns_out', 'interfaces': {'local': 'management'}, 'endpoints': {'peer': {'external': 'dns'}}},
        {'policy': 'dns_in', 'interfaces': {'local': 'management', 'client': {'app': 'web_dns', 'interface': 'upstream_interface'}}}]
    source['guests']['web']['network_policy'] = [
        {'policy': 'dns_out', 'interfaces': {'local': 'management'},
         'endpoints': {'peer': {'app': 'database_dns', 'endpoint': 'dns_endpoint'}}}]
    return spec, source


class PrivateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stack, self.site = self.root/'stack', self.root/'site'
        for root in (self.stack, self.site):
            (root/'.github/workflows').mkdir(parents=True)
        self.spec, self.source = composition()
        self.env = {'HOMELAB_STACK_SOURCE':'owner/stack/.github/workflows/deploy.yml@'+'a'*40,
                    'HOMELAB_ENVIRONMENT_PREFIX':'private-apps','HOMELAB_RUNNER_LABELS':'["self-hosted","linux"]',
                    'HOMELAB_REPOSITORY':'owner/site'}
        (self.stack/'.github/workflows/phase.yml').write_text('jobs:\n  run:\n    uses: owner/framework/.github/workflows/guest-phase.yml@'+'b'*40+'\n')
        (self.site/'site.json').write_text(json.dumps(self.source))
        (self.stack/'images.json').write_text(json.dumps({'pihole': {
            'repository': 'example/pihole', 'tag': '1', 'digest': 'sha256:' + 'a' * 64}}))
        (self.site/'.github/workflows/ci.yml').write_text('on:\n  workflow_call:\n' + CI_JOBS)
        (self.stack/'stack.json').write_text(json.dumps(self.spec))
        subprocess.run(['git', 'init', '-q', str(self.stack)], check=True)
        self.freeze_stack()

    def freeze_stack(self):
        """Commit each synthetic revision before declaring it as runtime source."""
        subprocess.run(['git', '-C', str(self.stack), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.stack), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Synthetic source fixture'], check=True)
        self.revision = subprocess.check_output(['git', '-C', str(self.stack), 'rev-parse', 'HEAD'], text=True).strip()
        self.env['HOMELAB_STACK_SOURCE'] = 'owner/stack/.github/workflows/deploy.yml@' + self.revision
        self.write()

    def write(self):
        (self.site/'.github/workflows/deploy.yml').write_text(yaml.safe_dump({'env':self.env},sort_keys=False))

    def test_native_jobs_use_only_guest_names_and_preserve_operations(self):
        value=p.model(self.stack,self.site);public=workflows.models(self.stack, site_source=self.site / 'site.json')
        self.assertEqual(set(value['jobs']),{'validate','selection','database','web'})
        self.assertEqual(value['concurrency'],{'group':'homelab-private-deployment','cancel-in-progress':False,'queue':'max'})
        for guest,title in [('database','Database'),('web','Web')]:
            job=value['jobs'][guest];old=public['guest-'+guest+'.yml']['jobs']['deploy']
            self.assertEqual(job['name'],title)
            self.assertEqual(job['environment'],'private-apps-'+guest)
            self.assertEqual(job['runs-on'],['self-hosted','linux'])
            self.assertEqual(job['needs'],public['deploy.yml']['jobs'][guest]['needs'])
            self.assertEqual(job['timeout-minutes'],old['timeout-minutes'])
            for actual,expected in zip(job['steps'],old['steps'],strict=True):
                self.assertEqual(actual,p.bind(expected,'[]'))
            self.assertIn("github.repository == 'owner/site'",job['if'])
            self.assertNotIn('inputs.',json.dumps(job))
        self.assertEqual(value['jobs']['selection']['needs'],['validate'])

    def test_yaml_site_uses_the_same_generator_and_ambiguous_sources_refuse(self):
        expected=p.model(self.stack,self.site)
        original=self.site/'site.json';raw=original.read_bytes();document=json.loads(raw);original.unlink()
        for suffix in ('.yaml','.yml'):
            path=self.site/('site'+suffix);path.write_text(yaml.safe_dump(document,sort_keys=False))
            self.assertEqual(p.model(self.stack,self.site),expected)
            original.write_bytes(raw)
            with self.assertRaises(ValueError):p.model(self.stack,self.site)
            original.unlink();path.unlink()

    def test_missing_or_nonreusable_local_ci_refuses_before_generation(self):
        path = self.site / '.github/workflows/ci.yml'
        for raw in [None, '', '[]', 'on: push\n', 'on: [push]\n', 'on: {}\n',
                    'on: null\n', 'on: 7\n', 'on: not_workflow_call\n']:
            if raw is None:
                path.unlink()
            else:
                path.write_text(raw)
            with self.subTest(raw=raw), patch.object(workflows, 'models') as generate:
                with self.assertRaisesRegex(ValueError, 'reusable local CI workflow'):
                    p.model(self.stack, self.site)
                generate.assert_not_called()
        path.unlink()
        path.symlink_to(self.site / 'site.json')
        with self.assertRaisesRegex(ValueError, 'reusable local CI workflow'):
            p.model(self.stack, self.site)
        path.unlink()
        for raw in ['on:\n  workflow_call:\n', "'on':\n  workflow_call: {}\n",
                    'on: workflow_call\n', 'on: [push, workflow_call]\n']:
            path.write_text(raw + CI_JOBS)
            job = p.model(self.stack, self.site)['jobs']['validate']
            self.assertEqual(job['name'], 'Validate')
            self.assertNotIn('uses', job)
            self.assertEqual(job['steps'], [{'run': 'echo synthetic'}])
            self.assertEqual(job['defaults'], {'run': {'shell': 'bash -e {0}'}})

    def test_native_validation_preserves_every_source_step_and_job_setting(self):
        path = self.site / '.github/workflows/ci.yml'
        value = yaml.safe_load(path.read_text())
        value['permissions'] = {'contents': 'read'}
        source = value['jobs']['source']
        source.update(name='Long original title', **{'timeout-minutes': 9,
                      'defaults': {'run': {'shell': 'bash'}}})
        source['steps'].append({'name': 'Check source', 'run': 'python3 check.py',
                                'env': {'SELECTED': '${{ github.sha }}'}})
        path.write_text(yaml.safe_dump(value))
        self.assertEqual(p.model(self.stack, self.site)['jobs']['validate'],
                         {**source, 'name': 'Validate'})

    def test_native_validation_refuses_to_drop_other_jobs_or_workflow_context(self):
        path = self.site / '.github/workflows/ci.yml'
        original = yaml.safe_load(path.read_text())
        variants = []
        for jobs in [{'other': {'steps': []}}, {'source': None}, {'source': {}},
                     {'source': {'steps': 'not-steps'}},
                     {'source': {'steps': []}, 'other': {'steps': []}}]:
            value = copy.deepcopy(original); value['jobs'] = jobs; variants.append(value)
        for key, setting in [('env', {'EXTRA': 'value'}), ('permissions', {'contents': 'write'})]:
            value = copy.deepcopy(original); value[key] = setting; variants.append(value)
        for value in variants:
            path.write_text(yaml.safe_dump(value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.model(self.stack, self.site)

    def test_native_validation_refuses_an_unbound_reusable_input_condition(self):
        path = self.site / '.github/workflows/ci.yml'
        value = yaml.safe_load(path.read_text())
        for expression in ['${{ inputs.x }}', "${{ inputs['x'] }}",
                           '${{ inputs["x"] }}', "${{ inputs \n ['x'] }}"]:
            value['jobs']['source']['if'] = expression
            path.write_text(yaml.safe_dump(value))
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, 'closed validation job inputs'):
                p.model(self.stack, self.site)

    def test_guest_run_refuses_bracket_input_references_after_materialisation(self):
        original = workflows.models
        for expression in ["${{ inputs['x'] }}", '${{ inputs["x"] }}',
                           "${{ inputs \n ['x'] }}"]:
            def changed(stack, **kwargs):
                value = original(stack, **kwargs)
                value['guest-web.yml']['jobs']['deploy']['steps'][-1]['with']['extra'] = expression
                return value
            with self.subTest(expression=expression), patch.object(workflows, 'models', changed):
                with self.assertRaisesRegex(ValueError, 'closed guest workflow inputs'):
                    p.model(self.stack, self.site)

    def test_reusable_ci_requires_nonempty_job_mapping(self):
        path = self.site / '.github/workflows/ci.yml'
        for jobs in ['', 'jobs: {}\n', 'jobs: []\n', 'jobs: null\n']:
            path.write_text('on:\n  workflow_call:\n' + jobs)
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, 'containing jobs'):
                p.validation_workflow(self.site)

    def test_disabled_defaults_and_valid_leaf_exclusion_are_literal(self):
        self.env['HOMELAB_DISABLED']='["web"]';self.write()
        value=p.model(self.stack,self.site)
        self.assertNotIn('web',value['jobs'])
        self.assertIn("fromJSON('[\"web\"]')",value['jobs']['database']['if'])
        self.assertTrue(any(s.get('with',{}).get('disabled')=='["web"]' for s in value['jobs']['database']['steps']))
        self.env['HOMELAB_DISABLED']='';self.write();p.model(self.stack,self.site)
        self.env['HOMELAB_DISABLED']='["database"]';self.write()
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
            def changed(stack, **kwargs):
                models=original(stack, **kwargs)
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
        self.assertEqual(p.compiler.workflow_selection(path,'deploy.yml')['revision'],self.revision)
        path.write_text(path.read_text()+'jobs:\n  other:\n    uses: owner/stack/.github/workflows/deploy.yml@'+'c'*40+'\n')
        with self.assertRaises(ValueError):p.compiler.workflow_selection(path,'deploy.yml')

    def test_stack_pin_mismatch_refuses_before_recipe_generation(self):
        self.env['HOMELAB_STACK_SOURCE'] = 'owner/stack/.github/workflows/deploy.yml@' + 'f'*40
        self.write()
        with patch.object(workflows, 'models') as generate:
            with self.assertRaisesRegex(ValueError, 'Checked out source differs'):
                p.model(self.stack, self.site)
            generate.assert_not_called()

    def test_quoted_metadata_refuses_the_noncanonical_source_selection(self):
        path = self.site / '.github/workflows/deploy.yml'
        original = path.read_text()
        line = '  HOMELAB_STACK_SOURCE: owner/stack/.github/workflows/deploy.yml@' + self.revision
        for mark in ("'", '"'):
            path.write_text(original.replace(line, '  HOMELAB_STACK_SOURCE: ' + mark + line.split(': ',1)[1] + mark))
            with self.assertRaisesRegex(ValueError, 'one immutable workflow selection'):
                p.settings(self.site)

    def test_matching_head_with_modified_or_untracked_source_refuses(self):
        original = (self.stack / 'stack.json').read_text()
        for mode in ('tracked', 'untracked'):
            if mode == 'tracked':
                (self.stack / 'stack.json').write_text(original + '\n')
            else:
                (self.stack / 'stack.json').write_text(original)
                (self.stack / 'untracked-input.json').write_text('{}')
            with self.subTest(mode=mode), patch.object(workflows, 'models') as generate:
                with self.assertRaisesRegex(ValueError, 'clean pinned stack source'):
                    p.model(self.stack, self.site)
                generate.assert_not_called()
