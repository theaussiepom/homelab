"""Plain guest names retain the actual recipe, DAG and isolated secret subsets."""
import copy
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
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


def pbs_document(labels):
    """Only the fixed local-call ABI; private tests own the real shell body."""
    return {'name': 'PBS firewall', 'on': {
        'pull_request': {'paths': ['bootstrap/pbs-firewall.yaml', 'bootstrap/pbs-known_hosts',
            'tests/fixtures/pbs-firewall.example.yaml', p.PBS_WORKFLOW]},
        'workflow_call': {'secrets': {p.PBS_SECRET: {'required': True}}}},
        'permissions': {'contents': 'read'}, 'jobs': {
            'validate': {'runs-on': 'ubuntu-24.04',
                'outputs': {'selected': '${{ steps.selection.outputs.selected }}'},
                'steps': [{'id':'selection','run': 'echo selected=true >> "$GITHUB_OUTPUT"'}]},
            'firewall': {'needs': 'validate', 'if': workflows.PRIVATE_MAIN + " && needs.validate.outputs.selected == 'true'",
                'environment': 'homelab-bootstrap', 'runs-on': labels, 'timeout-minutes': 15,
                'steps': [{'env': {p.PBS_SECRET: '${{ secrets.' + p.PBS_SECRET + ' }}'},
                    'run': 'test -n "$PBS_FIREWALL_SSH_KEY"'}]}}}


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

    def write_pbs(self, value=None):
        """Author only public synthetic metadata, never contact a target."""
        path = self.site / p.PBS_WORKFLOW
        path.write_text(yaml.safe_dump(pbs_document(['self-hosted', 'linux']) if value is None else value))
        return path

    def with_backup(self, plan):
        """Supply only component graph metadata; retain real workflow/recipe lowering."""
        graph = self.original_graph(plan)
        graph['backup'] = {'name': 'Configure backups', 'needs': ['selection'],
                          'environment': 'backup', 'workflow_secrets': ['PBS_API_TOKEN']}
        return graph

    def test_parallel_source_checks_gate_setup_and_every_guest_path(self):
        public = workflows.models(self.stack, site_source=self.site/'site.json')
        baseline = p.model(self.stack,self.site)
        for identifier, title in [('validate','Validate config'),('selection','Validate deployment')]:
            job = baseline['jobs'][identifier]
            self.assertEqual(job['name'],title)
            self.assertNotIn('needs',job)
            self.assertNotIn('environment',job)
            self.assertNotIn('secrets.',json.dumps(job))
        for guest in ('database','web'):
            self.assertEqual(baseline['jobs'][guest]['needs'],
                             ['validate',*public['deploy.yml']['jobs'][guest]['needs']])
            self.assertIn("needs.validate.result == 'success'",baseline['jobs'][guest]['if'])

        self.write_pbs()
        policy_only = p.model(self.stack,self.site)
        self.original_graph = workflows.component_workflows.model
        def enrolled(plan):
            graph = self.with_backup(plan)
            for guest in graph['guests'].values():
                guest['needs'].insert(1,'_backup')
            return graph
        with patch.object(workflows.component_workflows,'model',side_effect=enrolled):
            operational = p.model(self.stack,self.site)
        for value in (policy_only,operational):
            self.assertEqual(set(value['jobs']),{'validate','selection','_backup','database','web'})
            backup = value['jobs']['_backup']
            self.assertEqual(backup['name'],'Configure backups')
            self.assertEqual(backup['needs'],['validate','selection'])
            required = set(("github.repository == 'owner/site' && " + workflows.PRIVATE_MAIN).split(' && '))
            required |= {'!failure()','!cancelled()',"needs.validate.result == 'success'","needs.selection.result == 'success'"}
            self.assertEqual(set(backup['if'].split(' && ')),required)
            self.assertNotIn('needs',value['jobs']['validate'])
            self.assertNotIn('needs',value['jobs']['selection'])
        for guest in ('database','web'):
            self.assertEqual(policy_only['jobs'][guest],baseline['jobs'][guest])
            self.assertEqual(operational['jobs'][guest]['needs'],
                             ['selection','_backup',*public['deploy.yml']['jobs'][guest]['needs'][1:]])
            self.assertEqual(operational['jobs'][guest]['steps'],baseline['jobs'][guest]['steps'])
            self.assertEqual(operational['jobs'][guest]['environment'],baseline['jobs'][guest]['environment'])

    def test_pbs_is_one_early_backup_job_with_named_step_secret_and_no_inner_queue(self):
        baseline=p.model(self.stack,self.site)
        self.write_pbs();value=p.model(self.stack,self.site)
        self.assertNotIn('_pbs',value['jobs'])
        backup=value['jobs']['_backup']
        self.assertEqual(backup['name'],'Configure backups');self.assertEqual(backup['needs'],['validate','selection'])
        self.assertEqual(backup['environment'],'homelab-bootstrap');self.assertEqual(backup['timeout-minutes'],15)
        self.assertNotIn('concurrency',backup)
        native=backup['steps'][-1]
        self.assertEqual(native['env'],{'PBS_FIREWALL_SSH_KEY':'${{ secrets.PBS_FIREWALL_SSH_KEY }}'})
        self.assertEqual(native['if'],"success() && steps.pbs_check_selection.outputs.selected == 'true'")
        restored=copy.deepcopy(value);del restored['jobs']['_backup'];self.assertEqual(restored,baseline)

    def test_pbs_and_schedule_share_one_job_before_guests_without_a_final_coordinator(self):
        self.original_graph=workflows.component_workflows.model
        with patch.object(workflows.component_workflows,'model',side_effect=self.with_backup):
            before=p.model(self.stack,self.site);self.write_pbs();after=p.model(self.stack,self.site)
        backup=after['jobs']['_backup']
        self.assertEqual(backup['needs'],['validate','selection']);self.assertNotIn('_pbs',after['jobs'])
        self.assertEqual(backup['steps'][-1],before['jobs']['_backup']['steps'][-1])
        self.assertEqual(backup['steps'][0],before['jobs']['_backup']['steps'][0])
        self.assertNotIn('if',backup['steps'][-1]);self.assertNotIn('continue-on-error',backup['steps'][-1])
        self.assertEqual(backup['steps'][-1]['env'],{'DISABLED':'[]','PBS_API_TOKEN':'${{ secrets.PBS_API_TOKEN }}'})
        self.assertTrue(all('database' not in item and 'web' not in item for item in backup['needs']))
        for guest in ('database','web'):self.assertEqual(after['jobs'][guest],before['jobs'][guest])
        self.assertLess(next(i for i,row in enumerate(backup['steps']) if 'PBS_FIREWALL_SSH_KEY' in row.get('env',{})),len(backup['steps'])-1)

    def test_pbs_inline_reuses_checked_sources_and_locked_tools_and_namespaces_step_outputs(self):
        value=pbs_document(['self-hosted','linux'])
        checkout='actions/checkout@'+'a'*40
        value['jobs']['validate']['steps'][:0]=[
            {'uses':checkout,'with':{'persist-credentials':False}},
            {'uses':checkout,'with':{'persist-credentials':False,'repository':'example/framework','ref':'1'*40,'path':'framework-source'}},
            {'name':'Install source tools','run':'python3 -m pip install --require-hashes -r framework-source/requirements.lock.txt'}]
        value['jobs']['firewall']['steps'].append({'id':'inputs','run':'echo work=synthetic >> "$GITHUB_OUTPUT"',
                                                'timeout-minutes':3,'continue-on-error':False})
        value['jobs']['firewall']['steps'].append({'if':"always() && steps.inputs.outputs.work != ''",'run':'echo "${{ steps.inputs.outputs.work }}"'})
        selected={'repository':'example/framework','revision':'1'*40}
        steps=p.pbs_steps(value,selected)
        self.assertEqual(len(steps),4)
        self.assertEqual(steps[0]['id'],'pbs_check_selection')
        self.assertIn('steps.pbs_host_inputs.outputs.work',steps[-1]['run'])
        self.assertIn('always()',steps[-1]['if']);self.assertIn('pbs_check_selection',steps[-1]['if'])
        for mutate in (lambda v:v['jobs']['validate']['steps'][0]['with'].update(ref='foreign'),
                       lambda v:v['jobs']['validate']['steps'][1]['with'].update(ref='2'*40),
                       lambda v:v['jobs']['validate']['steps'][1]['with'].update(repository='foreign/framework'),
                       lambda v:v['jobs']['validate']['steps'][1].update(id='checkout'),
                       lambda v:v['jobs']['validate']['steps'][2].update(env={'FOREIGN':'value'}),
                       lambda v:v['jobs']['firewall']['steps'][0].update(run='/opt/homelab-tools/bin/ansible-playbook'),
                       lambda v:v['jobs']['firewall']['steps'][0].update(**{'continue-on-error':True}),
                       lambda v:v['jobs']['firewall']['steps'][0].update(run="echo ${{ steps['inputs'].outputs.work }}"),
                       lambda v:v['jobs']['firewall']['steps'][0].update(env={'ARRAY':['unsupported']}),
                       lambda v:v['jobs']['firewall']['steps'].append({'id':'inputs','run':'true'})):
            changed=copy.deepcopy(value);mutate(changed)
            with self.subTest(mutation=repr(mutate)),self.assertRaises(ValueError):p.pbs_steps(changed,selected)

    def test_pbs_rejects_job_id_collision_without_overwriting(self):
        self.write_pbs(); original = workflows.models
        def collision(*args, **kwargs):
            value = original(*args, **kwargs); value['deploy.yml']['jobs']['_pbs'] = {'name': 'Foreign guest'}; return value
        with patch.object(workflows, 'models', side_effect=collision), self.assertRaisesRegex(ValueError, 'public guest jobs'):
            p.model(self.stack, self.site)

    def test_pbs_step_named_inputs_is_not_a_reusable_workflow_input(self):
        value = pbs_document(['self-hosted', 'linux'])
        value['jobs']['firewall']['steps'].append({'id': 'inputs', 'run': 'echo synthetic'})
        value['jobs']['firewall']['steps'].append({'run': 'echo "${{ steps.inputs.outputs.work }}"'})
        self.write_pbs(value)
        self.assertIn('_backup', p.model(self.stack, self.site)['jobs'])

    def test_pbs_present_unsupported_workflow_refuses_before_recipe_generation(self):
        original = pbs_document(['self-hosted', 'linux']); variants = [[], {}, {'on': {}}]
        for key, value in [('env', {}), ('concurrency', {'group': 'homelab-private-deployment'}), ('permissions', {'contents': 'write'})]:
            row = copy.deepcopy(original); row[key] = value; variants.append(row)
        for events in [{}, {'push': {'branches': ['main']}},
                       {**original['on'], 'push': {}}, {**original['on'], 'workflow_dispatch': {}},
                       {**original['on'], 'workflow_call': {'secrets': {p.PBS_SECRET: {'required': False}}}},
                       {**original['on'], 'workflow_call': {'secrets': {p.PBS_SECRET: {'required': True}, 'FOREIGN': {'required': True}}}},
                       {**original['on'], 'workflow_call': {'inputs': {}, 'secrets': {p.PBS_SECRET: {'required': True}}}}]:
            row = copy.deepcopy(original); row['on'] = events; variants.append(row)
        row = copy.deepcopy(original); row['on']['pull_request']['paths'].append('site.yaml'); variants.append(row)
        for jobs in [{}, {'validate': None, 'firewall': {}}, {**original['jobs'], 'other': {}}]:
            row = copy.deepcopy(original); row['jobs'] = jobs; variants.append(row)
        for job, key, value in [('validate', 'runs-on', ['self-hosted']), ('validate', 'environment', 'homelab-bootstrap'),
                ('validate', 'outputs', {}), ('validate', 'steps', None),
                ('validate', 'steps', [{'run': '${{ secrets.PBS_FIREWALL_SSH_KEY }}'}]),
                ('validate', 'steps', [{'run': "${{ secrets['FOREIGN'] }}"}]),
                ('validate', 'steps', [{'run': '${{ secrets \n .PBS_FIREWALL_SSH_KEY }}'}]),
                ('validate', 'steps', [{'run': "${{ secrets \n ['PBS_FIREWALL_SSH_KEY'] }}"}]),
                ('firewall', 'environment', '${{ inputs.environment }}'), ('firewall', 'needs', []),
                ('firewall', 'if', 'always()'), ('firewall', 'timeout-minutes', 30),
                ('firewall', 'runs-on', 'ubuntu-24.04'), ('firewall', 'runs-on', [{}]),
                ('firewall', 'runs-on', ['self-hosted']), ('firewall', 'steps', None),
                ('firewall', 'steps', [{'run': "${{ inputs['extra'] }}"}]),
                ('firewall', 'concurrency', {'group': 'homelab-private-deployment'})]:
            row = copy.deepcopy(original); row['jobs'][job][key] = value; variants.append(row)
        for value in variants:
            self.write_pbs(value)
            with self.subTest(value=value), patch.object(workflows, 'models') as generate:
                with self.assertRaises(ValueError): p.model(self.stack, self.site)
                generate.assert_not_called()

    def test_pbs_whole_context_values_refuse_without_confusing_step_ids(self):
        """Whole contexts and case/whitespace variants cannot bypass PBS admission."""
        for context, job in [('secrets', 'validate'), ('inputs', 'firewall')]:
            for name in (context, context.upper(), context.title(),
                         ''.join(c.upper() if i % 2 == 0 else c for i, c in enumerate(context))):
                expressions = ['${{ toJSON(' + name + ') }}', '${{ ' + name + ' }}',
                        '${{\n' + name + ' }}', '${{\t' + name + ' }}',
                        '${{ ' + name + '\n .value }}', '${{ ' + name + "\t ['value'] }}"]
                for space in ('\t', '\n', '\r', '\v', '\f', '\u0085', '\u00a0', '\u1680',
                              '\u2000', '\u2003', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000'):
                    expressions.extend(('${{' + space + name + ' }}', '${{ ' + name + space + '}}'))
                for expression in expressions:
                    value = pbs_document(['self-hosted', 'linux'])
                    value['jobs'][job]['steps'].append({'env': {'ALL': expression}, 'run': 'true'})
                    self.write_pbs(value)
                    with self.subTest(expression=expression, job=job), \
                            patch.object(workflows, 'models') as generate:
                        with self.assertRaisesRegex(ValueError,
                                'without protected credentials' if job == 'validate' else 'unbound inputs'):
                            p.model(self.stack, self.site)
                        generate.assert_not_called()
        value = pbs_document(['self-hosted', 'linux'])
        value['jobs']['firewall']['steps'].append({'id': 'inputs', 'run': 'echo synthetic'})
        value['jobs']['firewall']['steps'].append({'run': 'echo "${{ steps.inputs.outputs.work }}"'})
        self.write_pbs(value)
        self.assertIn('_backup', p.model(self.stack, self.site)['jobs'])

    def test_pbs_unsafe_file_or_parent_is_not_treated_as_absence(self):
        path = self.site / p.PBS_WORKFLOW
        path.symlink_to(self.site / 'missing')
        with self.assertRaises(ValueError): p.pbs_workflow(self.site, ['self-hosted', 'linux'])
        path.unlink(); path.mkdir()
        with self.assertRaises(ValueError): p.pbs_workflow(self.site, ['self-hosted', 'linux'])
        path.rmdir()
        directory = path.parent; moved = directory.with_name('moved'); directory.rename(moved); directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError): p.pbs_workflow(self.site, ['self-hosted', 'linux'])

    def test_native_jobs_use_only_guest_names_and_preserve_operations(self):
        value=p.model(self.stack,self.site);public=workflows.models(self.stack, site_source=self.site / 'site.json')
        self.assertEqual(set(value['jobs']),{'validate','selection','database','web'})
        self.assertEqual(value['concurrency'],{'group':'homelab-private-deployment','cancel-in-progress':False,'queue':'max'})
        for guest,title in [('database','Database'),('web','Web')]:
            job=value['jobs'][guest];old=public['guest-'+guest+'.yml']['jobs']['deploy']
            self.assertEqual(job['name'],title)
            self.assertEqual(job['environment'],'private-apps-'+guest)
            self.assertEqual(job['runs-on'],['self-hosted','linux'])
            self.assertEqual(job['needs'],['validate',*public['deploy.yml']['jobs'][guest]['needs']])
            self.assertEqual(job['timeout-minutes'],old['timeout-minutes'])
            for actual,expected in zip(job['steps'],old['steps'],strict=True):
                self.assertEqual(actual,p.bind(expected,'[]'))
            self.assertIn("github.repository == 'owner/site'",job['if'])
            self.assertNotIn('inputs.',json.dumps(job))
        self.assertNotIn('needs',value['jobs']['selection'])

    def test_authored_guest_labels_change_only_presentation_not_packets_or_job_ownership(self):
        import component_packet
        self.spec['app_profiles']['resolver']['health'] = {'ready':{'type':'adapter','check':'readiness'}}
        (self.stack/'stack.json').write_text(json.dumps(self.spec))
        self.freeze_stack()
        before = p.model(self.stack,self.site)
        packets = component_packet.lower_plan(p.compiler.resolve_plan(self.stack,self.site/'site.json'))
        titles = {'database':'Storage guest','web':'Browser guest'}
        for guest,title in titles.items():
            self.source['guests'][guest]['display_name'] = title
        (self.site/'site.json').write_text(json.dumps(self.source))
        after = p.model(self.stack,self.site)
        self.assertEqual(component_packet.lower_plan(p.compiler.resolve_plan(self.stack,self.site/'site.json')),packets)
        for guest,title in titles.items():
            old = copy.deepcopy(before['jobs'][guest]);new = copy.deepcopy(after['jobs'][guest])
            self.assertEqual(new.pop('name'),title);old.pop('name')
            self.assertEqual(new,old)

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
            self.assertEqual(job['name'], 'Validate config')
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
                         {**source, 'name': 'Validate config'})

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
