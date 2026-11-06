"""Workflow-owned units use conforming Plan/secret-component fakes.

Two focused integrations use the actual source resolver; no target or generated
credential is touched. This suite does not stand in for recipe/action/CD tests.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

F=Path(Path(__file__).resolve().parents[1]).resolve()
sys.path.insert(0,str(F/'blueprints'))
import component_workflows as m


class PlanFake:
    def __init__(self,resolved):
        self.resolved=copy.deepcopy(resolved);self.site={'secret_sources':{}}
        self.snapshot=copy.deepcopy(self.resolved);self.calls=0
    def check(self):
        self.calls+=1
        if self.resolved!=self.snapshot:raise ValueError('sealed Plan changed')


def fake():
    return PlanFake({'guests':{'db-east':{'display_name':'Database'},'room_a':{'display_name':'Room'},'independent':{'display_name':'Independent'}},
        'apps':{'consumer':{'guest':'room_a','adapter':'pihole','identity':{'phase':'dns-client'},'display_name':'Pi-hole'},
                'unrelated':{'guest':'room_a','adapter':'unbound','identity':{'phase':'dns-other'},'display_name':'Other resolver'},
                'producer':{'guest':'room_a','adapter':'unbound','identity':{'phase':'dns-server'},'display_name':'Unbound'}},
        'app_dependencies':{'consumer':['producer'],'unrelated':[],'producer':[]},
        'guest_dependencies':{'db-east':[],'room_a':['db-east'],'independent':[]},
        'enabled':['db-east','room_a','independent']})


def reusable(raw=None,extra=''):
    return 'name: Deploy\njobs:\n  stack:\n    uses: example/stack/.github/workflows/deploy.yml@'+'a'*40+'\n    with:\n'+('      runner_labels: \'["self-hosted"]\'\n' if raw is None else '      disabled: '+raw+'\n')+extra


def flat(raw=None,extra=''):
    return 'name: Deploy\nenv:\n  HOMELAB_STACK_SOURCE: example/stack/.github/workflows/deploy.yml@'+'a'*40+'\n'+('' if raw is None else '  HOMELAB_DISABLED: '+raw+'\n')+extra+'jobs:\n  selection:\n    runs-on: ubuntu-24.04\n'


class GraphTests(unittest.TestCase):
    def test_plain_guest_and_app_labels_cannot_become_actions_expressions(self):
        for group, key in (('guests', 'room_a'), ('apps', 'consumer')):
            for value in ('${{ github.run_id }}', 'text ${{ secrets.EXAMPLE }}', 'x\x01y', 'x\x7fy'):
                plan = fake()
                plan.resolved[group][key]['display_name'] = value
                plan.snapshot = copy.deepcopy(plan.resolved)
                with self.subTest(group=group, value=value), mock.patch.object(m.component_secrets,
                        'action_inputs', return_value={}), self.assertRaisesRegex(ValueError, 'workflow-label'):
                    m.model(plan)
        self.assertEqual(m.label('Pi-hole (guest 1)'), 'Pi-hole (guest 1)')

    def test_actual_guest_map_and_source_stable_ready_application_order_no_global_barrier(self):
        plan=fake()
        with mock.patch.object(m.component_secrets,'action_inputs',return_value={}) as inputs:
            value=m.model(plan)
        self.assertEqual(value['guest_order'],['db-east','room_a','independent'])
        self.assertEqual(value['guests']['room_a']['name'],'Room')
        self.assertEqual(value['guests']['room_a']['needs'],['selection','db-east'])
        self.assertEqual(value['guests']['independent']['needs'],['selection'])
        self.assertEqual([row['id'] for row in value['guests']['room_a']['phases']],
                         ['infrastructure','preparation','dns-other','dns-server','dns-client'])
        self.assertEqual([call.args[1] for call in inputs.call_args_list],['unrelated','producer','consumer'])
        self.assertEqual(plan.calls,2);self.assertEqual(plan.resolved,plan.snapshot)

    def test_disabled_empty_leaf_all_and_required_dependencies(self):
        guests=['db-east','room_a','independent'];deps=fake().resolved['guest_dependencies']
        for disabled,expected in [([],guests),(['independent'],['db-east','room_a']),(guests,[])]:
            self.assertEqual(m.selection(guests,deps,disabled),expected)
        for disabled in (['db-east'],['unknown'],['room_a','room_a'],[1],None):
            with self.subTest(disabled=disabled),self.assertRaises(ValueError):m.selection(guests,deps,disabled)
        plan=fake();plan.resolved['enabled']=['db-east','room_a'];plan.snapshot=copy.deepcopy(plan.resolved)
        with mock.patch.object(m.component_secrets,'action_inputs',return_value={}):
            self.assertEqual(set(m.model(plan)['guests']),{'db-east','room_a'})

    def test_monitored_agents_stay_inside_guest_jobs_and_server_cannot_be_disabled(self):
        plan=fake();plan.resolved['monitoring']={'guest':'db-east'};plan.snapshot=copy.deepcopy(plan.resolved)
        with mock.patch.object(m.component_secrets,'action_inputs',return_value={}):value=m.model(plan)
        self.assertEqual(len(value['guests']),3)
        for guest in value['guests'].values():
            self.assertEqual(guest['phases'][-1],{'id':'zabbix-agent','name':'Zabbix agent','application':None,'inputs':{}})
        self.assertEqual(value['guests']['independent']['needs'],['selection'])
        with self.assertRaises(ValueError):m.selection(['db-east','other'],{'db-east':[],'other':[]},['db-east'],monitoring_guest='db-east')
        self.assertEqual(m.selection(['db-east','other'],{'db-east':[],'other':[]},['db-east','other'],monitoring_guest='db-east'),[])

    def test_scalar_slots_are_phase_scoped_and_guest_only_declares_selected_secret_names(self):
        plan=fake()
        for app in plan.resolved['apps'].values():app['adapter']='node_red'
        plan.snapshot=copy.deepcopy(plan.resolved)
        def inputs(resolver,key):
            self.assertEqual(resolver.apps,plan.resolved['apps'])
            return {'node_red_api_token':{'environment':'API_'+key.upper(),'workflow_secret':'SECRET_'+key.upper()}}
        with mock.patch.object(m.component_secrets,'action_inputs',side_effect=inputs):value=m.model(plan)
        phases=value['guests']['room_a']['phases']
        self.assertEqual(phases[0]['inputs'],{});self.assertEqual(phases[1]['inputs'],{})
        for phase in phases[2:]:
            self.assertEqual(list(phase['inputs']),['node_red_api_token'])
            self.assertEqual(phase['inputs']['node_red_api_token']['workflow_secret'],'SECRET_'+phase['application'].upper())
        self.assertEqual(value['guests']['room_a']['workflow_secrets'],['SECRET_UNRELATED','SECRET_PRODUCER','SECRET_CONSUMER'])
        self.assertEqual(value['guests']['db-east']['workflow_secrets'],[])
        with mock.patch.object(m.component_secrets,'action_inputs',return_value={'node_red_api_token': {'environment':'API_SHARED','workflow_secret':'ONE_DECLARED_SECRET'}}):
            repeated=m.model(plan)
        self.assertEqual(repeated['guests']['room_a']['workflow_secrets'],['ONE_DECLARED_SECRET'])
        for wrong in ({'arbitrary_json':{'environment':'ENV','workflow_secret':'SECRET'}},
                      {'node_red_api_token':{'environment':'ENV','workflow_secret':'SECRET','value':'forbidden'}},
                      {'node_red_api_token':{'environment':'unsafe-name','workflow_secret':'SECRET'}}):
            with mock.patch.object(m.component_secrets,'action_inputs',return_value=wrong),self.assertRaises(ValueError):m.model(plan)

    def test_reserved_colliding_cyclic_or_unsealed_workflow_inputs_refuse(self):
        cases=[lambda p:p.resolved['apps']['producer']['identity'].update(phase='infrastructure'),
               lambda p:p.resolved['apps']['producer']['identity'].update(phase='dns-client'),
               lambda p:p.resolved['app_dependencies']['producer'].append('consumer'),
               lambda p:p.resolved['app_dependencies']['producer'].append('missing')]
        for change in cases:
            plan=fake();change(plan);plan.snapshot=copy.deepcopy(plan.resolved)
            with self.subTest(change=change),mock.patch.object(m.component_secrets,'action_inputs',return_value={}),self.assertRaises(ValueError):m.model(plan)
        for guests,deps in [(['selection'],{'selection':[]}),([[]],{}),(['a'],{'a':[['bad']]}),(['a'],{'a':['a']})]:
            with self.subTest(guests=guests),self.assertRaises(ValueError):m.selection(guests,deps,[])
        plan=fake();plan.resolved['apps']['consumer']['display_name']='changed outside seal'
        with self.assertRaises(ValueError):m.model(plan)


class WorkflowLiteralTests(unittest.TestCase):
    def test_both_existing_shapes_preserve_omission_blank_and_single_quoted_json(self):
        for form in (flat,reusable):
            for raw,expected in [(None,[]),("''",[]),("'[]'",[]),("'[\"leaf_a\"]'",['leaf_a'])]:
                with self.subTest(form=form.__name__,raw=raw):self.assertEqual(m.workflow_disabled(form(raw)),expected)
        # This extractor can read an env block before full workflow validation.
        self.assertEqual(m.workflow_disabled(flat("'[]'").split('jobs:')[0]),[])
        # A native guest may be named stack; only a second reusable with block is ambiguous.
        self.assertEqual(m.workflow_disabled(flat("'[]'").replace('  selection:','  stack:')),[])

    def test_style_expression_json_type_duplicates_unknown_input_and_mapping_refusals(self):
        wrong=['[]','"[]"',"'null'","'{}'","'[1]'","'[[]]'","'[\"leaf\",\"leaf\"]'","'not-json'","'${{ inputs.disabled }}'",'!!str \'[]\'','&disabled \'[]\'','*missing']
        for form in (flat,reusable):
            for raw in wrong:
                with self.subTest(form=form.__name__,raw=raw),self.assertRaises(ValueError):m.workflow_disabled(form(raw))
        duplicate=[flat("'[]'", "  HOMELAB_DISABLED: '[]'\n"),
                   reusable("'[]'", "      disabled: '[]'\n"),
                   flat("'[]'").replace('env:\n','env:\nenv:\n'),
                   reusable("'[]'").replace('  stack:\n','  stack: {}\n  stack:\n')]
        for text in duplicate:
            with self.subTest(kind='duplicate'),self.assertRaisesRegex(ValueError,'unique declared'):m.workflow_disabled(text)
        for text in [flat("'[]'","  enabled: '[]'\n"),reusable("'[]'","      enabled: '[]'\n"),
                     '', 'jobs: []\n','jobs: {other: {}}\n',reusable("'[]'").replace('with:\n','with: []\n'),
                     flat("'[]'")+ '---\nname: Other\n',
                     flat("'[]'").replace('env:\n','env: &cfg\n')]:
            with self.subTest(kind='shape'),self.assertRaises(ValueError):m.workflow_disabled(text)
        with self.assertRaises(ValueError):m.workflow_disabled(flat("'[]'").replace('  selection:\n','  stack:\n    with: {disabled: \'[]\'}\n'))

    def test_bounded_utf8_and_raw_disabled_contract(self):
        for text in (None,1,'x'*(1024*1024+1),'\ud800'):
            with self.subTest(type=type(text).__name__),self.assertRaises(ValueError):m.workflow_disabled(text)
        for raw in (None,'null','true','{}','["a","a"]','[1]','x'*(1024*1024+1),'\ud800'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):m.disabled_json(raw)
        self.assertEqual(m.disabled_json(''),[])


class RealPlanIntegrationTests(unittest.TestCase):
    def test_actual_minimal_and_duplicate_profile_plans_have_only_selected_guest_phase_jobs(self):
        import component_plan
        from test_component_plan import library, site
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();stack=root/'library';consumer=root/'consumer'
            stack.mkdir();consumer.mkdir()
            spec=library()
            spec['software']={'unbound': {'images': {'unbound': 'unbound'}}}
            spec['runtime_profiles']={'unbound': {'containers': {'unbound': {
                'memory_mib':256,'cpu_limit':1,'pids_limit':128}}}}
            spec['app_profiles']['recursive'].update(software=['unbound'],runtime=['unbound'])
            (stack/'stack.json').write_text(json.dumps(spec))
            # Source-only synthetic image; never pulled, started or qualified.
            (stack/'images.json').write_text(json.dumps({'unbound': {'repository':'example/unbound','tag':'1','digest':'sha256:'+'a'*64}}))
            selected=site();source=consumer/'site.json';source.write_text(json.dumps(selected))
            original=component_plan.resolve(stack,source);value=m.model(original)
            self.assertEqual(value['guest_order'],['resolver'])
            self.assertEqual([p['id'] for p in value['guests']['resolver']['phases']],['infrastructure','preparation','recursive_a'])
            selected['guests']['resolver']['resources']={'memory_mib':1024}
            selected['apps']['backup']=copy.deepcopy(selected['apps']['recursive_a'])
            selected['apps']['backup']['properties']={'publish_port':5336}
            source.write_text(json.dumps(selected))
            plan=component_plan.resolve(stack,source);value=m.model(plan)
            self.assertEqual(len(value['guests']),1)
            self.assertEqual([p['application'] for p in value['guests']['resolver']['phases'][2:]],['recursive_a','backup'])
            self.assertEqual(value['guests']['resolver']['workflow_secrets'],[])
            none=component_plan.resolve(stack,source,['resolver'])
            self.assertEqual(m.model(none)['guests'],{})


if __name__=='__main__':unittest.main()
