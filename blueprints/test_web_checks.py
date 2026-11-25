"""Final job orchestration with real pools and synthetic ordinary admission only."""
import copy
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import web_checks as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications/tests'))
from test_routed_checks import row


class WebChecksTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.env={'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','RUNNER_TEMP':self.temp.name}
        first=row();alias=copy.deepcopy(first);alias.update(host='alias.example.invalid',route_origins=['https://alias.example.invalid'])
        self.rows={'a':[first,alias],'b':[copy.deepcopy(first)]}
        self.plan=SimpleNamespace(resolved={'guests':dict.fromkeys(['a','b','dns','ingress']),
            'routed_checks':{key:{'rows':value} for key,value in self.rows.items()}})
        self.graph={'checks':{'owners':{key:{'name':'Check '+key,'needs':[key,'dns','ingress']} for key in self.rows},
            'endpoint_count':3}}
        self.results={key:'success' for key in ['a','b','dns','ingress','selection','validate','_backup']}
        self.graph['backup']={}
        self.execute_calls=[]

    def execute(self,phase,packet,*,route_executor,blocked_routes=None):
        self.assertEqual(phase,'http-checks')
        owner=json.loads(packet.read_text())['owner'];self.execute_calls.append(owner)
        result=m.routed_checks.parallel(self.rows[owner],route_executor,blocked=blocked_routes)
        if result['status']=='failed':raise m.routed_checks.VerificationFailure(result)
        return result

    def run_checks(self,**kwargs):
        with patch.object(m,'bootstrap_closed') as guard,patch.object(m.compiler,'resolve_plan',return_value=self.plan),\
             patch.object(m.compiler,'site_path',return_value='site'),patch.object(m.compiler,'parse_disabled',return_value=[]),\
             patch.object(m.component_workflows,'model',return_value=self.graph),\
             patch.object(m.compiler,'lower_plan',return_value={key:{'owner':key} for key in self.rows}):
            result=m.run(Path('stack'),Path('site'),'[]',json.dumps(self.results),environment=self.env,
                         execute=kwargs.pop('execute',self.execute),**kwargs)
            guard.assert_called_once()
            return result

    def test_failed_identity_still_probes_ordinary_page_in_same_guest(self):
        self.plan.resolved['guests']['identity'] = {}
        self.results['identity'] = 'failure'
        common = ['a', 'dns', 'ingress']
        self.graph['checks']['owners']['a'].update(needs=[*common, 'identity'],
                                                  row_needs=[common, [*common, 'identity']])
        with patch.object(m.routed_checks,'probe',return_value={'status':'passed','attempts':1}) as probe:
            result = self.run_checks()
        self.assertEqual(result['counts'], {'passed':2, 'failed':0, 'blocked':1})
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(result['endpoints'][0]['status'], 'passed')
        self.assertEqual(result['endpoints'][1]['prerequisites'], {'identity':'failure'})

    def test_real_owner_and_endpoint_pools_overlap_and_keep_aliases_on_failure(self):
        barrier=threading.Barrier(3)
        def probe(row,deadline):
            barrier.wait(timeout=3)
            return {'status':'failed','attempts':1,'cause':'timeout','stage':'connect'} if row['host'].startswith('alias') else {'status':'passed','attempts':1}
        with patch.object(m.routed_checks,'probe',side_effect=probe):value=self.run_checks()
        self.assertEqual(value['status'],'failed');self.assertEqual(value['counts'],{'passed':2,'failed':1,'blocked':0})
        self.assertEqual([r['host'] for r in value['endpoints']],[r['host'] for rows in self.rows.values() for r in rows])
        self.assertCountEqual(self.execute_calls,['a','b'])

    def test_failed_unrelated_guest_does_not_block_successful_eligible_owner(self):
        self.results['b']='failure'
        with patch.object(m.routed_checks,'probe',return_value={'status':'passed','attempts':1}):value=self.run_checks()
        self.assertEqual(self.execute_calls,['a']);self.assertEqual(value['counts'],{'passed':2,'failed':0,'blocked':1})
        self.assertEqual(value['endpoints'][-1]['prerequisites'],{'b':'failure'})
        self.results['b']='success';self.results.pop('dns')
        self.assertEqual(self.run_checks()['counts']['blocked'],3)
        self.results['dns']='success';self.results['validate']='skipped'
        self.assertEqual(self.run_checks()['counts']['blocked'],3)

    def test_admission_refusal_invalid_or_missing_results_and_unexpected_future_fail_closed(self):
        for result in (None,{}, {'endpoints':[]},{'endpoints':[{'endpoint':0,'exposure':'web','status':'passed'}]*2}):
            with self.subTest(result=result):
                value=self.run_checks(execute=lambda *a,**k:result)
                self.assertEqual(value['counts']['blocked'],3)
        with patch.object(m.deploy,'failure_diagnostic',side_effect=OSError):
            value=self.run_checks(execute=lambda *a,**k:(_ for _ in ()).throw(ValueError('PRIVATE')))
        self.assertEqual(value['counts']['blocked'],3);self.assertNotIn('PRIVATE',json.dumps(value))
        original=m.check_owner
        def broken(owner,*args):
            if owner=='a':raise RuntimeError('PRIVATE')
            return original(owner,*args)
        with patch.object(m,'check_owner',side_effect=broken),patch.object(m.routed_checks,'probe',return_value={'status':'passed','attempts':1}):
            value=self.run_checks()
        self.assertEqual(value['counts'],{'passed':1,'failed':0,'blocked':2})

    def test_empty_selection_input_validation_and_no_credentials(self):
        self.graph={}
        value=self.run_checks();self.assertEqual(value['status'],'not_selected')
        for raw in ('null','[]','{"unknown":"success"}','{"a":"complete"}',1,'x'*65537):
            with self.subTest(raw=str(raw)[:30]),self.assertRaises(ValueError):m.job_results(raw,self.plan.resolved['guests'])
        for key,value in [('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/heads/branch'),
            ('HOMELAB_APP_SECRET_VALUE','PRIVATE'),('PBS_API_TOKEN','PRIVATE'),('APPLICATION_SSH_KEY','PRIVATE'),
            ('PROXMOX_APP_TOKEN','PRIVATE'),('PROXMOX_NFS_SSH_KEY','PRIVATE')]:
            with patch.dict(self.env,{key:value}),self.assertRaises(ValueError):self.run_checks()
        self.graph={'checks':{'owners':{},'endpoint_count':1}}
        with self.assertRaises(ValueError):self.run_checks()

    def test_main_closed_json_escaped_summary_and_failure_exit(self):
        value={'status':'failed','endpoints':[{'status':'blocked','guest':'a|<script>',
            'host':'web.example.invalid','port':443,'path':'/','cause':'owner_check_failed'}]}
        path=Path(self.temp.name)/'summary'
        argv=['web','--stack','stack','--site-root','site','--results','{}']
        with patch.object(sys,'argv',argv),patch.dict(os.environ,{'GITHUB_STEP_SUMMARY':str(path)}),\
             patch.object(m,'run',return_value=value),patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertEqual(m.main(),1)
        self.assertIn('a&#124;&lt;script&gt;',path.read_text());self.assertNotIn('<script>',path.read_text())
        self.assertEqual(len(output.getvalue().splitlines()),2)
        for status,expected in [('passed',0),('not_selected',0)]:
            with patch.object(sys,'argv',argv),patch.object(m,'run',return_value={'status':status,'endpoints':[]}),\
                 patch.dict(os.environ,{},clear=True),patch('sys.stdout',new_callable=io.StringIO):
                self.assertEqual(m.main(),expected)
        with patch.object(sys,'argv',argv),patch.object(m,'run',side_effect=ValueError('PRIVATE')),\
             patch('sys.stdout',new_callable=io.StringIO) as output:self.assertEqual(m.main(),1)
        self.assertNotIn('PRIVATE',output.getvalue())
        with patch.object(sys,'argv',argv),patch.object(m.compiler,'site_path',side_effect=ValueError),\
             patch('sys.stdout',new_callable=io.StringIO),self.assertRaises(SystemExit) as stopped:
            runpy.run_path(str(Path(m.__file__)),run_name='__main__')
        self.assertEqual(stopped.exception.code,1)


if __name__=='__main__':unittest.main()
