"""Read-only caller evidence plus real ordinary phase/receipt integration."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[3]/'blueprints')]
import component_routed as m
import component_plan
import component_packet
import deploy
from private_io import encoded,read_json,write_bytes,write_new
from test_routed_checks import row
import test_component_deployment as fixture


class RouteCallerTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.work=self.root/'guest';self.work.mkdir(mode=0o700)
        self.operation=self.work/'ordinary-101-1';self.operation.mkdir(mode=0o700)
        self.cfg={'guest':{'interfaces':[{'ipv4':'198.18.20.10/24'}]},
            'app':{'route_checks':{'mode':'inline','rows':[row()]},'hostname':'example','address':'198.18.20.10'},
            'paths':{'private_key':'/never-read/deploy.key'}}
        p=patch.object(m.component_inputs,'binding',return_value={'fixed':True});self.binding=p.start();self.addCleanup(p.stop)
        for method in ('dhcp_admission','guest_trust'):
            p=patch.object(m.proxmox_guest,method);p.start();self.addCleanup(p.stop)
    def quiet(self,argv,env,log):
        self.assertNotIn('HOMELAB_APP_SECRET_TEST',env);self.assertNotIn('PBS_API_TOKEN',env)
        write_new(log,b'example : ok=1 changed=0 failed=0\n')
    def run_check(self):return m.run(self.cfg,self.root/'site.json',self.work,self.operation,{'fixed':True})
    def test_inline_uses_pinned_code_exact_transport_read_only_tasks_and_private_receipt(self):
        with patch.object(m,'quiet',side_effect=self.quiet)as quiet,patch('ansible_guest.ansible_environment',side_effect=lambda cfg,env:env),\
             patch.dict(os.environ,{'HOMELAB_APP_SECRET_TEST':'not-forwarded','PBS_API_TOKEN':'not-forwarded'}):
            self.assertEqual(self.run_check()['routed_endpoints'],1)
        directory=self.operation/'http-checks';variables=read_json(directory/'variables.json',private=True)
        self.assertEqual(variables['route_check_argv'][-1],json.dumps([row()]))
        compile(variables['route_check_argv'][2],'<pinned-check>','exec')
        self.assertIn((m.SOURCE/'dns_records.py').read_text().__repr__(),variables['route_check_argv'][2])
        self.assertNotIn('--resolve',variables['route_check_argv'][2])
        self.assertTrue(any(value.endswith('component-route-checks.yml')for value in quiet.call_args.args[0]))
        import yaml
        tasks=yaml.safe_load((m.SOURCE/'ansible/component-route-checks.yml').read_text())[0]['tasks']
        self.assertEqual(tasks[-1]['changed_when'],False)
        self.assertEqual(set(tasks[-1]),{'name','ansible.builtin.command','changed_when'})
        self.assertEqual(read_json(directory/'complete.json',private=True)['binding'],{'fixed':True})
        with self.assertRaises(FileExistsError):self.run_check()
    def test_deferred_has_separate_evidence_no_guest_transport_or_ordinary_updates(self):
        self.cfg['app']['route_checks']['mode']='deferred'
        prior=self.operation/'complete.json';write_new(prior,b'genuine prior evidence bytes\n');before=(prior.stat().st_ino,prior.read_bytes())
        with patch.object(m,'quiet',side_effect=self.quiet)as quiet:self.run_check()
        self.assertEqual((prior.stat().st_ino,prior.read_bytes()),before)
        command=quiet.call_args.args[0]
        self.assertEqual(command[1],str(m.SOURCE/'routed_checks.py'))
        self.assertTrue((self.work/'http-checks-101-1/complete.json').is_file())
        m.proxmox_guest.guest_trust.assert_not_called()
    def test_shared_pool_retains_private_evidence_binding_and_failure(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaisesRegex(ValueError,'only on the controller'):
                m.run(self.cfg,self.root/'site.json',self.work,self.operation,{'fixed':True},executor=pool)
            self.cfg['app']['route_checks']['mode']='deferred'
            with patch.object(m.routed_checks,'probe',return_value={'status':'passed','attempts':1}),patch.object(m,'quiet') as quiet:
                value=m.run(self.cfg,self.root/'site.json',self.work,self.operation,{'fixed':True},executor=pool)
            self.assertEqual(value['endpoints'][0]['status'],'passed');quiet.assert_not_called()
            self.assertTrue((self.work/'http-checks-101-1/complete.json').is_file())
            for suffix,result in [('failed',{'status':'failed','attempts':1,'cause':'timeout'}),
                                  ('changed',{'status':'passed','attempts':1})]:
                operation=self.work/('ordinary-'+suffix);operation.mkdir(mode=0o700)
                self.binding.side_effect=[{'fixed':True},{'changed':True}] if suffix=='changed' else None
                with patch.object(m.routed_checks,'probe',return_value=result),self.assertRaises(ValueError):
                    m.run(self.cfg,self.root/'site.json',self.work,operation,{'fixed':True},executor=pool)
                self.assertFalse((self.work/('http-checks-'+suffix)/'complete.json').exists())

    def test_changed_inputs_invalid_mode_source_or_reported_mutation_refuse(self):
        for mutate in (lambda c:c['app']['route_checks'].update(extra=True),lambda c:c['app']['route_checks'].update(mode='guess'),
                       lambda c:c['app']['route_checks']['rows'][0].update(source_address='198.18.20.99'),
                       lambda c:c['app']['route_checks']['rows'][0].update(resolver_source='198.18.20.99')):
            selected=copy.deepcopy(self.cfg);mutate(selected)
            with self.assertRaises(ValueError):m.configuration(selected)
        selected=copy.deepcopy(self.cfg);selected['app']['route_checks']['mode']='deferred'
        selected['app']['route_checks']['rows'][0]['resolver_source']='198.18.20.99'
        with self.assertRaises(ValueError):m.configuration(selected)
        self.binding.return_value={'changed':True}
        with self.assertRaisesRegex(ValueError,'before checks'):self.run_check()
        self.binding.side_effect=[{'fixed':True},{'changed':True}]
        with patch.object(m,'quiet',side_effect=self.quiet),patch('ansible_guest.ansible_environment',side_effect=lambda cfg,env:env),\
             self.assertRaisesRegex(ValueError,'during checks'):self.run_check()
        self.assertFalse((self.operation/'http-checks/complete.json').exists())
    def test_nonzero_ansible_changes_or_missing_recap_never_create_completion(self):
        for logbytes in (b'host : ok=1 changed=1 failed=0',b'no recap'):
            directory=self.work/('ordinary-'+str(len(logbytes))+'-1');directory.mkdir(mode=0o700)
            with patch.object(m,'quiet',side_effect=lambda argv,env,log:write_new(log,logbytes)),\
                 patch('ansible_guest.ansible_environment',side_effect=lambda cfg,env:env),self.assertRaisesRegex(ValueError,'read-only'):
                m.run(self.cfg,self.root/'site.json',self.work,directory,{'fixed':True})
            self.assertFalse((directory/'http-checks/complete.json').exists())


class RouteOrdinaryIntegrationTests(unittest.TestCase):
    def fixture(self,mode):
        case=fixture.DeploymentIntegrationTests();case.setUp();self.addCleanup(case.doCleanups)
        resolved=copy.deepcopy(case.plan.resolved)
        resolved['routed_checks']={'resolver':{'mode':mode,'rows':[row()]}}
        plan=component_plan.Plan(case.plan.library,case.plan.site,resolved,case.plan.pins)
        packet=component_packet.lower_plan(plan,inputs=case.inputs)['resolver']
        write_bytes(case.packet,encoded(packet));case.cfg=json.loads(packet['files']['site.json'])
        return case
    def test_inline_completion_waits_for_routes_and_failed_routes_preserve_hold(self):
        case=self.fixture('inline');work=case.state/'610'
        def failed(*args):
            self.assertTrue((work/'ORDINARY-HOLD.json').exists())
            self.assertFalse((work/'ordinary-complete.json').exists())
            raise ValueError('read-only check failure')
        with patch.object(m,'run',side_effect=failed),self.assertRaisesRegex(ValueError,'check failure'):case.all_phases()
        self.assertTrue((work/'ORDINARY-HOLD.json').is_file())
        self.assertFalse((work/'ordinary-complete.json').exists())
    def test_deferred_requires_this_exact_genuine_success_and_never_advances_canonical(self):
        case=self.fixture('deferred');case.all_phases();work=case.state/'610';canonical=work/'ordinary-complete.json'
        before=(canonical.stat().st_ino,canonical.read_bytes())
        with patch.object(m,'quiet',side_effect=lambda argv,env,log:write_new(log,b'{"status":"passed"}\n')):
            result=deploy.run('http-checks',case.packet,inputs=case.inputs,environment={})
        self.assertEqual(result['routed_endpoints'],1)
        self.assertEqual((canonical.stat().st_ino,canonical.read_bytes()),before)
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}),patch.object(m,'run')as run,\
             self.assertRaisesRegex(ValueError,'exact run and binding'):deploy.run('http-checks',case.packet,inputs=case.inputs,environment={})
        run.assert_not_called()
    def test_parallel_executor_requires_ordinary_completion_and_cannot_enter_other_phases(self):
        case=self.fixture('deferred')
        with ThreadPoolExecutor(max_workers=1) as pool:
            with patch.object(m,'run') as check,self.assertRaises(ValueError):
                deploy.run('http-checks',case.packet,inputs=case.inputs,environment={},route_executor=pool)
            check.assert_not_called()
            with self.assertRaisesRegex(ValueError,'cannot change deployment phases'):
                deploy.run('infrastructure',case.packet,inputs=case.inputs,environment={},route_executor=pool)
            case.all_phases()
            with patch.object(m,'run',return_value={'status':'passed'}) as check:
                self.assertEqual(deploy.run('http-checks',case.packet,inputs=case.inputs,environment={},route_executor=pool)['status'],'passed')
            self.assertIs(check.call_args.kwargs['executor'],pool)

    def test_inline_success_and_unselected_deferred_phase(self):
        case=self.fixture('inline')
        with patch.object(m,'run',wraps=m.run)as check,\
             patch.object(m,'quiet',side_effect=lambda argv,env,log:write_new(log,b'example : ok=1 changed=0 failed=0\n')),\
             patch('ansible_guest.ansible_environment',side_effect=lambda cfg,env:env):
            case.all_phases();case.all_phases()
            check.assert_called_once()
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):case.all_phases()
            self.assertEqual(check.call_count,2)
        self.assertTrue((case.state/'610/ordinary-complete.json').exists())
        with self.assertRaisesRegex(ValueError,'Select this component guest phase'):deploy.run('http-checks',case.packet,inputs=case.inputs,environment={})
