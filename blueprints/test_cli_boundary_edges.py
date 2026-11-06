"""Offline CLI/reader/boundary edges with bounded synthetic inputs and fakes."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

F=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import authored_config as authored
import compile as compiler
from component_errors import ComponentError
import component_workflows
import workflows
from component_process_fixtures import configuration
import component_sources
import component_plan
spec=importlib.util.spec_from_file_location('cli_boundary_checker',F/'tools/check_boundaries.py')
boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)


class TemporarySourceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()


class ReaderAndDiagnosticEdges(TemporarySourceTests):
    def test_required_site_absence_ambiguity_and_symlink_still_refuse_after_optional_retirement(self):
        with self.assertRaisesRegex(ValueError,authored.ERROR):authored.site_path(self.root)
        first=self.root/'site.yaml';first.write_text('literal: value\n')
        self.assertEqual(authored.site_path(self.root),first)
        second=self.root/'site.json';second.write_text('{}')
        with self.assertRaisesRegex(ValueError,authored.ERROR):authored.site_path(self.root)
        second.unlink();first.unlink();first.symlink_to(self.root/'missing.yaml')
        with self.assertRaisesRegex(ValueError,authored.ERROR):authored.site_path(self.root)

    def test_unsupported_explicit_authored_extension_refuses_without_payload_echo_or_redirect(self):
        target=self.root/'site.toml';target.write_text('PRIVATE_SENTINEL')
        with self.assertRaisesRegex(ValueError,authored.ERROR) as caught:authored.source_path(target)
        self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
        self.assertEqual(target.read_text(),'PRIVATE_SENTINEL')

    def test_invalid_error_code_and_unsafe_subject_parts_are_replaced_or_filtered(self):
        error=ComponentError('PRIVATE_SENTINEL\nraw',('apps','safe','../PRIVATE_SENTINEL',1,None))
        self.assertEqual(error.code,'component.invalid');self.assertEqual(error.path,('apps','safe'))
        self.assertEqual(str(error),'component.invalid at apps.safe')
        self.assertEqual(str(ComponentError('component.reference',('apps','safe'))),'component.reference at apps.safe')


class WorkflowCLIAndRecipeEdges(TemporarySourceTests):
    def test_main_forwards_exact_paths_disabled_and_check_arguments(self):
        stack=self.root/'stack';site=self.root/'site.yaml'
        with patch.object(sys,'argv',['tool','--stack',str(stack),'--site',str(site),'--disabled','["worker"]','--check']), \
             patch.object(workflows,'synchronize',return_value={'workflows':3,'changed':0}) as synchronize, \
             patch('sys.stdout',new_callable=io.StringIO) as output:
            workflows.main()
        synchronize.assert_called_once_with(stack,site_source=site,disabled=['worker'],check=True)
        self.assertEqual(output.getvalue(),'3 generated workflows; 0 changed.\n')

    def test_main_preserves_closed_value_and_missing_key_refusal_without_workaround(self):
        for failure in (ValueError('synthetic workflow refusal'),KeyError('synthetic missing key')):
            with self.subTest(kind=type(failure).__name__),patch.object(sys,'argv',[
                    'tool','--stack',str(self.root/'stack'),'--site',str(self.root/'site.yaml')]), \
                 patch.object(workflows,'synchronize',side_effect=failure), \
                 patch('sys.stdout',new_callable=io.StringIO) as output,self.assertRaises(SystemExit) as caught:
                workflows.main()
            self.assertEqual(str(caught.exception),str(failure));self.assertEqual(output.getvalue(),'')

    def test_actual_main_guard_checks_real_generated_files_with_only_plan_model_collaborators_fake(self):
        stack=self.root/'stack';directory=stack/'.github/workflows';directory.mkdir(parents=True)
        (directory/'phase.yml').write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@'+'a'*40+'\n')
        site=self.root/'site.yaml';site.write_text('kind: site\n')
        graph={'guest_order':[],'dependencies':{},'monitoring_guest':None,'guests':{}}
        with patch.object(compiler,'resolve_plan',return_value=object()) as resolver, \
             patch.object(component_workflows,'model',return_value=graph):
            workflows.synchronize(stack,site_source=site,check=False)
            before={path.name:path.read_bytes() for path in directory.iterdir()}
            with patch.object(sys,'argv',['tool','--stack',str(stack),'--site',str(site),'--check']), \
                 patch('sys.stdout',new_callable=io.StringIO) as output:
                runpy.run_path(str(F/'blueprints/workflows.py'),run_name='__main__')
        self.assertEqual(output.getvalue(),'2 generated workflows; 0 changed.\n')
        self.assertEqual(set(before),{'deploy.yml','phase.yml'})
        self.assertEqual({path.name:path.read_bytes() for path in directory.iterdir()},before)
        self.assertEqual(resolver.call_count,2)
        self.assertTrue(all(call.args[:2]==(stack,site) for call in resolver.call_args_list))

    def test_both_yaml_trigger_representations_are_accepted_by_the_same_strict_recipe_guard(self):
        raw=workflows.PHASE_RECIPE.read_text();boolean=workflows.yaml.safe_load(raw)
        self.assertIn(True,boolean);normalized=copy.deepcopy(boolean);normalized['on']=normalized.pop(True)
        for label,text in (('yaml-on',raw),('quoted-on',workflows.yaml.safe_dump(normalized,sort_keys=False))):
            target=self.root/(label+'.yml');target.write_text(text)
            with self.subTest(trigger=label),patch.object(workflows,'PHASE_RECIPE',target):
                job,defaults=workflows.phase_recipe(check_actions=False)
            self.assertEqual(defaults,{'run':{'shell':'bash'}})
            self.assertEqual(job['if'],workflows.PRIVATE_MAIN+" && !contains(fromJSON(inputs.disabled || '[]'), inputs.guest)")
            self.assertEqual(len(job['steps']),10)

    def test_false_check_actions_skips_only_missing_composite_files_not_recipe_policy(self):
        target=self.root/'recipe.yml';target.write_bytes(workflows.PHASE_RECIPE.read_bytes())
        with patch.object(workflows,'PHASE_RECIPE',target):
            workflows.phase_recipe(check_actions=False)
            with self.assertRaisesRegex(ValueError,'shared actions identical'):workflows.phase_recipe()
            document=workflows.yaml.safe_load(target.read_text());document['permissions']={'contents':'write'}
            target.write_text(workflows.yaml.safe_dump(document,sort_keys=False))
            with self.assertRaisesRegex(ValueError,'unsupported framework recipe policies'):workflows.phase_recipe(check_actions=False)

    def test_immutable_workflow_selection_and_revision_guard_remain_exact(self):
        selected=self.root/'phase.yml';selected.write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@'+'a'*40+'\n')
        self.assertEqual(compiler.workflow_selection(selected,'guest-phase.yml'),{'repository':'example/framework','revision':'a'*40})
        with patch.object(compiler.subprocess,'check_output',return_value='a'*40+'\n') as git:
            compiler.check_revision(self.root,'a'*40)
        git.assert_called_once_with(['git','-C',str(self.root),'rev-parse','HEAD'],text=True)
        with patch.object(compiler.subprocess,'check_output',return_value='b'*40+'\n'), \
             self.assertRaisesRegex(ValueError,'Checked out source differs'):compiler.check_revision(self.root,'a'*40)
        selected.write_text(selected.read_text()+selected.read_text())
        with self.assertRaisesRegex(ValueError,'one immutable workflow selection'):compiler.workflow_selection(selected,'guest-phase.yml')


class CompilationCLIAdmissionEdges(TemporarySourceTests):
    def test_admitted_enabled_packet_writes_only_new_private_output_and_forwards_source_arguments(self):
        _,packet=configuration(self.root);stack=self.root/'stack';site=self.root/'site.yaml';output=self.root/'packet.json'
        argv=['tool','--stack',str(stack),'--site',str(site),'--guest','worker','--admit','--output',str(output)]
        with patch.object(sys,'argv',argv),patch.object(compiler,'compile_site',return_value={'worker':packet}) as compile_site:
            compiler.main()
        compile_site.assert_called_once_with(stack,site,[],admit=True)
        self.assertEqual(output.read_bytes(),compiler.encoded(packet))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
        before=output.read_bytes()
        with patch.object(sys,'argv',argv),patch.object(compiler,'compile_site',return_value={'worker':packet}),self.assertRaises(FileExistsError):compiler.main()
        self.assertEqual(output.read_bytes(),before)

    def test_admitted_disabled_packet_refuses_before_output_creation(self):
        _,packet=configuration(self.root);packet['enabled']=False;output=self.root/'packet.json'
        argv=['tool','--stack',str(self.root/'stack'),'--site',str(self.root/'site.yaml'),
              '--guest','worker','--admit','--output',str(output)]
        with patch.object(sys,'argv',argv),patch.object(compiler,'compile_site',return_value={'worker':packet}), \
             self.assertRaisesRegex(ValueError,'Keep disabled guests outside deployment admission'):compiler.main()
        self.assertFalse(output.exists())


class BoundaryProjectionEdges(TemporarySourceTests):
    def test_mac_literal_and_url_hostname_walk_are_not_implicit_allocation_exemptions(self):
        self.assertTrue(boundary.concrete_network('02:00:00:00:00:01'))
        self.assertFalse(boundary.concrete_network(17));self.assertFalse(boundary.concrete_network('198.18.0.2'))
        values=list(boundary._network_values({'records':['https://10.44.20.5:8443/path','scheme:///path',None,5]}))
        self.assertEqual(values,['https://10.44.20.5:8443/path','10.44.20.5','scheme:///path'])
        self.assertTrue(any(boundary.concrete_network(value) for value in values))

    def test_stack_projection_skips_only_known_fixture_nonconfig_files_and_reports_site_policy_allocation(self):
        library={key:{} for key in ('guest_templates','app_profiles','software','runtime_profiles','health_profiles','monitoring_profiles','authentication_profiles')}
        library['policies']={key:{} for key in component_sources.POLICIES}
        site={key:{} for key in ('networks','external_endpoints','guests','domains','host_aliases')}
        site['policies']={'network':{'explicit':{'rules':[{'direction':'out','proto':'tcp','comment':'synthetic concrete rule',
                                                        'destination':'10.44.20.0/24','port':'443'}]}}}
        source=json.dumps({'schema':component_sources.SCHEMA,'kind':'site'})
        files=[('notes.md','not parsed'),('tests/fixture.yaml',': not a source'),
               ('definition.yaml','kind: app-profile\n'),('site.example.yaml',source)]
        with patch.object(component_sources,'library',return_value=(library,object())), \
             patch.object(component_sources,'site',return_value=(site,object())) as loader, \
             patch.object(component_plan,'resolve') as resolver:
            findings=boundary.stack_allocations(self.root,files)
        loader.assert_called_once_with(self.root/'site.example.yaml')
        resolver.assert_called_once_with(self.root,self.root/'site.example.yaml',admit=False)
        self.assertEqual(findings,[('site.example.yaml',1,'concrete-network-policy')])


if __name__=='__main__':unittest.main()
