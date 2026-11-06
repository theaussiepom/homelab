"""Real source→lowerer→existing renderer entrypoints, without guest bundles."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'proxmox/applications'))
import render
import component_lower
import component_plan
from test_component_plan import library, site


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stack, self.consumer = self.root / 'library', self.root / 'consumer'
        self.stack.mkdir()
        self.consumer.mkdir()

    def compile(self, selected=None):
        spec = library()
        spec['software'] = {'unbound': {'images': {'unbound': 'unbound'}}}
        spec['runtime_profiles'] = {'unbound': {'containers': {'unbound': {
            'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}}}}
        profile = spec['app_profiles']['recursive']
        profile.update(software=['unbound'], runtime=['unbound'], storage={'config': {
            'target': '/opt/unbound/etc/unbound', 'required': False, 'read_only': False, 'kind': 'directory'}})
        (self.stack / 'stack.json').write_text(json.dumps(spec))
        # Explicitly synthetic immutable image: these tests render configuration,
        # never pull/start it or claim vendor/target qualification.
        (self.stack / 'images.json').write_text(json.dumps({'unbound': {
            'repository': 'example/unbound', 'tag': '1', 'digest': 'sha256:' + 'a' * 64}}))
        path = self.consumer / 'site.json'
        path.write_text(json.dumps(site() if selected is None else selected))
        plan = component_plan.resolve(self.stack, path)
        return component_lower.runtime_config(plan, 'resolver')

    def test_fresh_standalone_unbound_reaches_real_renderer_without_pihole(self):
        cfg = self.compile()
        document = render.compose(cfg)
        self.assertEqual(set(document['services']), {'recursive_a_unbound'})
        value = document['services']['recursive_a_unbound']
        self.assertEqual(value['ports'], ['127.0.0.1:5335:53/udp'])
        self.assertEqual(value['volumes'], [])
        self.assertNotIn('network_mode', value)
        self.assertNotIn('networks', value)
        self.assertEqual(value['pull_policy'], 'missing')
        self.assertEqual(value['mem_limit'], '256m')
        self.assertNotIn('pihole', document['services'])

    def test_two_projects_same_local_service_key_have_distinct_real_outputs(self):
        selected = site()
        selected['guests']['resolver']['resources'] = {'memory_mib': 1024}
        selected['guests']['resolver']['compose_projects'] = {
            'first': {'name': 'project-one'}, 'second': {'name': 'project-two'}}
        first = selected['apps']['recursive_a']
        first['identity'] = {'project': 'first', 'services': {'unbound': 'unbound'}}
        second = copy.deepcopy(first)
        second['identity']['project'] = 'second'
        second['properties'] = {'publish_port': 5336}
        selected['apps']['recursive_b'] = second
        cfg = self.compile(selected)
        documents = render.compositions(cfg)
        self.assertEqual(set(documents), {'project-one', 'project-two'})
        self.assertEqual(set(documents['project-one']['services']), {'unbound'})
        self.assertEqual(set(documents['project-two']['services']), {'unbound'})
        self.assertEqual(documents['project-two']['services']['unbound']['ports'], ['127.0.0.1:5336:53/udp'])
        with self.assertRaises(ValueError):
            render.compose(cfg)

    def test_retained_config_binding_and_cosmetic_repeat_are_preserved(self):
        selected = site()
        guest = selected['guests']['resolver']
        guest['compose_projects'] = {'retained': {'name': 'old-project'}}
        guest['root_paths'] = {'configuration': {'path': '/srv/example/retained-unbound'}}
        app = selected['apps']['recursive_a']
        app.update(lifecycle='retained', identity={'phase': 'unbound', 'runtime_id': 'unbound',
            'project': 'retained', 'services': {'unbound': 'unbound'}, 'networks': {'default': 'default'}},
            storage={'config': {'root_path': 'configuration', 'subpath': ''}})
        first = render.compose(self.compile(selected))
        app['display_name'] = 'A different visible label'
        self.assertEqual(render.compose(self.compile(selected)), first)
        self.assertEqual(first['services']['unbound']['volumes'],
                         ['/srv/example/retained-unbound:/opt/unbound/etc/unbound'])
        app.pop('storage')
        with self.assertRaises(ValueError):
            render.compose(self.compile(selected))
        app['lifecycle'] = 'fresh'
        app['storage'] = {'config': {'root_path': 'configuration', 'subpath': ''}}
        with self.assertRaises(ValueError):
            render.compose(self.compile(selected))

    def test_real_renderer_cli_writes_project_artifacts_and_owned_service_map(self):
        cfg = self.compile()
        input_path, output = self.root / 'runtime.json', self.root / 'rendered'
        input_path.write_text(json.dumps(cfg))
        input_path.chmod(0o600)
        completed = subprocess.run([sys.executable, str(ROOT / 'proxmox/applications/render.py'),
            '--config', str(input_path), '--output', str(output)], capture_output=True, text=True)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (0, '', ''))
        manifest = json.loads((output / 'component-projects.json').read_text())
        self.assertEqual(len(manifest), 1)
        project = next(iter(manifest))
        self.assertEqual(manifest[project]['applications'], {'recursive_a': ['recursive_a_unbound']})
        document = json.loads((output / manifest[project]['file']).read_text())
        self.assertEqual(document, render.compose(cfg))
        self.assertEqual((output / manifest[project]['file']).stat().st_mode & 0o777, 0o600)

    def test_project_file_is_explicit_and_fresh_default_does_not_depend_on_project_count(self):
        import component_runtime
        selected = site()
        guest = selected['guests']['resolver']
        guest['resources'] = {'memory_mib': 1024}
        guest['compose_projects'] = {'first': {'name': 'old-project', 'file': 'compose.yml'}}
        first = selected['apps']['recursive_a']
        first['identity'] = {'project': 'first'}
        cfg = self.compile(selected)
        self.assertIn('compose.yml', component_runtime.artifacts(cfg))
        selected['apps']['recursive_b'] = copy.deepcopy(first)
        selected['apps']['recursive_b'].pop('identity')
        selected['apps']['recursive_b']['properties'] = {'publish_port': 5336}
        outputs = component_runtime.artifacts(self.compile(selected))
        self.assertIn('compose.yml', outputs)
        self.assertIn('compose-recursive_b.yml', outputs)
        for bad in ('../compose.yml', '/compose.yml', 'compose.json', 'component-projects.json', 'x.yml\n'):
            with self.subTest(filename=bad):
                guest['compose_projects']['first']['file'] = bad
                with self.assertRaises(ValueError):
                    self.compile(selected)
        guest['compose_projects']['first']['file'] = 'compose.yml'
        guest['compose_projects']['second'] = {'name': 'other-project', 'file': 'compose.yml'}
        with self.assertRaises(ValueError):
            self.compile(selected)

    def test_real_source_lower_renderer_refuses_root_and_subpath_interpolation(self):
        selected = site()
        guest = selected['guests']['resolver']
        guest['compose_projects'] = {'retained': {'name': 'old-project'}}
        guest['root_paths'] = {'configuration': {'path': '/srv/example/config'}}
        app = selected['apps']['recursive_a']
        app.update(lifecycle='retained', identity={'phase': 'unbound', 'runtime_id': 'unbound',
            'project': 'retained', 'services': {'unbound': 'unbound'}, 'networks': {'default': 'default'}},
            storage={'config': {'root_path': 'configuration', 'subpath': ''}})
        self.assertEqual(render.compose(self.compile(selected))['services']['unbound']['volumes'],
                         ['/srv/example/config:/opt/unbound/etc/unbound'])
        for field in ('root', 'subpath'):
            with self.subTest(field=field):
                bad = copy.deepcopy(selected)
                if field == 'root':
                    bad['guests']['resolver']['root_paths']['configuration']['path'] = '/srv/example/${COMPONENT_LITERAL_ROOT}'
                else:
                    bad['apps']['recursive_a']['storage']['config']['subpath'] = '${COMPONENT_LITERAL_ROOT}'
                with self.assertRaises(ValueError):
                    render.compose(self.compile(bad))


if __name__ == '__main__':
    unittest.main()
