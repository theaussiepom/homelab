"""Maintained tutorial and public field inventory use the real source contracts."""
import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'proxmox/applications'))
import authored_config
import compile as compiler
import component_packet
from component_errors import ComponentError


class DocumentationContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / 'config'
        shutil.copytree(ROOT / 'docs/examples/first-configuration', self.config)
        self.site = self.config / 'site.yaml'

    def test_documented_cli_check_packet_mode_phases_and_create_only_output(self):
        with patch('sys.argv', ['compile.py', '--stack', str(self.config), '--site', str(self.site), '--check']), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            compiler.main()
        self.assertIn('All component guests compile offline', output.getvalue())
        target = self.root / 'resolver.json'
        argv = ['compile.py', '--stack', str(self.config), '--site-root', str(self.config),
                '--guest', 'resolver', '--output', str(target)]
        with patch('sys.argv', argv):
            compiler.main()
        original = target.read_bytes()
        packet = json.loads(original)
        self.assertEqual(packet['schema'], 'homelab-component-guest-deployment-v1')
        self.assertEqual(json.loads(packet['files']['site.json'])['deployment']['phases'],
                         ['preparation', 'recursive_a'])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with patch('sys.argv', argv), self.assertRaises(FileExistsError):
            compiler.main()
        self.assertEqual(target.read_bytes(), original)

    def test_tutorial_is_source_only_and_refuses_real_deployment_admission(self):
        with patch('subprocess.run', side_effect=AssertionError('No process or target')), \
             patch('socket.create_connection', side_effect=AssertionError('No network')):
            plan = compiler.resolve_plan(self.config, self.site)
            self.assertEqual(set(plan.resolved['apps']), {'recursive_a'})
            self.assertEqual(plan.resolved['guest_dependencies'], {'resolver': []})
            with self.assertRaisesRegex(ComponentError, 'synthetic-binding'):
                compiler.resolve_plan(self.config, self.site, admit=True)

    def test_explicit_template_defaults_and_omission_produce_identical_effective_packets(self):
        plan = compiler.resolve_plan(self.config, self.site)
        before = component_packet.lower_plan(plan)
        selected = authored_config.read(self.site)
        guest = selected['guests']['resolver']
        template = plan.library['guest_templates'][guest['template']]
        for name in ('resources', 'startup', 'security'):
            self.assertNotIn(name, guest)
            guest[name] = copy.deepcopy(template[name])
        # JSON is the same authored value model; keep the sole site YAML filename.
        self.site.write_text(json.dumps(selected))
        after = compiler.resolve_plan(self.config, self.site)
        self.assertEqual(component_packet.lower_plan(after), before)
        selected['guests']['resolver']['resources'] = {'memory_mib': 1024}
        self.site.write_text(json.dumps(selected))
        guest = compiler.resolve_plan(self.config, self.site).resolved['guests']['resolver']
        self.assertEqual(guest['resources'], dict(template['resources'], memory_mib=1024))

    def test_documented_display_change_preserves_persistent_app_identity(self):
        before = compiler.resolve_plan(self.config, self.site)
        selected = authored_config.read(self.site)
        selected['apps']['recursive_a']['display_name'] = 'Example recursive resolver'
        self.site.write_text(json.dumps(selected))
        after = compiler.resolve_plan(self.config, self.site)
        self.assertEqual(after.resolved['apps']['recursive_a']['display_name'], 'Example recursive resolver')
        self.assertEqual(after.resolved['apps']['recursive_a']['identity'],
                         before.resolved['apps']['recursive_a']['identity'])

    def test_public_literal_field_inventory_is_reachable_in_reference(self):
        # This is a completeness tripwire, not a second validator: actual example
        # compilation above establishes behavior. New public fields require docs.
        reference = '\n'.join(path.read_text() for path in (ROOT / 'docs/reference').glob('*.md'))
        fields = set()
        for name in ('component_types', 'component_sources', 'component_connections',
                     'component_exposures', 'component_secrets', 'component_auth',
                     'component_properties', 'component_foundations', 'component_monitoring'):
            tree = ast.parse((ROOT / 'blueprints' / (name + '.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and ((isinstance(node.func, ast.Name) and node.func.id == 'closed')
                        or (isinstance(node.func, ast.Attribute) and node.func.attr == 'closed')):
                    for argument in node.args[1:3]:
                        for child in ast.walk(argument):
                            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                                fields.add(child.value)
        self.assertGreater(len(fields), 100)
        self.assertEqual(sorted(field for field in fields
                                if not re.search(r'\b' + re.escape(field) + r'\b', reference)), [])
        for relative in ('site.md', 'library.md', 'sources.md', 'connections.md', 'exposures.md',
                         'guests.md', 'apps.md', 'app-properties.md', 'lifecycle.md', 'support.md', 'cli.md'):
            self.assertIn('(' + relative + ')', (ROOT / 'docs/reference/README.md').read_text())


if __name__ == '__main__':
    unittest.main()
