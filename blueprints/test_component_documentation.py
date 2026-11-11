"""Maintained tutorial and public field inventory use the real source contracts."""
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
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
from test_documentation_contract_helpers import PAGE, SOURCE, check_contract, expect_component_refusal


class DocumentationContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / 'config'
        shutil.copytree(ROOT / 'docs/examples/first-configuration', self.config)
        self.site = self.config / 'site.yaml'

    def walkthrough_block(self, marker, language):
        text = (ROOT / 'docs/guides/first-configuration.md').read_text()
        blocks = re.findall(r'<!-- ' + re.escape(marker) + r' -->\n```' + language + r'\n(.*?)\n```',
                            text, re.S)
        self.assertEqual(len(blocks), 1, marker)
        return blocks[0] + '\n'

    def personalised_site(self):
        self.site.write_text(self.walkthrough_block('example: personalised-site', 'yaml'))
        return authored_config.read(self.site)

    def test_personalised_walkthrough_executes_printed_commands_and_inspects_effects(self):
        self.personalised_site()
        environment = dict(os.environ, FRAMEWORK=str(ROOT), WORK=str(self.root),
                           PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'])
        checked = subprocess.run(['/bin/sh', '-eu', '-c', self.walkthrough_block('walkthrough: compile', 'sh')],
                                 cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertIn('All component guests compile offline', checked.stdout)
        inspected = subprocess.run(['/bin/sh', '-eu', '-c', self.walkthrough_block('walkthrough: inspect', 'sh')],
                                   cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(inspected.returncode, 0, inspected.stdout + inspected.stderr)
        self.assertEqual(inspected.stdout, self.walkthrough_block('walkthrough: expected', 'text'))
        packet = json.loads((self.root / 'resolver.json').read_text())
        config = json.loads(packet['files']['site.json'])
        runtime = json.loads(packet['files']['component-runtime.json'])
        guest = config['guest']
        self.assertEqual(config['site'], {'node': 'practice-pve', 'api_endpoint': 'https://192.0.2.20:8006/'})
        self.assertEqual((guest['vmid'], guest['hostname'], guest['memory_mib']), (620, 'practice-resolver', 1024))
        self.assertEqual(guest['interfaces'], [{'bridge': 'practice0', 'vlan': None,
            'mac': '02:00:00:30:00:20', 'ipv4': '198.18.30.20/24', 'gateway': '198.18.30.1', 'ipv6': 'manual'}])
        self.assertEqual((guest['cpu'], guest['root_gib'], runtime['guest']['os_reserve_mib']), (1, 8, 256))
        self.assertEqual(runtime['applications']['recursive_a']['interfaces']['local_interface'], {'scope': 'guest-loopback'})
        expect_component_refusal(lambda: compiler.resolve_plan(self.config, self.site, admit=True),
                                 'component.synthetic-binding', ('guests', 'resolver', 'admission'))

    def test_personalised_alternative_decisions_and_typed_extraction_preserve_bindings(self):
        selected = self.personalised_site()
        selected['contexts']['lab'].update(node='workshop-pve', timezone='Australia/Brisbane')
        selected['external_endpoints']['api']['address'] = '192.0.2.30'
        selected['external_endpoints']['dns']['address'] = '198.18.40.53'
        selected['storage']['local']['pool'] = 'workshop-local'
        selected['networks']['primary'].update(cidr='198.18.40.0/24', bridge='workshop0', gateway='198.18.40.1')
        guest = selected['guests']['resolver']
        guest.update(identity={'vmid': 720, 'hostname': 'workshop-resolver'},
                     template_file_id='workshop:vztmpl/debian-13.tar.zst', resources={'memory_mib': 1536})
        guest['interfaces']['management'].update(mac='02:00:00:40:00:20',
                                                address={'mode': 'static', 'value': '198.18.40.20'})
        self.site.write_text(json.dumps(selected))
        with patch('subprocess.run', side_effect=AssertionError('No process or target')), \
             patch('socket.create_connection', side_effect=AssertionError('No network')):
            plan = compiler.resolve_plan(self.config, self.site)
            before = component_packet.lower_plan(plan)
        config = json.loads(before['resolver']['files']['site.json'])
        runtime = json.loads(before['resolver']['files']['component-runtime.json'])
        self.assertEqual(config['site'], {'node': 'workshop-pve', 'api_endpoint': 'https://192.0.2.30:8006/'})
        lowered = config['guest']
        self.assertEqual((lowered['vmid'], lowered['hostname'], lowered['storage_id'], lowered['template_file_id']),
                         (720, 'workshop-resolver', 'workshop-local', 'workshop:vztmpl/debian-13.tar.zst'))
        self.assertEqual(lowered['interfaces'], [{'bridge': 'workshop0', 'vlan': None,
            'mac': '02:00:00:40:00:20', 'ipv4': '198.18.40.20/24', 'gateway': '198.18.40.1', 'ipv6': 'manual'}])
        self.assertEqual(lowered['dns_servers'], ['198.18.40.53'])
        self.assertEqual(runtime['guest'], {'id': 'resolver', 'memory_mib': 1536,
                                           'os_reserve_mib': 256, 'timezone': 'Australia/Brisbane'})
        self.assertEqual(plan.resolved['apps']['recursive_a']['profile'], 'recursive')
        # Execute the exact complete leaf and parent reference printed in the guide.
        (self.config / 'apps').mkdir()
        (self.config / 'apps/recursive.yaml').write_text(self.walkthrough_block('example: personalised-app-leaf', 'yaml'))
        reference = authored_config.parse(self.walkthrough_block('example: personalised-app-reference', 'yaml').encode(), '.yaml')
        selected['apps'] = reference['apps']
        self.site.write_text(json.dumps(selected))
        extracted = compiler.resolve_plan(self.config, self.site)
        self.assertEqual(component_packet.lower_plan(extracted), before)
        self.assertEqual(extracted.resolved['guest_dependencies'], {'resolver': []})
        self.assertNotEqual(extracted.pins, plan.pins)

    def test_personalised_refusals_report_documented_cidr_and_memory_failures(self):
        selected = self.personalised_site()
        compiler.compile_site(self.config, self.site)
        wrong = copy.deepcopy(selected)
        wrong['networks']['primary']['cidr'] = '198.18.30.20/24'
        self.site.write_text(json.dumps(wrong))
        expect_component_refusal(lambda: compiler.resolve_plan(self.config, self.site),
                                 'component.invalid', ('networks', 'primary'))
        wrong = copy.deepcopy(selected)
        wrong['guests']['resolver']['resources']['memory_mib'] = 256
        self.site.write_text(json.dumps(wrong))
        expect_component_refusal(lambda: compiler.resolve_plan(self.config, self.site),
                                 'component.memory-budget', ())
        self.site.write_text(json.dumps(selected))
        self.assertEqual(set(compiler.compile_site(self.config, self.site)), {'resolver'})

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

    def test_network_nic_documentation_conformance(self):
        count = check_contract((ROOT / SOURCE).read_text(), (ROOT / PAGE).read_text(),
                               read_text=lambda path: (ROOT / path).read_text())
        self.assertGreater(count, 0)

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

    def test_documented_shell_temp_path_is_physical_before_confined_compilation(self):
        # Exercise the actual bounded setup lines, without pip, venv or targets.
        # A symlinked TMPDIR reproduces macOS /var even on Linux.
        physical = self.root / 'scratch'
        physical.mkdir()
        alias = self.root / 'temporary-alias'
        alias.symlink_to(physical, target_is_directory=True)
        text = (ROOT / 'docs/guides/first-configuration.md').read_text()
        setup = re.findall(r'```sh\n(.*?)\n```', text, re.S)[0].splitlines()
        for corrected in (False, True):
            prefix = setup[:3] if corrected else setup[:2]
            command = '\n'.join([*prefix,
                'cp -R "$FRAMEWORK/docs/examples/first-configuration" "$WORK/config"',
                'printf "%s\\n" "$WORK"'])
            result = subprocess.run(['/bin/sh', '-eu', '-c', command], cwd=ROOT,
                env={'PATH': '/usr/bin:/bin', 'TMPDIR': str(alias) + '/'},
                capture_output=True, text=True, timeout=10, check=True)
            work = Path(result.stdout.strip())
            if corrected:
                self.assertEqual(work, work.resolve())
                packets = compiler.compile_site(work / 'config', work / 'config/site.yaml')
                self.assertEqual(set(packets), {'resolver'})
            else:
                self.assertNotEqual(work, work.resolve())
                with self.assertRaises(ComponentError):
                    compiler.compile_site(work / 'config', work / 'config/site.yaml')

    def test_public_literal_field_inventory_is_reachable_in_reference(self):
        # This is a completeness tripwire, not a second validator: actual example
        # compilation above establishes behavior. New public fields require docs.
        reference = '\n'.join(path.read_text() for path in (ROOT / 'docs/reference').glob('*.md'))
        fields = set()
        for name in ('component_types', 'component_sources', 'component_connections',
                     'component_exposures', 'component_secrets', 'component_auth',
                     'component_properties', 'component_foundations', 'component_monitoring',
                     'component_backup', 'component_backup_job', 'component_backup_management', 'component_backup_key'):
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
                         'guests.md', 'apps.md', 'app-properties.md', 'backup.md', 'lifecycle.md', 'support.md', 'cli.md'):
            self.assertIn('(' + relative + ')', (ROOT / 'docs/reference/README.md').read_text())


if __name__ == '__main__':
    unittest.main()
