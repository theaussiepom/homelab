"""Execute actual component phase Bash with only its three commands replaced.

An existing graph interface fake supplies unrelated Plan bindings. Generated
workflow/action source is real. This models default success() step gating; it
is not GitHub execution, credential handling or native deployment acceptance.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import workflows
from component_input_secrets import PREFIX
from test_component_workflow_generation import graph

STUB = r'''import json, os, pathlib, sys
stage = pathlib.Path(__file__).stem
phase, guest = os.environ['PHASE'], os.environ['GUEST']
args = sys.argv[1:]
packet = pathlib.Path(args[args.index('--output' if stage == 'compile' else '--packet') + 1])
names = json.loads(os.environ['STUB_SECRET_NAMES'])
row = {'stage': stage, 'phase': phase, 'guest': guest, 'packet': str(packet),
       'secrets': {name: os.environ[name] for name in names if os.environ.get(name)},
       'present_slots': sorted(name for name in os.environ if name.startswith('HOMELAB_APP_SECRET_'))}
with open(os.environ['STUB_TRACE'], 'a') as out: out.write(json.dumps(row) + '\n')
if os.environ.get('STUB_FAIL') == phase + ':' + stage: raise SystemExit(23)
if stage == 'compile':
    assert args[args.index('--site-root') + 1] == '.' and '--site' not in args
    assert args[args.index('--guest') + 1] == guest and '--admit' in args
    assert args[args.index('--disabled') + 1] == '[]'
    with packet.open('x') as out: json.dump({'phase': phase, 'guest': guest}, out)
else:
    assert json.loads(packet.read_text()) == {'phase': phase, 'guest': guest}
    if stage == 'deploy': assert args[args.index('--phase') + 1] == phase
'''


class ComponentJobExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = self.root / 'stack'; (self.stack / '.github/workflows').mkdir(parents=True)
        (self.stack / '.github/workflows/phase.yml').write_text(
            'jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@' + '1' * 40 + '\n')
        source = self.root / 'site.yaml'; source.write_text('kind: site\n')
        self.graph = graph()
        with patch.object(workflows.compiler, 'resolve_plan', return_value=object()) as resolver, \
             patch.object(workflows.component_workflows, 'model', return_value=self.graph):
            self.models = workflows.models(self.stack, site_source=source)
        resolver.assert_called_once_with(self.stack, source, None)
        recipe, _ = workflows.phase_recipe()
        self.action = workflows.composite_actions(recipe)['guest-phase']
        actual = yaml.safe_load((workflows.PHASE_RECIPE.parents[1] / 'actions/guest-phase/action.yml').read_text())
        self.assertEqual(self.action, actual)
        self.assertEqual([step['name'] for step in actual['runs']['steps']],
                         ['Check readiness', 'Check inputs', 'Load credentials', 'Deploy'])
        self.common = set(workflows.COMMON_SECRETS)
        self.slots = {PREFIX + slot.upper() for slot in workflows.SCALAR_SLOTS}
        self.known = self.common | self.slots | {
            name for row in self.graph['guests'].values() for name in row['workflow_secrets']}

    def inputs(self, call, values):
        """Only direct fixture leaf bindings; no expression evaluation engine."""
        selected = {name: row.get('default', '') for name, row in self.action['inputs'].items()}
        for name, value in call['with'].items():
            if value == '${{ inputs.disabled }}': value = '[]'
            elif value.startswith('${{'):
                match = re.fullmatch(r'\$\{\{ secrets\.([A-Za-z_][A-Za-z_0-9]*) \}\}', value)
                self.assertIsNotNone(match, value); value = values[match[1]]
            selected[name] = value
        return selected

    def environment(self, fields, selected):
        # Ambient controller secrets never enter a synthetic trace or command.
        result = {key: value for key, value in os.environ.items()
                  if key not in self.known and not key.startswith(PREFIX)}
        for name, expression in fields.items():
            match = re.fullmatch(r'\$\{\{ inputs\.([A-Za-z_][A-Za-z_0-9]*) \}\}', expression)
            self.assertIsNotNone(match, expression)
            result[name] = selected[match[1]]
        return result

    def exercise(self, guests, fail=None, guard='CONFIGURING'):
        temporary = tempfile.TemporaryDirectory(dir=self.root); self.addCleanup(temporary.cleanup)
        work = Path(temporary.name).resolve()
        for relative in ('blueprints/compile.py', 'blueprints/credentials.py', 'proxmox/applications/deploy.py'):
            target = work / 'framework-source' / relative
            target.parent.mkdir(parents=True, exist_ok=True); target.write_text(STUB)
        runner = work / 'temp'; runner.mkdir(mode=0o700)
        trace = work / 'trace.jsonl'; bootstrap = work / 'bootstrap'; bootstrap.mkdir()
        if fail == 'guard': (bootstrap / guard).touch()
        values = {name: 'synthetic ' + name + ' \n literal " $ : / end'
                  for name in self.known - self.slots}
        returncode = 0
        for guest in guests:
            job = self.models['guest-' + guest + '.yml']['jobs']['deploy']
            for call in job['steps'][1:]:
                self.assertNotIn('if', call); self.assertNotIn('continue-on-error', call)
                selected = self.inputs(call, values)
                for step in self.action['runs']['steps']:
                    self.assertNotIn('if', step); self.assertNotIn('continue-on-error', step)
                    environment = self.environment(step.get('env', {}), selected)
                    script = step['run']
                    if step['name'] == 'Check readiness':
                        script = script.replace('/var/lib/homelab-bootstrap', str(bootstrap))
                    environment.update(HOMELAB_CONFIG_PYTHON=sys.executable, RUNNER_TEMP=str(runner),
                        GITHUB_RUN_ID='900', GITHUB_RUN_ATTEMPT='1', STUB_TRACE=str(trace),
                        STUB_SECRET_NAMES=json.dumps(sorted(self.known)), STUB_FAIL=fail or '')
                    result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=work,
                        env=environment, capture_output=True, text=True, timeout=15)
                    self.assertFalse(any(secret in result.stdout + result.stderr for secret in values.values()))
                    if result.returncode:
                        returncode = result.returncode
                        break
                if returncode: break  # Model GitHub's unchanged default success() gating.
            if returncode: break
        records = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return returncode, records, runner, values

    def test_actual_phase_chains_use_unique_private_packets_and_step_only_scalars(self):
        status, records, folder, values = self.exercise(self.graph['guest_order'])
        self.assertEqual(status, 0)
        expected = [(guest, phase['id'], stage) for guest in self.graph['guest_order']
                    for phase in self.graph['guests'][guest]['phases']
                    for stage in ('compile', 'credentials', 'deploy')]
        self.assertEqual([(row['guest'], row['phase'], row['stage']) for row in records], expected)
        self.assertEqual(len(records), 18)
        self.assertEqual(len({row['packet'] for row in records}), 6)
        for index in range(0, len(records), 3):
            compile_row, credential_row, deploy_row = records[index:index + 3]
            guest, phase = compile_row['guest'], compile_row['phase']
            packet = folder / ('guest-900-1-' + guest + '-' + phase + '.json')
            self.assertTrue(all(row['packet'] == str(packet) for row in records[index:index + 3]))
            self.assertEqual(stat.S_IMODE(packet.stat().st_mode), 0o600)
            self.assertEqual(json.loads(packet.read_text()), {'guest': guest, 'phase': phase})
            self.assertEqual(compile_row['secrets'], {}); self.assertEqual(compile_row['present_slots'], [])
            self.assertEqual(credential_row['secrets'], {name: values[name] for name in self.common})
            self.assertEqual(credential_row['present_slots'], [])
            declaration = next(row for row in self.graph['guests'][guest]['phases'] if row['id'] == phase)
            selected = {PREFIX + slot.upper(): values[row['workflow_secret']]
                        for slot, row in declaration['inputs'].items()}
            self.assertEqual(deploy_row['secrets'], selected)
            self.assertEqual(deploy_row['present_slots'], sorted(selected))
        self.assertEqual(len(list(folder.iterdir())), 6)

    def test_each_phase_compile_credential_or_deploy_failure_stops_all_later_commands(self):
        stages = ('compile', 'credentials', 'deploy')
        for guest in self.graph['guest_order']:
            phases = [row['id'] for row in self.graph['guests'][guest]['phases']]
            for index, phase in enumerate(phases):
                for position, stage in enumerate(stages):
                    with self.subTest(guest=guest, phase=phase, stage=stage):
                        status, records, _, _ = self.exercise([guest], phase + ':' + stage)
                        self.assertEqual(status, 23)
                        expected = [(earlier, item) for earlier in phases[:index] for item in stages]
                        expected += [(phase, item) for item in stages[:position + 1]]
                        self.assertEqual([(row['phase'], row['stage']) for row in records], expected)

    def test_guard_failure_prevents_compile_binding_and_deploy(self):
        for guard in ('CONFIGURING', 'BOOTSTRAP-CD-HOLD.json'):
            with self.subTest(guard=guard):
                status, records, folder, _ = self.exercise(['viewer'], 'guard', guard)
                self.assertNotEqual(status, 0)
                self.assertEqual(records, [])
                self.assertEqual(list(folder.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
