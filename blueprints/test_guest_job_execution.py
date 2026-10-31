"""Run exact phase scripts against inert local tools; model default-success gating."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

import workflows
import test_workflow_materialization as oracle
import test_workflow_secrets as secrets

STUB = r'''import json, os, pathlib, sys
stage = pathlib.Path(__file__).stem
phase, guest = os.environ['PHASE'], os.environ['GUEST']
args = sys.argv[1:]
packet = pathlib.Path(args[args.index('--output' if stage == 'compile' else '--packet') + 1])
row = {'stage': stage, 'phase': phase, 'guest': guest, 'packet': str(packet),
       'secrets': {name: os.environ[name] for name in json.loads(os.environ['STUB_SECRET_NAMES']) if os.environ.get(name)}}
with open(os.environ['STUB_TRACE'], 'a') as out: out.write(json.dumps(row) + '\n')
if os.environ.get('STUB_FAIL') == phase + ':' + stage: raise SystemExit(23)
if stage == 'compile':
    assert args[args.index('--guest') + 1] == guest
    with packet.open('x') as out: json.dump({'phase': phase, 'guest': guest}, out)
else:
    assert json.loads(packet.read_text()) == {'phase': phase, 'guest': guest}
    if stage == 'deploy': assert args[args.index('--phase') + 1] == phase
'''


class GuestJobExecutionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); oracle.fixture(self.root)
        self.models = workflows.models(self.root)
        self.known = secrets.ALL_NAMES | set(secrets.ALIASES)

    def environment(self, fields, values):
        result = {key: value for key, value in os.environ.items() if key not in self.known}
        for key, expression in fields.items():
            if expression == '${{ inputs.disabled }}': value = '[]'
            elif expression.startswith('${{'):
                direct = re.fullmatch(r'\$\{\{ secrets\.([A-Z_]+) \}\}', expression)
                if direct: value = values.get(direct[1], '')
                else:
                    guard = re.fullmatch(r"\$\{\{ '([a-z0-9-]+)' == '([a-z-]+)' && (?:secrets\.([A-Z_]+)|'') \|\| '' \}\}", expression)
                    self.assertIsNotNone(guard, expression)
                    value = values.get(guard[3], '') if guard[1] == guard[2] else ''
            else: value = expression
            result[key] = value
        return result

    def exercise(self, guest, fail=None):
        temp = tempfile.TemporaryDirectory(dir=self.root); self.addCleanup(temp.cleanup)
        work = Path(temp.name)
        for path in ('blueprints/compile.py', 'blueprints/credentials.py', 'proxmox/applications/deploy.py'):
            target = work / 'framework-source' / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(STUB)
        runner_temp = work / 'temp'; runner_temp.mkdir(mode=0o700)
        trace = work / 'trace.jsonl'
        workflow = self.models['guest-' + guest + '.yml']
        values = {key: 'invented-' + key for key in workflow['on']['workflow_call']['secrets']}
        job = workflow['jobs']['deploy']; returncode = 0
        for step in job['steps'][6:]:
            self.assertNotIn('if', step); self.assertNotIn('continue-on-error', step)
            environment = self.environment(step['env'], values)
            environment.update(RUNNER_TEMP=str(runner_temp), GITHUB_RUN_ID='900', GITHUB_RUN_ATTEMPT='1',
                STUB_TRACE=str(trace), STUB_SECRET_NAMES=json.dumps(sorted(self.known)), STUB_FAIL=fail or '')
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']], cwd=work,
                                    env=environment, capture_output=True, text=True, timeout=15)
            if result.returncode:
                returncode = result.returncode
                break  # GitHub's documented default success() step condition.
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        return returncode, records, runner_temp, values

    def test_all36_phase_command_chains_use_unique_private_packets_and_step_only_credentials(self):
        commands = 0
        for guest, phases in oracle.PHASES.items():
            with self.subTest(guest=guest):
                status, records, folder, values = self.exercise(guest)
                self.assertEqual(status, 0)
                self.assertEqual([(r['phase'], r['stage']) for r in records],
                                 [(phase, stage) for phase in phases for stage in ('compile', 'credentials', 'deploy')])
                self.assertEqual(len({r['packet'] for r in records}), len(phases))
                for index, phase in enumerate(phases):
                    compile_row, credentials_row, deploy_row = records[index * 3:index * 3 + 3]
                    expected = folder / ('guest-900-1-' + guest + '-' + phase + '.json')
                    self.assertTrue(all(row['packet'] == str(expected) for row in (compile_row, credentials_row, deploy_row)))
                    self.assertEqual(stat.S_IMODE(expected.stat().st_mode), 0o600)
                    self.assertEqual(compile_row['secrets'], {})
                    self.assertEqual(credentials_row['secrets'], {key: values[key] for key in secrets.COMMON})
                    self.assertEqual(deploy_row['secrets'], {alias: values[name] for alias, name in secrets.ALIASES.items() if name in values})
                    self.assertEqual(json.loads(expected.read_text()), {'guest': guest, 'phase': phase})
                commands += len(records)
        self.assertEqual(commands, 108)

    def test_each_phase_compile_credential_or_deploy_failure_stops_all_later_commands(self):
        phases = oracle.PHASES['automation']; stages = ('compile', 'credentials', 'deploy')
        for phase_index, phase in enumerate(phases):
            for stage_index, stage in enumerate(stages):
                with self.subTest(phase=phase, stage=stage):
                    status, records, _, _ = self.exercise('automation', phase + ':' + stage)
                    self.assertEqual(status, 23)
                    expected = [(name, item) for name in phases[:phase_index] for item in stages]
                    expected.extend((phase, item) for item in stages[:stage_index + 1])
                    self.assertEqual([(r['phase'], r['stage']) for r in records], expected)
