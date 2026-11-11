"""The complete documented composition exercises real compiler boundaries."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

import component_plan
import component_packet
from component_errors import ComponentError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / 'docs/examples/backup'


class BackupDocumentation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'example'
        shutil.copytree(EXAMPLE, self.root)
        self.path = self.root / 'site.yaml'
        self.site = yaml.safe_load(self.path.read_text())

    def plan(self, disabled=None):
        self.path.write_text(yaml.safe_dump(self.site))
        return component_plan.resolve(self.root, self.path, disabled)

    def test_complete_example_resolves_management_public_key_and_guest_packet(self):
        plan = self.plan()
        packet = component_packet.lower_plan(plan)['resolver']
        cfg = json.loads(packet['files']['site.json'])
        job = cfg['app']['backup']['job']
        self.assertFalse(cfg['guest']['volumes']['backup-stage']['backup'])
        self.assertEqual(job['destination']['backup_id'], 'guest-610')
        self.assertEqual(job['destination']['datastore'], 'recovery')
        self.assertEqual(cfg['deployment']['phases'][-1], 'pbs-agent')
        self.assertEqual(plan.resolved['backup']['management']['credential']['name'], 'PBS_API_TOKEN')
        self.assertNotIn('PBS_API_TOKEN', json.dumps(packet))
        public = (self.root / 'assets/master-public.pem.fixture').read_text()
        self.assertEqual(job['recovery_public_key']['pem'], public)
        self.assertEqual(plan.pins['site']['assets/master-public.pem.fixture'], hashlib.sha256(public.encode()).hexdigest())
        self.assertEqual(component_packet.lower_plan(self.plan())['resolver'], packet)
        disabled = self.plan(['resolver'])
        self.assertEqual(disabled.resolved['enabled'], [])
        self.assertEqual(set(disabled.resolved['backup']['group']['group']['members']), {'guest-610'})

    def test_actual_backup_example_generates_separate_management_job(self):
        import workflows
        import component_workflows
        import private_workflows
        from unittest.mock import patch
        directory=self.root/'.github/workflows';directory.mkdir(parents=True)
        (directory/'phase.yml').write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@'+'1'*40+'\n')
        plan=self.plan();graph=component_workflows.model(plan)
        self.assertEqual(graph['backup']['needs'],['selection','resolver'])
        model=workflows.models(self.root,site_source=self.path)
        self.assertEqual(model['backup.yml']['jobs']['deploy']['environment'],'backup')
        self.assertNotIn('PBS_API_TOKEN',json.dumps(model['guest-resolver.yml']))
        env={'HOMELAB_ENVIRONMENT_PREFIX':'example','HOMELAB_REPOSITORY':'example/private'}
        with patch.object(private_workflows,'settings',return_value=(env,['self-hosted'])), \
             patch.object(private_workflows,'validation_workflow',return_value={'name':'Validate'}), \
             patch.object(private_workflows.compiler,'workflow_selection',return_value={'revision':'a'*40,'repository':'example/framework'}), \
             patch.object(private_workflows.compiler,'check_revision'), \
             patch.object(private_workflows.compiler,'workflow_disabled',return_value=[]), \
             patch.object(private_workflows.subprocess,'check_output',return_value=''):
            (directory/'deploy.yml').write_text('synthetic private source')
            private=private_workflows.model(self.root,self.root)
        self.assertEqual(private['jobs']['_backup']['environment'],'backup')
        self.assertEqual(private['jobs']['_backup']['needs'],['selection','resolver'])
        self.assertNotIn('inputs.',json.dumps(private['jobs']['_backup']))

    def test_documented_public_key_handoff_stages_normally_and_preserves_compiled_identity(self):
        """Compile the documented PEM-in-.pub handoff after real Git and private-path checks."""
        page = (ROOT/'docs/reference/backup.md').read_text()
        fragment = yaml.safe_load(page.split('<!-- example: backup-job -->\n```yaml\n', 1)[1].split('\n```', 1)[0])
        binding = fragment['backup']['recovery_public_key']
        relative = binding['source']
        self.assertEqual(relative, 'assets/backup/pbs-recovery-public.pub')
        self.assertIn('`'+relative+'`', (ROOT/'docs/backup/configure.md').read_text())
        before = json.loads(component_packet.lower_plan(self.plan())['resolver']['files']['site.json'])['app']['backup']['job']
        public = (self.root/'assets/master-public.pem.fixture').read_bytes()
        target = self.root/relative;target.parent.mkdir(parents=True);target.write_bytes(public)
        shutil.copyfile(ROOT/'.gitignore', self.root/'.gitignore')
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        def git(*args, check=True):
            return subprocess.run(['git', '-C', str(self.root), *args], env=env,
                                  capture_output=True, check=check, timeout=10)
        git('init', '-q', '-b', 'fixture')
        git('config', 'core.excludesFile', '/dev/null')
        self.assertEqual(git('check-ignore', '--no-index', '--', relative, check=False).returncode, 1)
        self.assertEqual(git('check-ignore', '--no-index', '--', 'assets/backup/master-public.pem', check=False).returncode, 0)
        spec = importlib.util.spec_from_file_location('backup_handoff_staged_guard', ROOT/'.githooks/staged_guard.py')
        guard = importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
        self.assertFalse(guard.private_path(relative))
        self.assertTrue(guard.private_path('assets/backup/master-public.pem'))
        git('add', '--', relative)
        self.assertEqual(git('diff', '--cached', '--name-only').stdout.decode().splitlines(), [relative])
        self.site['backup']['recovery_public_key'] = binding
        plan = self.plan()
        after = json.loads(component_packet.lower_plan(plan)['resolver']['files']['site.json'])['app']['backup']['job']
        self.assertEqual(after, before)
        self.assertEqual(plan.pins['site'][relative], hashlib.sha256(public).hexdigest())
        self.assertEqual(after['recovery_public_key']['pem'].encode(), public)

    def test_documented_shared_only_variation_does_not_enroll_guests(self):
        self.site['guests']['resolver'].pop('backup')
        with self.assertRaisesRegex(ComponentError, 'backup-client-coverage'): self.plan()
        self.site['backup'] = {}
        cfg = json.loads(component_packet.lower_plan(self.plan())['resolver']['files']['site.json'])
        self.assertNotIn('backup', cfg['app'])
        self.assertNotIn('pbs-agent', cfg['deployment']['phases'])

    def test_new_fields_fail_at_the_documented_component_boundary(self):
        original = copy.deepcopy(self.site)
        cases = [
            (lambda s: s['backup'].pop('management'), 'backup-recovery-key'),
            (lambda s: s['backup']['management'].update(datastore_path='/'), 'backup-datastore-path'),
            (lambda s: s['backup']['management'].update(credential='missing'), 'backup-management-credential'),
            (lambda s: s['backup']['recovery_public_key'].update(source='missing.pem'), 'source'),
            (lambda s: s['guests']['resolver'].update(backup={'password':'obsolete'}), 'fields'),
        ]
        for mutate, code in cases:
            self.site = copy.deepcopy(original); mutate(self.site)
            with self.subTest(code=code), self.assertRaisesRegex(ComponentError, code): self.plan()

    def test_complete_mixed_client_example_compiles_with_one_group_and_inherited_timeout(self):
        """Read the maintained two-client source through the real compiler and runtime validator."""
        self.path = self.root/'client-limits.yaml'
        plan = component_plan.resolve(self.root, self.path)
        packets = component_packet.lower_plan(plan)
        expected = {'resolver': {'max_bytes': 64*1024**2, 'max_files': 20000, 'timeout_seconds': 300},
                    'replica': {'max_bytes': 32*1024**2, 'max_files': 10000, 'timeout_seconds': 300}}
        import backup_policy
        for guest, limits in expected.items():
            cfg = json.loads(packets[guest]['files']['site.json'])
            job = backup_policy.validate(cfg['app']['backup']['job'])
            self.assertEqual(job['limits'], limits)
            self.assertEqual(job['staging']['size_bytes'], 1024**3)
            self.assertFalse(cfg['guest']['volumes']['backup-stage']['backup'])
            self.assertEqual(job['group']['name'], 'example-recovery')
        schedule = plan.resolved['backup']['group']
        self.assertEqual(schedule['limits'], expected['replica'])
        self.assertEqual(set(schedule['group']['members']), {'guest-610', 'guest-611'})
        self.assertEqual(component_packet.lower_plan(component_plan.resolve(self.root, self.path)), packets)
        disabled = component_plan.resolve(self.root, self.path, ['replica'])
        self.assertEqual(disabled.resolved['guests']['replica']['backup']['job']['limits'], expected['replica'])
        self.assertEqual(disabled.resolved['backup']['group'], schedule)

    def test_actual_client_limit_source_refusals_include_disabled_members_and_four_times_floor(self):
        """Closed overrides and effective volume limits refuse at source resolution."""
        self.path = self.root/'client-limits.yaml'
        self.site = yaml.safe_load(self.path.read_text())
        self.site['guests']['resolver']['backup']['limits']['max_bytes'] = 256*1024**2
        self.plan()
        original = copy.deepcopy(self.site)
        cases = [({'max_bytes': 256*1024**2+1}, 'backup-staging-volume'),
                 ({'timeout_seconds': 300}, 'fields'), (None, 'fields'), ({}, 'backup-client-limits'),
                 ({'max_files': True}, 'integer'), ({'max_bytes': 0}, 'integer')]
        for override, code in cases:
            self.site = copy.deepcopy(original)
            self.site['guests']['resolver']['backup']['limits'] = override
            with self.subTest(override=override), self.assertRaisesRegex(ComponentError, code):
                self.plan(['resolver'])

    def test_documented_mixed_client_cli_commands_compile_the_canonical_source(self):
        """Run the maintained non-native shell example with the selected source interpreter."""
        marker = '<!-- example: backup-client-limits-compile -->\n```bash\n'
        page = (EXAMPLE/'README.md').read_text()
        self.assertEqual(page.count(marker), 1)
        source = page.split(marker, 1)[1].split('\n```', 1)[0]
        outputs = self.root/'cli-output'; outputs.mkdir(mode=0o700)
        commands = self.root/'commands'; commands.mkdir(mode=0o700)
        # Some execution contexts ignore TMPDIR. Delegate to real mktemp with
        # an explicit owned template; the documented compiler commands stay exact.
        temporary = commands/'mktemp'
        temporary.write_text('#!/bin/sh\nexec "$PBS_DOC_REAL_MKTEMP" "$@" "$PBS_DOC_TEST_OUTPUT/packet.XXXXXXXX"\n')
        temporary.chmod(0o700)
        real_mktemp = shutil.which('mktemp')
        self.assertIsNotNone(real_mktemp)
        trace = self.root/'cli-directory.txt'
        source += '\nprintf "%s\\n" "$PBS_LIMITS_WORK" > "$PBS_DOC_TEST_TRACE"\n'
        env = dict(os.environ, PBS_DOC_TEST_OUTPUT=str(outputs), PBS_DOC_REAL_MKTEMP=real_mktemp,
                   PBS_DOC_TEST_TRACE=str(trace),
                   PATH=os.pathsep.join((str(commands), str(Path(sys.executable).parent), os.environ['PATH'])))
        result = subprocess.run(['bash', '-eu'], input=source, text=True, cwd=ROOT,
                                env=env, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'resolver: overridden; replica: inherited; one group and timeout')
        generated = Path(trace.read_text().strip())
        self.assertEqual(generated.resolve(), generated)
        self.assertTrue(generated.is_relative_to(outputs), str(generated))
        self.assertEqual(sorted(path.name for path in generated.iterdir()), ['replica.json', 'resolver.json'])
        for guest, size, files in [('resolver', 64*1024**2, 20000), ('replica', 32*1024**2, 10000)]:
            packet = json.loads((generated/(guest+'.json')).read_text())
            cfg = json.loads(packet['files']['site.json'])
            self.assertEqual(cfg['app']['backup']['job']['limits'],
                             {'max_bytes': size, 'max_files': files, 'timeout_seconds': 300})


if __name__ == '__main__': unittest.main()
