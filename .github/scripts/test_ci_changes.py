"""Check event selection and real Git changes without network or native hosts."""
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from ci_changes import needs_iso


class ChangeSelectionTests(unittest.TestCase):
    def test_coverage_failure_stdout_is_bounded_selective_and_keeps_exit_status(self):
        workflow = (Path(__file__).resolve().parents[1] / 'workflows/ci.yml').read_text()
        marker = '      - name: Measure all current framework Python code\n'
        self.assertEqual(workflow.count(marker), 1)
        # Read this fixed literal shell block without adding a YAML dependency
        # to the deliberately standard-library-only source-safety job.
        block = workflow.split(marker, 1)[1].split('        run: |\n', 1)[1]
        lines = []
        for line in block.splitlines():
            if not line.startswith('          '):
                break
            lines.append(line[10:])
        script = '\n'.join(lines) + '\n'
        self.assertIn('exit "$coverage_status"', script)
        for status, summary in [(0, True), (7, True), (9, False)]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root / 'tools').mkdir()
                fixture = '''import json,sys
from pathlib import Path
p=Path(sys.argv[-1]);p.mkdir(parents=True)
(p/'bootstrap.txt').write_text('OLDEST_LOG_MUST_BE_TRUNCATED'+'x'*20000+'\\nEXPECTED_FAILURE_DETAIL\\n::warning::UNTRUSTED_TEST_TEXT')
(p/'applications.txt').write_text('PASSED_SUITE_MUST_NOT_BE_PRINTED')
if SUMMARY:
 (p/'summary.json').write_text(json.dumps({'suites':[{'suite':'bootstrap','exit_code':STATUS},{'suite':'applications','exit_code':0},{'suite':'../outside','exit_code':1}]}))
raise SystemExit(STATUS)
'''.replace('SUMMARY', repr(summary)).replace('STATUS', repr(status))
                (root / 'tools/measure_coverage.py').write_text(fixture)
                (root / 'bin').mkdir()
                (root / 'bin/python').symlink_to(sys.executable)
                environment = dict(os.environ, RUNNER_TEMP=str(root / 'runner'),
                                   PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=root,
                                        env=environment, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertNotIn('PASSED_SUITE_MUST_NOT_BE_PRINTED', result.stdout)
                self.assertNotIn('OLDEST_LOG_MUST_BE_TRUNCATED', result.stdout)
                self.assertNotIn('outside failure details', result.stdout)
                if status == 7:
                    self.assertIn('EXPECTED_FAILURE_DETAIL', result.stdout)
                    self.assertIn('::stop-commands::', result.stdout)
                    self.assertLess(len(result.stdout), 17000)
                elif status == 0:
                    self.assertEqual(result.stdout, '')
                else:
                    self.assertIn('Per-suite failure diagnostics unavailable', result.stdout)

    def test_only_relevant_paths_select_iso_and_renames_include_the_old_path(self):
        head, base = 'a' * 40, 'b' * 40
        for event_name, event in [('push', {'before': base}),
                                  ('pull_request', {'pull_request': {'base': {'sha': base}}})]:
            for path in ['proxmox/iso/README.md', 'proxmox/iso/scripts/installer_ci.py',
                         'proxmox/iso/tests/test_installer_ci.py', '.github/workflows/ci.yml',
                         '.github/scripts/ci_changes.py', '.github/scripts/test_ci_changes.py',
                         'tests/test_boundaries.py', '.github/workflows/installer-disk-safety.yml',
                         '.github/workflows/installer-config-validation.yml']:
                git = Mock(return_value=(path + '\0').encode())
                self.assertTrue(needs_iso(event_name, event, head, git))
                self.assertIn('--no-renames', git.call_args.args[0])
            self.assertFalse(needs_iso(event_name, event, head, Mock(return_value=b'proxmox/applications/render.py\0')))

    def test_missing_invalid_or_unavailable_history_keeps_iso_coverage(self):
        for base in ['', '0' * 40, '--help', None, 12]:
            git = Mock()
            self.assertTrue(needs_iso('push', {'before': base}, 'a' * 40, git))
            git.assert_not_called()
        git = Mock(side_effect=subprocess.CalledProcessError(128, ['git']))
        self.assertTrue(needs_iso('push', {'before': 'b' * 40}, 'a' * 40, git))

    def test_schedule_and_manual_entry_keep_the_original_purposes(self):
        git = Mock()
        self.assertFalse(needs_iso('schedule', {}, 'a' * 40, git))
        self.assertTrue(needs_iso('workflow_dispatch', {}, 'a' * 40, git))
        git.assert_not_called()
        with self.assertRaises(ValueError):
            needs_iso('pull_request_target', {}, 'a' * 40, git)

    def test_real_git_rename_out_of_iso_still_runs_iso_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            git('config', 'commit.gpgsign', 'false')
            (root / 'proxmox/iso').mkdir(parents=True)
            (root / 'proxmox/iso/example.txt').write_text('fixture\n')
            git('add', '.')
            git('commit', '-qm', 'Initial fixture')
            base = git('rev-parse', 'HEAD')
            git('mv', 'proxmox/iso/example.txt', 'example.txt')
            git('commit', '-qm', 'Move fixture')
            head = git('rev-parse', 'HEAD')
            def run(argv, **kwargs):
                return subprocess.check_output(argv, cwd=directory, **kwargs)
            self.assertTrue(needs_iso('push', {'before': base}, head, run))


if __name__ == '__main__':
    unittest.main()
