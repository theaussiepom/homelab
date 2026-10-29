"""Check event selection and real Git changes without network or native hosts."""
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from ci_changes import needs_iso


class ChangeSelectionTests(unittest.TestCase):
    def test_only_relevant_paths_select_iso_and_renames_include_the_old_path(self):
        head, base = 'a' * 40, 'b' * 40
        for event_name, event in [('push', {'before': base}),
                                  ('pull_request', {'pull_request': {'base': {'sha': base}}})]:
            for path in ['proxmox/iso/README.md', '.github/workflows/ci.yml',
                         '.github/scripts/ci_changes.py', '.github/scripts/test_ci_changes.py',
                         'tests/test_boundaries.py']:
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
