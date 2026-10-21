#!/usr/bin/env python3
"""Behavioural tests against disposable repositories; never push anything."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import source_safety as safety

spec = importlib.util.spec_from_file_location('push_guard', safety.ROOT / '.githooks/push_guard.py')
push = importlib.util.module_from_spec(spec)
spec.loader.exec_module(push)

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='public-guard-test-')
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'fixture')
        self.git('config', 'user.email', '123+fixture@users.noreply.github.com')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('remote', 'add', 'origin', 'https://example.invalid/fixture.git')
        self.scanner = Path(os.environ['GITLEAKS_BIN']).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, name='README.md', text='Public fixture\n'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git('add', '-f', name)
        self.git('commit', '-qm', 'Fixture change')
        return self.git('rev-parse', 'HEAD')

    def check(self, base=''):
        return safety.run(self.root, 'HEAD', base, self.scanner)

    def assert_blocked(self, reason):
        with self.assertRaises(safety.guard.Blocked) as exc:
            self.check()
        self.assertEqual(exc.exception.reason, reason)

    def test_clean_committed_tree_scanned_with_empty_real_diff(self):
        self.commit()
        before = (self.root / '.git/index').read_bytes()
        result = self.check()
        self.assertEqual(result['head_files'], 1)
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_unstaged_content_is_not_substituted_for_commit(self):
        self.commit()
        (self.root / 'README.md').write_text('token = ' + 'ghp_' + 'AbCd1234' * 5 + '\n')
        self.assertEqual(self.check()['status'], 'passed')

    def test_secret_added_then_deleted_still_blocks(self):
        self.commit('settings.txt', 'token = ' + 'ghp_' + 'AbCd1234' * 5 + '\n')
        self.git('rm', '-q', 'settings.txt')
        self.git('commit', '-qm', 'Remove fixture')
        self.assert_blocked('secret_pattern_findings')

    def test_private_path_blocks_and_index_is_preserved(self):
        self.commit('.env', 'SETTING=fixture\n')
        before = (self.root / '.git/index').read_bytes()
        self.assert_blocked('private_file_path')
        self.assertEqual((self.root / '.git/index').read_bytes(), before)

    def test_forced_ignored_file_blocks(self):
        self.commit('.gitignore', 'scratch.txt\n')
        self.commit('scratch.txt', 'fixture\n')
        self.assert_blocked('staged_ignore_rule_excludes_file')

    def test_symlink_blocks(self):
        self.commit()
        (self.root / 'link').symlink_to('README.md')
        self.git('add', 'link'); self.git('commit', '-qm', 'Link fixture')
        self.assert_blocked('symlink_gitlink_or_unsupported_mode')

    def test_binary_blocks(self):
        self.commit()
        (self.root / 'binary.txt').write_bytes(b'\0fixture')
        self.git('add', 'binary.txt'); self.git('commit', '-qm', 'Binary fixture')
        self.assert_blocked('binary_file_requires_separate_review')

    def test_changed_maintainer_email_blocks(self):
        self.git('config', 'user.name', 'theaussiepom')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.commit()
        self.assert_blocked('maintainer_identity_mismatch')

    def test_base_limits_history_but_not_full_head_tree(self):
        base = self.commit('unchanged.txt')
        self.commit('second.txt')
        result = self.check(base)
        self.assertEqual(result['commits_checked'], 1)
        self.assertEqual(result['head_files'], 2)

    def test_invalid_revision_cannot_be_an_option(self):
        self.commit()
        with self.assertRaises(safety.guard.Blocked):
            safety.resolve(self.root, '--help')

    def test_missing_scanner_fails_closed(self):
        self.commit()
        with self.assertRaises(Exception):
            safety.run(self.root, 'HEAD', '', self.root / 'absent-scanner')

    def push_check(self):
        old = os.getcwd()
        try:
            os.chdir(self.root)
            push.START = time.monotonic()
            return push.run('origin', 'refs/heads/main '+self.git('rev-parse', 'HEAD')+' refs/heads/main '+'0'*40+'\n')
        finally:
            os.chdir(old)

    def test_unsigned_outgoing_commit_blocks(self):
        self.commit()
        with self.assertRaises(push.Refused):
            self.push_check()

    def test_personal_committer_email_blocks(self):
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.commit()
        with self.assertRaises(push.Refused) as exc:
            self.push_check()
        self.assertIn('noreply', str(exc.exception))

    def test_signed_outgoing_commit_passes(self):
        key = self.root / '.git/test-signing-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        allowed = self.root / '.git/allowed-signers'
        allowed.write_text('123+fixture@users.noreply.github.com ' + Path(str(key)+'.pub').read_text())
        self.git('config', 'gpg.format', 'ssh')
        self.git('config', 'user.signingkey', str(key))
        self.git('config', 'gpg.ssh.allowedSignersFile', str(allowed))
        self.git('config', 'commit.gpgsign', 'true')
        self.commit()
        self.assertEqual(self.push_check()['commits_checked'], 1)

if __name__ == '__main__':
    unittest.main()
