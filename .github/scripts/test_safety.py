#!/usr/bin/env python3
"""Behavioural tests against disposable repositories; never push anything."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
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

    def test_public_author_display_name_passes_the_normal_history_scan(self):
        """Scan a real commit with a display-name author and independent committer."""
        with patch.dict(os.environ, {
            'GIT_AUTHOR_NAME': 'Public display name',
            'GIT_AUTHOR_EMAIL': safety.OWN_EMAIL,
        }):
            self.commit()
        self.assertEqual(self.git('show', '-s', '--format=%an'), 'Public display name')
        self.assertEqual(self.git('show', '-s', '--format=%ae'), safety.OWN_EMAIL)
        self.assertEqual(self.git('show', '-s', '--format=%cn'), 'fixture')
        self.assertEqual(self.check()['status'], 'passed')

    def test_base_limits_history_but_not_full_head_tree(self):
        base = self.commit('unchanged.txt')
        self.commit('second.txt')
        result = self.check(base)
        self.assertEqual(result['commits_checked'], 1)
        self.assertEqual(result['head_files'], 2)

    def digest_history(self, text=None):
        """Invented integrity metadata deliberately exercises default rules."""
        text = text or 'key_sha256 = "' + hashlib.sha256(b'synthetic vendor key').hexdigest() + '"\n'
        revision = self.commit('settings.txt', text)
        with self.assertRaises(safety.guard.Blocked) as blocked:
            safety.scan_tree(self.root, revision, self.scanner)
        self.assertEqual(blocked.exception.reason, 'secret_pattern_findings')
        entries = [dict(finding, sha256=hashlib.sha256(text.encode()).hexdigest(),
                        reason='Reviewed synthetic integrity digest')
                   for finding in blocked.exception.findings]
        self.git('rm', '-q', 'settings.txt')
        self.git('commit', '-qm', 'Remove obsolete fixture')
        return entries, text, revision

    def test_committed_head_review_clears_exact_historical_finding_without_index_changes(self):
        entries, _, _ = self.digest_history()
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries))
        before = (self.root / '.git/index').read_bytes()
        self.assertEqual(self.check()['status'], 'passed')
        self.assertEqual((self.root / '.git/index').read_bytes(), before)

    def test_historical_review_does_not_approve_changed_file_bytes(self):
        entries, text, _ = self.digest_history()
        self.commit('settings.txt', text + '# changed bytes\n')
        self.git('rm', '-q', 'settings.txt')
        self.git('commit', '-qm', 'Remove changed fixture')
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries))
        self.assert_blocked('secret_pattern_findings')

    def test_historical_review_does_not_approve_other_findings_in_same_file(self):
        text = ''.join('key_sha256 = "' + hashlib.sha256(label).hexdigest() + '"\n'
                       for label in (b'first synthetic key', b'second synthetic key'))
        entries, _, _ = self.digest_history(text)
        self.assertGreater(len(entries), 1)
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries[:1]))
        self.assert_blocked('secret_pattern_findings')

    def test_real_transient_secret_still_blocks_with_unrelated_digest_review(self):
        entries, _, _ = self.digest_history()
        self.commit('transient.txt', 'token = ' + 'ghp_' + 'AbCd1234' * 5 + '\n')
        self.git('rm', '-q', 'transient.txt')
        self.git('commit', '-qm', 'Remove transient fixture')
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries))
        self.assert_blocked('secret_pattern_findings')

    def test_uncommitted_head_review_is_never_used(self):
        entries, _, _ = self.digest_history()
        self.commit(safety.guard.REVIEW_FILE, '[]')
        (self.root / safety.guard.REVIEW_FILE).write_text(json.dumps(entries))
        self.git('add', safety.guard.REVIEW_FILE)
        self.assert_blocked('secret_pattern_findings')

    def test_malformed_committed_review_and_historical_review_both_block(self):
        self.commit()
        valid_head = self.git('rev-parse', 'HEAD')
        for text in ('{}', '[{}]', '[', '[null]', ''):
            with self.subTest(text=text):
                self.commit(safety.guard.REVIEW_FILE, text)
                with self.assertRaises(safety.guard.Blocked):
                    self.check(valid_head)
        # A later valid head manifest must not replace malformed old policy.
        self.commit(safety.guard.REVIEW_FILE, '[]')
        with self.assertRaises(safety.guard.Blocked):
            self.check(valid_head)

    def test_historical_manifest_content_is_still_secret_scanned(self):
        entry = {'path': 'fixture.txt', 'sha256': 'a' * 64,
                 'rule': 'synthetic', 'line': 1,
                 'reason': 'token = ' + 'ghp_' + 'AbCd1234' * 5}
        self.commit(safety.guard.REVIEW_FILE, json.dumps([entry]))
        self.commit(safety.guard.REVIEW_FILE, '[]')
        self.assert_blocked('secret_pattern_findings')

    def test_historical_ignore_policy_is_not_replaced_by_head_policy(self):
        self.commit('.gitignore', 'blocked.txt\n')
        self.commit('blocked.txt', 'ordinary fixture\n')
        self.git('rm', '-q', 'blocked.txt')
        self.commit('.gitignore', '')
        self.assert_blocked('staged_ignore_rule_excludes_file')

    def test_combined_review_manifest_limit_is_not_doubled(self):
        def entries(prefix):
            return [{'path': prefix + str(i), 'sha256': 'a' * 64,
                     'rule': 'synthetic', 'line': 1, 'reason': 'Synthetic review'}
                    for i in range(100)]
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries('old')))
        self.commit(safety.guard.REVIEW_FILE, json.dumps(entries('new')))
        self.assert_blocked('invalid_reviewed_findings')

    def test_head_manifest_symlink_and_oversize_are_refused(self):
        self.commit()
        (self.root / '.githooks').mkdir()
        (self.root / safety.guard.REVIEW_FILE).symlink_to('../README.md')
        self.git('add', safety.guard.REVIEW_FILE)
        self.git('commit', '-qm', 'Synthetic linked policy')
        self.assert_blocked('unsupported_policy_file_mode')
        self.git('rm', '-q', safety.guard.REVIEW_FILE)
        self.commit(safety.guard.REVIEW_FILE, ' ' * (safety.guard.MAX_FILE_BYTES + 1))
        self.assert_blocked('file_size_limit')

    def test_additional_review_bytes_count_towards_the_existing_total_limit(self):
        for number in range(8):
            (self.root / f'bounded-{number}.txt').write_bytes(b'x' * safety.guard.MAX_FILE_BYTES)
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic maximum-sized snapshot')
        historical = self.git('rev-parse', 'HEAD')
        head = self.commit(safety.guard.REVIEW_FILE, '[]')
        with self.assertRaises(safety.guard.Blocked) as blocked:
            safety.scan_tree(self.root, historical, self.scanner, review_head=head)
        self.assertEqual(blocked.exception.reason, 'total_size_limit')

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
