"""Real Git index and scanner tests; every credential-shaped value is synthetic."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

GUARD = Path(__file__).with_name('staged_guard.py')
SCANNER = os.environ.get('GITLEAKS_BIN') or shutil.which('gitleaks')


@unittest.skipUnless(SCANNER, 'Set GITLEAKS_BIN to the installed Gitleaks 8.30.1 binary')
class StagedGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='guard-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env['GITLEAKS_BIN'] = SCANNER
        self.git('init', '-q', '-b', 'fixture')
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'core.excludesFile', '/dev/null')
        self.git('config', 'core.hooksPath', '/dev/null')

    def git(self, *args, data=None):
        return subprocess.run(['git', '-C', str(self.root), *args], input=data,
                              capture_output=True, check=True, env=self.env).stdout

    def write(self, name, value, stage=True):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(value.encode() if isinstance(value, str) else value)
        if stage:
            self.git('add', '-f', '--', name)
        return p

    def token(self):
        return 'gh' + 'p_' + hashlib.sha1(b'synthetic-staged-guard-fixture').hexdigest()

    def check_guard(self, expected=0, env=None):
        r = subprocess.run([sys.executable, str(GUARD)], cwd=self.root,
                           env=env or self.env, capture_output=True, timeout=8)
        result = json.loads(r.stdout)
        self.assertEqual(r.returncode, expected, result)
        self.assertNotIn(self.token().encode(), r.stdout + r.stderr)
        return result

    def baseline(self):
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'Synthetic fixture baseline')

    def fake_scanner(self, body, version='8.30.1'):
        p = Path(self.temp.name) / 'scanner'
        p.write_text('#!' + sys.executable + '\nimport sys,json,time,os,subprocess\n'
                     + f'if sys.argv[1] == "version":\n print({version!r});sys.exit(0)\n' + body)
        p.chmod(0o700)
        return dict(self.env, GITLEAKS_BIN=str(p))

    def test_empty_index_needs_no_scanner(self):
        self.check_guard(env=dict(self.env, GITLEAKS_BIN='/absent/scanner'))

    def test_safe_initial_commit(self):
        self.write('config.yaml', 'enabled: true\n')
        self.assertEqual(self.check_guard()['scanned_files'], 1)

    def test_private_env_forced_into_index(self):
        self.write('.env', 'SETTING=anything\n')
        self.assertEqual(self.check_guard(1)['reason'], 'private_file_path')

    def test_nested_secret_filename(self):
        self.write('ha/config/secrets.yaml', 'a: b\n')
        self.assertEqual(self.check_guard(1)['reason'], 'private_file_path')

    def test_runtime_storage_is_private(self):
        self.write('ha/.storage/core.config', '{}')
        self.assertEqual(self.check_guard(1)['reason'], 'private_file_path')

    def test_env_example_is_allowed_but_scanned(self):
        self.write('compose/.env.example', 'API_TOKEN=\n')
        self.check_guard()
        self.write('compose/.env.example', 'API_TOKEN=' + self.token() + '\n')
        self.assertEqual(self.check_guard(1)['reason'], 'secret_pattern_findings')

    def test_staged_token_is_detected_without_emitting_it(self):
        self.write('config.yaml', 'token: ' + self.token() + '\n')
        self.assertTrue(self.check_guard(1)['findings'])

    def test_private_key_in_ordinary_file_is_detected(self):
        header = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
        footer = '-----END ' + 'RSA PRIVATE KEY-----'
        self.write('ordinary.txt', header + '\n' + ('QWxwaGFCZXRhR2FtbWE=' * 8) + '\n' + footer)
        self.assertEqual(self.check_guard(1)['reason'], 'secret_pattern_findings')

    def test_unstaged_cleanup_cannot_hide_staged_secret(self):
        p = self.write('config.yaml', 'token: ' + self.token() + '\n')
        p.write_text('token: ""\n')
        self.check_guard(1)

    def test_unstaged_secret_does_not_change_safe_staged_bytes(self):
        p = self.write('config.yaml', 'token: ""\n')
        p.write_text('token: ' + self.token() + '\n')
        self.check_guard()

    def test_untracked_secret_is_not_scanned(self):
        self.write('README.md', 'Safe change\n')
        self.write('private.txt', self.token(), stage=False)
        self.assertEqual(self.check_guard()['scanned_files'], 1)

    def test_unchanged_tracked_files_are_not_rescanned(self):
        self.write('old.txt', self.token())
        self.baseline()
        self.write('README.md', 'Only this file changed\n')
        self.assertEqual(self.check_guard()['scanned_files'], 1)

    def test_deletion_only_needs_no_scanner(self):
        self.write('old.txt', self.token())
        self.baseline()
        self.git('rm', 'old.txt')
        self.assertEqual(self.check_guard(env=dict(self.env, GITLEAKS_BIN='/absent'))['scanned_files'], 0)

    def test_renamed_secret_is_checked(self):
        self.write('old.txt', self.token())
        self.baseline()
        self.git('mv', 'old.txt', 'new.txt')
        self.check_guard(1)

    def test_staged_ignore_rule_applies_to_force_added_file(self):
        self.write('.gitignore', 'internal/\n')
        self.write('internal/info.txt', 'ordinary content\n')
        self.assertEqual(self.check_guard(1)['reason'], 'staged_ignore_rule_excludes_file')

    def test_unstaged_ignore_removal_cannot_bypass_staged_policy(self):
        p = self.write('.gitignore', 'internal/\n')
        p.write_text('')
        self.write('internal/info.txt', 'ordinary content\n')
        self.assertEqual(self.check_guard(1)['reason'], 'staged_ignore_rule_excludes_file')

    def test_unstaged_ignore_addition_does_not_change_staged_policy(self):
        p = self.write('.gitignore', '')
        self.baseline()
        p.write_text('README.md\n')
        self.write('README.md', 'safe\n')
        self.check_guard()

    def test_nested_staged_ignore_rule(self):
        self.write('docs/.gitignore', 'draft.txt\n')
        self.write('docs/draft.txt', 'safe\n')
        self.assertEqual(self.check_guard(1)['reason'], 'staged_ignore_rule_excludes_file')

    def test_spaces_unicode_and_newline_paths(self):
        self.write('docs/odd name café\nnotes.md', 'safe\n')
        self.check_guard()

    def test_symlink_not_followed(self):
        target = Path(self.temp.name) / 'private-outside-repo'
        target.write_text(self.token())
        (self.root / 'link').symlink_to(target)
        self.git('add', 'link')
        self.assertEqual(self.check_guard(1)['reason'], 'symlink_gitlink_or_unsupported_mode')

    def test_gitlink_not_accepted(self):
        self.write('README.md', 'safe\n')
        self.baseline()
        head = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + head + ',submodule')
        self.assertEqual(self.check_guard(1)['reason'], 'symlink_gitlink_or_unsupported_mode')

    def test_unmerged_index(self):
        oid = self.git('hash-object', '-w', '--stdin', data=b'safe').decode().strip()
        self.git('update-index', '--index-info', data=(f'100644 {oid} 1\tconflict\n100644 {oid} 2\tconflict\n').encode())
        self.assertEqual(self.check_guard(1)['reason'], 'unmerged_index')

    def test_binary_content_blocked(self):
        self.write('opaque.dat', b'hello\0world')
        self.assertEqual(self.check_guard(1)['reason'], 'binary_file_requires_separate_review')

    def test_invalid_utf8_blocked(self):
        self.write('opaque.dat', b'\xff\xfe')
        self.assertEqual(self.check_guard(1)['reason'], 'non_utf8_file_requires_separate_review')

    def test_archive_blocked_even_with_text_bytes(self):
        self.write('payload.zip', b'pretend archive')
        self.assertEqual(self.check_guard(1)['reason'], 'opaque_file_requires_separate_review')

    def test_large_file_refused_before_scanner(self):
        self.write('large.txt', b'x' * (2 * 1024 * 1024 + 1))
        self.assertEqual(self.check_guard(1)['reason'], 'file_size_limit')

    def test_total_bytes_limit(self):
        for i in range(9):
            self.write(f'large-{i}.txt', b'x' * (2 * 1024 * 1024))
        self.assertEqual(self.check_guard(1)['reason'], 'total_size_limit')

    def test_file_count_limit(self):
        for i in range(2001):
            self.write(f'files/{i}.txt', 'safe\n', stage=False)
        self.git('add', 'files')
        self.assertEqual(self.check_guard(1)['reason'], 'file_count_limit')

    def test_hardcoded_high_entropy_password_is_detected(self):
        value = hashlib.sha256(b'synthetic-password-fixture').hexdigest()
        self.write('config.py', 'password = "' + value + '"\n')
        self.assertEqual(self.check_guard(1)['reason'], 'secret_pattern_findings')

    def test_reviewed_false_positive_is_exact_to_file_hash_rule_line(self):
        data = 'token: ' + self.token() + '\n'
        self.write('fixture.txt', data)
        findings = self.check_guard(1)['findings']
        self.write('.githooks/reviewed-findings.json', json.dumps([dict(
            finding, sha256=hashlib.sha256(data.encode()).hexdigest(), reason='Synthetic fixture only')
            for finding in findings]))
        self.assertEqual(self.check_guard()['reviewed_findings'], len(findings))
        self.write('fixture.txt', data + '# changed content requires fresh review\n')
        self.assertEqual(self.check_guard(1)['reason'], 'secret_pattern_findings')

    def test_exception_for_one_rule_does_not_suppress_other_rules(self):
        data = 'token: ' + self.token() + '\n'
        self.write('fixture.txt', data)
        findings = self.check_guard(1)['findings']
        self.assertGreater(len(findings), 1)
        self.write('.githooks/reviewed-findings.json', json.dumps([dict(
            findings[0], sha256=hashlib.sha256(data.encode()).hexdigest(), reason='Synthetic fixture only')]))
        self.assertEqual(self.check_guard(1)['reason'], 'secret_pattern_findings')

    def test_unstaged_exception_cannot_suppress_finding(self):
        data = 'token: ' + self.token() + '\n'
        self.write('fixture.txt', data)
        finding = self.check_guard(1)['findings'][0]
        self.write('.githooks/reviewed-findings.json', json.dumps([dict(
            finding, sha256=hashlib.sha256(data.encode()).hexdigest(), reason='Synthetic')]), stage=False)
        self.check_guard(1)

    def test_inline_allow_cannot_suppress_finding(self):
        self.write('fixture.txt', 'token: ' + self.token() + ' # gitleaks:allow\n')
        self.check_guard(1)

    def test_external_scanner_config_cannot_disable_rules(self):
        self.write('fixture.txt', 'token: ' + self.token() + '\n')
        self.check_guard(1, env=dict(self.env, GITLEAKS_CONFIG_TOML='[allowlist]\npaths=[".*"]\n'))

    def test_missing_scanner_blocks(self):
        self.write('safe.txt', 'safe\n')
        self.assertEqual(self.check_guard(2, env=dict(self.env, GITLEAKS_BIN='/absent'))['reason'], 'check_error')

    def test_wrong_scanner_version_blocks(self):
        self.write('safe.txt', 'safe\n')
        self.assertEqual(self.check_guard(1, env=self.fake_scanner('', '0.0.0'))['reason'], 'gitleaks_version_mismatch')

    def test_scanner_crash_blocks_without_raw_stderr(self):
        self.write('safe.txt', 'safe\n')
        env = self.fake_scanner('print("PRIVATE RAW DIAGNOSTIC",file=sys.stderr)\nsys.exit(2)\n')
        self.assertEqual(self.check_guard(1, env=env)['reason'], 'command_failed')

    def test_scanner_missing_report_blocks(self):
        self.write('safe.txt', 'safe\n')
        self.assertEqual(self.check_guard(1, env=self.fake_scanner('sys.exit(0)\n'))['reason'], 'scanner_report_missing')

    def test_five_second_budget_is_enforced(self):
        self.write('safe.txt', 'safe\n')
        before = time.perf_counter()
        self.assertEqual(self.check_guard(1, env=self.fake_scanner('time.sleep(20)\n'))['reason'], 'time_budget_exceeded')
        self.assertLess(time.perf_counter() - before, 6.5)

    def test_index_mutation_during_scan_blocks(self):
        self.write('safe.txt', 'safe\n')
        body = ('root=os.environ["FIXTURE_ROOT"]\n'
                'oid=subprocess.check_output(["git","-C",root,"hash-object","-w","--stdin"],input=b"changed").decode().strip()\n'
                'subprocess.run(["git","-C",root,"update-index","--add","--cacheinfo","100644,"+oid+",later.txt"],check=True)\n'
                'report=sys.argv[sys.argv.index("--report-path")+1]\n'
                'open(report,"w").write("[]")\n')
        env = dict(self.fake_scanner(body), FIXTURE_ROOT=str(self.root))
        self.assertEqual(self.check_guard(1, env=env)['reason'], 'index_changed_during_check')

    def test_index_and_worktree_are_unchanged_by_successful_check(self):
        p = self.write('safe.txt', 'safe\n')
        index = self.root / '.git/index'
        before = (index.read_bytes(), p.read_bytes())
        self.check_guard()
        self.assertEqual(before, (index.read_bytes(), p.read_bytes()))

    def test_actual_hook_blocks_commit_then_allows_clean_commit(self):
        hooks = self.root / '.githooks'
        hooks.mkdir()
        shutil.copyfile(GUARD, hooks / 'staged_guard.py')
        shutil.copyfile(GUARD.with_name('pre-commit'), hooks / 'pre-commit')
        (hooks / 'pre-commit').chmod(0o755)
        self.git('config', 'core.hooksPath', '.githooks')
        self.write('config.yaml', 'token: ' + self.token() + '\n')
        r = subprocess.run(['git', '-C', str(self.root), 'commit', '-qm', 'Synthetic blocked commit'],
                           capture_output=True, env=self.env)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn(self.token().encode(), r.stdout + r.stderr)
        self.write('config.yaml', 'token: ""\n')
        self.git('commit', '-qm', 'Synthetic clean commit')
        self.assertTrue(self.git('rev-parse', '--verify', 'HEAD').strip())


if __name__ == '__main__':
    unittest.main(verbosity=2)
