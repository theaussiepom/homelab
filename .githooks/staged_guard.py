#!/usr/bin/env python3
"""Offline, bounded checks of changed Git index blobs. Never print source values."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time

VERSION = '8.30.1'
MAX_SECONDS = 5.0
MAX_FILES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
REVIEW_FILE = '.githooks/reviewed-findings.json'
PRIVATE_DIRS = {'.ssh', '.gnupg', '.storage', '.homelab-private', '.runtime-env',
                'node_modules', '__pycache__', '.venv', 'backups', '.backups'}
PRIVATE_NAMES = {'.gitleaksignore', 'secrets.yaml', 'secrets.yml', 'secret.yaml', 'secret.yml', 'auth.json',
                 'flows_cred.json', 'acme.json', 'config.secret.inc.php', 'dump.rdb'}
OPAQUE_SUFFIXES = {'.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.tar', '.rar',
                   '.png', '.jpg', '.jpeg', '.gif', '.webp', '.pdf', '.woff', '.woff2'}


class Blocked(Exception):
    def __init__(self, reason, findings=None):
        self.reason, self.findings = reason, findings or []


def path_ok(path):
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and str(p) == path and not any(
        part in {'.', '..', '.git'} for part in p.parts)


def private_path(path):
    p = PurePosixPath(path)
    name = p.name.lower()
    if any(part.lower() in PRIVATE_DIRS for part in p.parts[:-1]):
        return True
    example = name.endswith(('.example', '.sample', '.template', '.j2'))
    if name in PRIVATE_NAMES or name.startswith(('id_rsa', 'id_ed25519')):
        return True
    if not example and (name == '.env' or name.startswith('.env.') or '.env' in p.suffixes
                        or '.private.' in name):
        return True
    return bool(re.search(r'\.(?:pem|key|p12|pfx|db|sqlite\d*)(?:$|-)|\.tfstate(?:\.|$)|\.tfplan$', name))


class Check:
    def __init__(self):
        self.started = time.monotonic()
        self.root = None
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1')

    def run(self, argv, data=None, cwd=None, env=None, allowed=(0,)):
        remaining = MAX_SECONDS - (time.monotonic() - self.started)
        if remaining <= 0:
            raise Blocked('time_budget_exceeded')
        try:
            result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, cwd=cwd, env=env or self.env,
                                    timeout=remaining, check=False)
        except subprocess.TimeoutExpired:
            raise Blocked('time_budget_exceeded') from None
        if result.returncode not in allowed:
            raise Blocked('command_failed')
        return result

    def git(self, *args, **kwargs):
        return self.run(['git', *args], cwd=self.root, **kwargs)

    def index_bytes(self):
        path = Path(os.fsdecode(self.git('rev-parse', '--git-path', 'index').stdout.strip()))
        if not path.is_absolute():
            path = self.root / path
        return path.read_bytes() if path.exists() else b''

    def read_blobs(self, entries):
        oids = list(dict.fromkeys(oid for _, oid in entries.values()))
        if not oids:
            return {}
        query = ''.join(oid + '\n' for oid in oids).encode()
        headers = self.git('cat-file', '--batch-check', data=query).stdout.splitlines()
        if len(headers) != len(oids):
            raise Blocked('invalid_object_headers')
        sizes = {}
        for oid, header in zip(oids, headers):
            fields = header.decode('ascii').split()
            if len(fields) != 3 or fields[:2] != [oid, 'blob']:
                raise Blocked('non_blob_object')
            sizes[oid] = int(fields[2])
            if sizes[oid] > MAX_FILE_BYTES:
                raise Blocked('file_size_limit')
        if sum(sizes[oid] for _, oid in entries.values()) > MAX_TOTAL_BYTES:
            raise Blocked('total_size_limit')
        data = self.git('cat-file', '--batch', data=query).stdout
        offset, blobs = 0, {}
        for oid in oids:
            end = data.index(b'\n', offset)
            if data[offset:end] != f'{oid} blob {sizes[oid]}'.encode():
                raise Blocked('invalid_blob_header')
            offset = end + 1
            blobs[oid] = data[offset:offset + sizes[oid]]
            offset += sizes[oid]
            if data[offset:offset + 1] != b'\n':
                raise Blocked('invalid_blob_length')
            offset += 1
        if offset != len(data):
            raise Blocked('unexpected_blob_output')
        return {path: blobs[oid] for path, (_, oid) in entries.items()}

    def scan(self):
        self.root = Path(os.fsdecode(self.git('rev-parse', '--show-toplevel').stdout.strip()))
        before = self.index_bytes()
        raw = self.git('ls-files', '--stage', '-z').stdout
        index = {}
        for row in raw.split(b'\0'):
            if not row:
                continue
            header, name = row.split(b'\t', 1)
            mode, oid, stage = header.decode('ascii').split()
            if stage != '0':
                raise Blocked('unmerged_index')
            path = name.decode('utf-8')
            if not path_ok(path):
                raise Blocked('unsafe_index_path')
            index[path] = (mode, oid)
        changed = [x.decode('utf-8') for x in self.git(
            'diff', '--cached', '--name-only', '--no-renames', '--diff-filter=ACMRT', '-z',
            '--no-ext-diff').stdout.split(b'\0') if x]
        if len(changed) > MAX_FILES:
            raise Blocked('file_count_limit')
        if not changed:
            if self.index_bytes() != before:
                raise Blocked('index_changed_during_check')
            return {'status': 'passed', 'scanned_files': 0, 'scanned_bytes': 0, 'reviewed_findings': 0}

        policy = {REVIEW_FILE} & index.keys()
        for name in changed:
            if name not in index or index[name][0] not in ('100644', '100755'):
                raise Blocked('symlink_gitlink_or_unsupported_mode', [{'path': name}])
            if private_path(name):
                raise Blocked('private_file_path', [{'path': name}])
            if PurePosixPath(name).suffix.lower() in OPAQUE_SUFFIXES:
                raise Blocked('opaque_file_requires_separate_review', [{'path': name}])
            for parent in PurePosixPath(name).parents:
                ignore = str(parent / '.gitignore')
                if ignore in index:
                    policy.add(ignore)
        for name in policy:
            if index[name][0] not in ('100644', '100755'):
                raise Blocked('unsupported_policy_file_mode', [{'path': name}])
        blobs = self.read_blobs({name: index[name] for name in set(changed) | policy})
        for name, value in blobs.items():
            if b'\0' in value:
                raise Blocked('binary_file_requires_separate_review', [{'path': name}])
            try:
                value.decode('utf-8')
            except UnicodeError:
                raise Blocked('non_utf8_file_requires_separate_review', [{'path': name}]) from None

        reviewed = set()
        if REVIEW_FILE in blobs:
            entries = json.loads(blobs[REVIEW_FILE])
            if not isinstance(entries, list) or len(entries) > 100:
                raise Blocked('invalid_reviewed_findings')
            for item in entries:
                if (not isinstance(item, dict) or set(item) != {'path', 'sha256', 'rule', 'line', 'reason'}
                        or not isinstance(item['path'], str) or not path_ok(item['path'])
                        or not isinstance(item['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', item['sha256'])
                        or not isinstance(item['rule'], str) or not item['rule']
                        or type(item['line']) is not int or item['line'] < 1
                        or not isinstance(item['reason'], str) or not item['reason'].strip()):
                    raise Blocked('invalid_reviewed_findings')
                reviewed.add((item['path'], item['sha256'], item['rule'], item['line']))

        configured = self.git('config', '--get', 'hooks.gitleaksPath', allowed=(0, 1)).stdout.strip()
        scanner = os.environ.get('GITLEAKS_BIN') or os.fsdecode(configured) or shutil.which('gitleaks')
        if not scanner:
            raise Blocked('gitleaks_not_installed')
        version = self.run([scanner, 'version']).stdout.decode('ascii').strip().removeprefix('v')
        if version != VERSION:
            raise Blocked('gitleaks_version_mismatch')

        with tempfile.TemporaryDirectory(prefix='staged-guard-') as tmp:
            scratch = Path(tmp)
            content = scratch / 'content'
            content.mkdir(mode=0o700)
            for name in set(changed) | {p for p in policy if p.endswith('.gitignore')}:
                dest = content / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(blobs[name])
                dest.chmod(0o600)
            ignore_git = scratch / 'ignore.git'
            self.run(['git', 'init', '--bare', '-q', str(ignore_git)])
            ignored = self.run(['git', '-c', 'core.excludesFile=/dev/null',
                                '--git-dir=' + str(ignore_git), '--work-tree=' + str(content),
                                'check-ignore', '--no-index', '--stdin', '-z'],
                               data=b''.join(name.encode() + b'\0' for name in changed), allowed=(0, 1))
            if ignored.stdout:
                raise Blocked('staged_ignore_rule_excludes_file',
                              [{'path': x.decode('utf-8')} for x in ignored.stdout.split(b'\0') if x])
            # Policy-only ignore files need not be scanned as changed content.
            for name in policy - set(changed):
                if name.endswith('.gitignore'):
                    (content / name).unlink()
            config = scratch / 'default-rules.toml'
            config.write_text('[extend]\nuseDefault = true\n')
            no_ignores = scratch / 'no-ignored-findings'
            no_ignores.write_text('')
            report = scratch / 'findings.json'
            scanner_env = {k: v for k, v in self.env.items() if not k.startswith('GITLEAKS_')}
            result = self.run([scanner, 'dir', str(content), '--config', str(config),
                               '--gitleaks-ignore-path', str(no_ignores), '--ignore-gitleaks-allow',
                               '--no-banner', '--no-color', '--redact=100', '--log-level', 'error',
                               '--report-format', 'json', '--report-path', str(report)],
                              cwd=scratch, env=scanner_env, allowed=(0, 1))
            if not report.is_file():
                raise Blocked('scanner_report_missing')
            findings = json.loads(report.read_bytes())
            if not isinstance(findings, list) or (result.returncode == 1 and not findings):
                raise Blocked('scanner_report_invalid')
            blocked, approved = [], 0
            for item in findings:
                p = Path(item['File'])
                if p.is_absolute():
                    p = p.relative_to(content)
                name = p.as_posix()
                if name not in changed:
                    raise Blocked('scanner_report_unexpected_path')
                key = (name, hashlib.sha256(blobs[name]).hexdigest(), item['RuleID'], item['StartLine'])
                if key in reviewed:
                    approved += 1
                else:
                    blocked.append({'path': name, 'rule': item['RuleID'], 'line': item['StartLine']})
            if blocked:
                raise Blocked('secret_pattern_findings', blocked)
        if self.index_bytes() != before:
            raise Blocked('index_changed_during_check')
        if time.monotonic() - self.started > MAX_SECONDS:
            raise Blocked('time_budget_exceeded')
        return {'status': 'passed', 'scanned_files': len(changed),
                'scanned_bytes': sum(len(blobs[p]) for p in changed), 'reviewed_findings': approved}


def main():
    check = Check()
    try:
        result = check.scan()
        code = 0
    except Blocked as exc:
        result = {'status': 'blocked', 'reason': exc.reason, 'findings': exc.findings}
        code = 1
    except Exception as exc:
        result = {'status': 'blocked', 'reason': 'check_error', 'error_type': type(exc).__name__}
        code = 2
    result['elapsed_seconds'] = round(time.monotonic() - check.started, 3)
    print(json.dumps(result, ensure_ascii=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
