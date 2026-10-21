#!/usr/bin/env python3
"""Scan committed trees and new history, independently of the real Git index.

No production inputs or credentials are used. Scanner reports never print values.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('staged_guard', ROOT / '.githooks/staged_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
MAX_COMMITS = 200
OWN_NAME = 'theaussiepom'
OWN_EMAIL = '53800477+theaussiepom@users.noreply.github.com'

def git(root, *args, env=None):
    r = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                       env=env, timeout=15)
    if r.returncode:
        raise guard.Blocked('git_operation_failed')
    return r.stdout

def resolve(root, ref):
    if ref != 'HEAD' and not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', ref):
        raise guard.Blocked('invalid_revision')
    return git(root, 'rev-parse', '--verify', ref + '^{commit}').decode().strip()

def check_identity(root, rev):
    fields = git(root, 'show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce%x00%B', rev).decode().split('\0', 4)
    if len(fields) != 5:
        raise guard.Blocked('invalid_commit_metadata')
    for name, email in [fields[:2], fields[2:4]]:
        if ((name.casefold() == OWN_NAME and email != OWN_EMAIL)
                or (email == OWN_EMAIL and name != OWN_NAME)):
            raise guard.Blocked('maintainer_identity_mismatch')
    for line in fields[4].splitlines():
        if re.match(r'(?i)(co-authored-by|signed-off-by):\s*theaussiepom\s*<', line):
            if '<' + OWN_EMAIL + '>' not in line:
                raise guard.Blocked('maintainer_trailer_email_mismatch')

def scan_tree(root, rev, scanner):
    objects = Path(os.fsdecode(git(root, 'rev-parse', '--git-path', 'objects').strip()))
    if not objects.is_absolute():
        objects = (Path(root) / objects).resolve()
    # A separate, unborn index makes every tracked file a staged addition. The
    # real checkout/index/HEAD are never rewritten, including on scan failure.
    with tempfile.TemporaryDirectory(prefix='public-source-check-') as temp:
        scratch = Path(temp)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'GITLEAKS_'))}
        subprocess.run(['git', 'init', '-q', str(scratch)], check=True,
                       capture_output=True, env=env)
        # Use a local object alternate rather than GIT_DIR/WORK_TREE variables:
        # the staged guard also creates its own temporary ignore-check repository.
        (scratch / '.git/objects/info/alternates').write_text(str(objects) + '\n')
        env.update(GIT_NO_REPLACE_OBJECTS='1', GITLEAKS_BIN=str(scanner))
        git(scratch, 'read-tree', rev, env=env)
        # Run the unchanged staged guard in the isolated process environment.
        # An inherited scanner override cannot silently replace this pin.
        completed = subprocess.run(
            [sys.executable, str(ROOT / '.githooks/staged_guard.py')],
            cwd=scratch, env=env, capture_output=True, timeout=8)
        result = json.loads(completed.stdout)
        if completed.returncode or result.get('status') != 'passed':
            raise guard.Blocked(result.get('reason', 'scanner_failed'),
                                result.get('findings', []))
        return result

def run(root, head, base, scanner):
    start = time.monotonic()
    head = resolve(root, head)
    args = ['rev-list', '--reverse', head]
    if base and set(base) != {'0'}:
        args.append('^' + resolve(root, base))
    revisions = git(root, *args).decode().splitlines()
    if len(revisions) > MAX_COMMITS:
        raise guard.Blocked('commit_count_limit')
    # HEAD may be a synthetic PR merge commit or an unchanged snapshot.
    revisions = list(dict.fromkeys(revisions + [head]))
    results, trees = [], {}
    for rev in revisions:
        if time.monotonic() - start > 180:
            raise guard.Blocked('history_time_budget_exceeded')
        check_identity(root, rev)
        tree = git(root, 'rev-parse', rev + '^{tree}').decode().strip()
        if tree not in trees:
            trees[tree] = scan_tree(root, rev, scanner)
        results.append({'commit': rev, 'tree': tree, **trees[tree]})
    return {'status': 'passed', 'commits_checked': len(revisions),
            'unique_trees_checked': len(trees), 'head_files': results[-1]['scanned_files'],
            'elapsed_seconds': round(time.monotonic() - start, 3)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--base', default='')
    parser.add_argument('--scanner', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(ROOT, args.head, args.base, args.scanner.resolve())
    except guard.Blocked as exc:
        print(json.dumps({'status': 'blocked', 'reason': exc.reason, 'findings': exc.findings}))
        return 1
    except Exception as exc:
        print(json.dumps({'status': 'blocked', 'reason': 'check_error', 'error_type': type(exc).__name__}))
        return 2
    print(json.dumps(result))
    return 0

if __name__ == '__main__':
    sys.exit(main())
