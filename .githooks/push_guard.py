#!/usr/bin/env python3
"""Bounded local identity/signature check of commits not yet on the remote."""
import json
import re
import subprocess
import sys
import time

START = time.monotonic()

class Refused(Exception):
    pass

def git(*args):
    remaining = 5 - (time.monotonic() - START)
    if remaining <= 0:
        raise Refused('time_budget_exceeded')
    r = subprocess.run(['git', *args], capture_output=True, timeout=remaining)
    if r.returncode:
        raise Refused('git_or_signature_check_failed')
    return r.stdout.decode().strip()

def run(remote, updates):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', remote):
        raise Refused('push_to_a_configured_named_remote')
    name, email = git('config', 'user.name'), git('config', 'user.email')
    if not name or not re.fullmatch(r'(?:\d+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com', email):
        raise Refused('configure_handle_and_github_noreply_email')
    commits = set()
    for row in updates.splitlines():
        parts = row.split()
        if len(parts) != 4 or not all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', p) for p in (parts[1], parts[3])):
            raise Refused('invalid_push_update')
        if set(parts[1]) == {'0'}:
            continue
        # Known remote history is not rewritten or re-signed by this hook.
        commits.update(git('rev-list', parts[1], '--not', '--remotes=' + remote).splitlines())
    if len(commits) > 200:
        raise Refused('commit_count_limit')
    for sha in sorted(commits):
        fields = git('show', '-s', '--format=%cn%x00%ce%x00%an%x00%ae%x00%B', sha).split('\0', 4)
        if fields[:2] != [name, email]:
            raise Refused('outgoing_committer_identity_mismatch')
        if fields[2].casefold() == name.casefold() and fields[3] != email:
            raise Refused('outgoing_author_email_mismatch')
        for line in fields[4].splitlines():
            if re.match(r'(?i)(co-authored-by|signed-off-by):\s*' + re.escape(name) + r'\s*<', line):
                if '<' + email + '>' not in line:
                    raise Refused('outgoing_trailer_email_mismatch')
        git('verify-commit', sha)
    return {'status': 'passed', 'commits_checked': len(commits)}

if __name__ == '__main__':
    try:
        result = run(sys.argv[1], sys.stdin.read(65536))
        result['elapsed_seconds'] = round(time.monotonic() - START, 3)
        print(json.dumps(result))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        print(json.dumps({'status': 'blocked', 'reason': reason}), file=sys.stderr)
        sys.exit(1)
