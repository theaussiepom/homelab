"""Select the expensive synthetic ISO checks within the shared CI workflow."""
import json
import os
from pathlib import Path
import re
import subprocess


ISO_INPUTS = {
    '.github/workflows/ci.yml',
    '.github/scripts/ci_changes.py',
    '.github/scripts/test_ci_changes.py',
    'tests/test_boundaries.py',
}


def needs_iso(event_name, event, head, git=subprocess.check_output):
    """An unavailable comparison runs the checks rather than skipping coverage."""
    if event_name == 'workflow_dispatch':
        return True
    if event_name == 'schedule':
        return False
    if event_name not in {'pull_request', 'push'}:
        raise ValueError('Unsupported validation event')
    base = (event.get('pull_request', {}).get('base', {}).get('sha', '')
            if event_name == 'pull_request' else event.get('before', ''))
    if not all(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value)
               and value != '0' * 40 for value in (base, head)):
        return True
    try:
        paths = git(['git', 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                     '--name-only', '-z', base, head, '--'], timeout=30,
                    stderr=subprocess.DEVNULL).decode('utf-8').split('\0')
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return True
    return any(path.startswith('proxmox/iso/') or path in ISO_INPUTS for path in paths)


if __name__ == '__main__':
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    result = needs_iso(os.environ['GITHUB_EVENT_NAME'], event, os.environ['GITHUB_SHA'])
    print('iso=' + str(result).lower())
