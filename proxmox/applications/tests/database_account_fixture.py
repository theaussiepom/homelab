"""Real Ansible account guards in disposable Docker; never a live guest."""
import grp
import json
import os
from pathlib import Path
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(Path('/.dockerenv').exists() and os.geteuid() == 0, 'Run only as root inside a disposable Docker container')
TASKS = Path(__file__).resolve().parents[1] / 'ansible/tasks/database-account.yml'

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    playbook = root / 'account.yml'
    playbook.write_text(json.dumps([{'hosts': 'all', 'connection': 'local', 'gather_facts': False,
                                    'tasks': [{'ansible.builtin.import_tasks': str(TASKS)}]}]))
    variables = root / 'variables.json'
    command = ['ansible-playbook', '-i', 'localhost,', str(playbook), '--extra-vars', '@' + str(variables)]

    def run(user, group, uid, gid):
        variables.write_text(json.dumps({'app': {'database': {
            'user': user, 'group': group, 'uid': uid, 'gid': gid, 'home': '/nonexistent'}}}))
        return subprocess.run(command, capture_output=True, text=True)

    def accounts():
        return {p: Path(p).read_bytes() for p in ('/etc/passwd', '/etc/group')}

    subprocess.run(['groupadd', '--gid', '31000', 'fixture_existing'], check=True)
    before = accounts()
    failed = run('fixture_new', 'fixture_existing', 31001, 31001)
    require(failed.returncode != 0, 'An existing group must not be renumbered')
    require(accounts() == before, 'The refused configuration changed numeric account identities')

    failed = run('fixture_new', 'fixture_new', 31001, 31000)
    require(failed.returncode != 0, 'A group ID owned by another group must be refused')
    require(accounts() == before, 'Synthetic database fixture check failed')

    subprocess.run(['useradd', '--uid', '31002', '--gid', 'fixture_existing', '--no-create-home', 'fixture_other'], check=True)
    before = accounts()
    failed = run('fixture_new', 'fixture_new', 31002, 31001)
    require(failed.returncode != 0, 'A user ID owned by another account must be refused')
    require(accounts() == before, 'UID collision must be caught before creating its group')

    passed = run('fixture_new', 'fixture_new', 31001, 31001)
    require(passed.returncode == 0, passed.stdout + passed.stderr)
    before = accounts()
    repeated = run('fixture_new', 'fixture_new', 31001, 31001)
    require(repeated.returncode == 0, repeated.stdout + repeated.stderr)
    require('changed=0' in repeated.stdout and accounts() == before, 'Synthetic database fixture check failed')
    require(grp.getgrnam('fixture_existing').gr_gid == 31000, 'Synthetic database fixture check failed')
    print('Database account guards passed: no existing group renumber, foreign UID/GID holds, exact creation and no-change repeat')
