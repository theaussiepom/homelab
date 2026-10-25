"""Run real Ansible against a tiny local runner; no GitHub/PVE calls."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

BASE = Path(__file__).resolve().parents[1]
TOKEN = 'synthetic-registration-token-never-print'


def archive(path, fail=False, bom=False):
    config = '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
assert os.environ['ACTIONS_RUNNER_INPUT_TOKEN'] == 'synthetic-registration-token-never-print'
assert '--token' not in sys.argv
args=sys.argv
assert args[args.index('--url')+1]=='https://github.com/example-owner/private-site'
print(os.environ['ACTIONS_RUNNER_INPUT_TOKEN'])  # Ansible must redact even malicious stdout.
'''
    if fail:
        config += 'raise SystemExit(9)\n'
    else:
        encoding = 'utf-8-sig' if bom else 'utf-8'
        config += f"Path('.runner').write_text(json.dumps({{'gitHubUrl':args[args.index('--url')+1],'agentName':args[args.index('--name')+1]}}), encoding={encoding!r})\n"
        config += "Path('.credentials').write_text('fixture credential only')\n"
    run = '''#!/usr/bin/env python3
import json
from pathlib import Path
assert json.loads(Path('.runner').read_text(encoding='utf-8-sig'))['agentName']=='homelab-deploy'
Path('fixture-job-complete').write_text('local fixture job passed; no GitHub job ran')
'''
    with tarfile.open(path, 'w:gz') as tar:
        for name, content in [('config.sh', config), ('run.sh', run)]:
            data = content.encode(); member = tarfile.TarInfo(name)
            member.size = len(data); member.mode = 0o755
            tar.addfile(member, io.BytesIO(data))


def run(work, evidence, name, fail=False, tampered=False, bom=False):
    area = work / name
    area.mkdir(parents=True)
    tar = area / 'runner.tar.gz'
    archive(tar, fail, bom)
    values = {'bootstrap_docker_fixture': True, 'runner_directory': str(area / 'install'),
              'runner_archive': str(tar), 'runner_archive_sha256': '0' * 64 if tampered else hashlib.sha256(tar.read_bytes()).hexdigest(),
              'runner_name': 'homelab-deploy', 'runner_repository': 'example-owner/private-site',
              'runner_service_file': str(area / 'homelab-deploy.service')}
    variables = area / 'vars.json'; variables.write_text(json.dumps(values))
    inventory = area / 'inventory.json'
    inventory.write_text(json.dumps({'all': {'hosts': {'deploy': {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable}}}}))
    command = ['ansible-playbook', '-i', str(inventory), str(BASE / 'ansible/runner.yml'), '-e', '@' + str(variables)]
    env = dict(os.environ, HOMELAB_RUNNER_REGISTRATION_TOKEN=TOKEN, ANSIBLE_NOCOLOR='1')
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    (evidence / (name + '.log')).write_text(output)
    assert TOKEN not in output, 'registration token leaked'
    if fail or tampered:
        assert result.returncode != 0
        assert not (area / 'install/fixture-job-complete').exists()
        if tampered:
            assert not (area / 'install/.bootstrap-attempt').exists()
    else:
        assert result.returncode == 0, 'runner playbook failed'
        assert (area / 'install/fixture-job-complete').is_file()
        assert 'NoNewPrivileges=true' in (area / 'homelab-deploy.service').read_text()
    if not tampered:
        retry = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        assert retry.returncode != 0 and 'already attempted' in retry.stdout
        assert TOKEN not in retry.stdout + retry.stderr
    return {'case': name, 'passed': True}


if __name__ == '__main__':
    work, evidence = map(Path, sys.argv[1:])
    cases = [run(work, evidence, 'registration'), run(work, evidence, 'failed-registration', fail=True),
             run(work, evidence, 'changed-archive', tampered=True), run(work, evidence, 'registration-bom', bom=True)]
    (evidence / 'runner-cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    print('Runner fixture: registration, process start, token redaction, changed archive and replay/partial-failure refusal passed.')
