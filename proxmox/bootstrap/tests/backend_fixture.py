"""Real local-state locking and one-time handover; offline Docker, no database."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
sys.path.insert(0, str(BASE))
import native
import runner
from bootstrap import container_backup


def run():
    (ROOT / '.work').mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='bootstrap-local-state-', dir=ROOT / '.work'))
    work.chmod(0o700)
    evidence = work / 'evidence'
    evidence.mkdir()
    operator = work / 'operator'
    tofu = operator / 'tofu'
    tofu.mkdir(parents=True)
    (tofu / 'main.tf').write_text('''terraform {
  backend "local" { path = "terraform.tfstate" }
}
resource "terraform_data" "fixture" {
  input = "synthetic state only"
  provisioner "local-exec" { command = "touch /evidence/held; sleep 8" }
}
''')
    container_name = 'bootstrap-state-writer-' + uuid.uuid4().hex[:10]
    writer = None

    def command(directory, *args, name=None):
        prefix = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
                  '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--memory', '512m', '--cpus', '1', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                  '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=128m,mode=1777', '-e', 'HOME=/tmp',
                  '-v', str(directory) + ':/work', '-v', str(evidence) + ':/evidence', '-w', '/work']
        if name:
            prefix += ['--name', name]
        return [sys.executable, str(BASE / 'workstation.py'), str(directory.parent),
                *prefix, 'homelab-bootstrap-test:1', 'tofu', *args]

    def client(directory, args, log, check=True):
        result = subprocess.run(command(directory, *args), capture_output=True, text=True, timeout=60)
        (evidence / log).write_text(result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError('Inspect ' + str(evidence / log))
        return result

    try:
        client(tofu, ['init', '-input=false', '-no-color'], 'initial-init.log')
        with (evidence / 'initial-apply.log').open('w') as log:
            writer = subprocess.Popen(command(tofu, 'apply', '-auto-approve', '-input=false', '-no-color', name=container_name),
                                      stdout=log, stderr=subprocess.STDOUT)
            for _ in range(80):
                if (evidence / 'held').exists():
                    break
                if writer.poll() is not None:
                    raise RuntimeError('Fixture writer exited before the locked operation')
                time.sleep(0.25)
            else:
                raise RuntimeError('Fixture writer did not reach the locked operation')
            blocked = client(tofu, ['plan', '-input=false', '-lock-timeout=1s', '-no-color'], 'competing-plan.log', check=False)
            if blocked.returncode == 0 or 'another bootstrap operation' not in (blocked.stdout + blocked.stderr).lower():
                raise RuntimeError('Competing writer was not refused')
            if writer.wait(timeout=45) != 0:
                raise RuntimeError('Fixture writer failed; preserve its logs')
        with native.workspace_lock(operator):
            staged, receipt = runner.stage_handover(operator)
        receiver = work / 'runner'
        shutil.copytree(staged, receiver)
        client(receiver / 'tofu', ['init', '-input=false', '-no-color'], 'runner-init.log')
        client(receiver / 'tofu', ['plan', '-input=false', '-detailed-exitcode', '-no-color'], 'runner-noop.log')
        receiver_state = json.loads(client(receiver / 'tofu', ['state', 'pull'], 'runner-state.json').stdout)
        if (receiver_state['lineage'], receiver_state['serial']) != (receipt['lineage'], receipt['serial']):
            raise RuntimeError('State lineage/serial changed during handover')
        try:
            with native.workspace_lock(operator):
                raise RuntimeError('Workstation was not frozen after handover')
        except native.Refused:
            pass
        backup_parent = Path(tempfile.mkdtemp(prefix='bootstrap-state-backup-'))
        container_backup(operator, backup_parent / 'snapshot')
        if native.sha(backup_parent / 'snapshot/tofu/terraform.tfstate') != receipt['state_sha256']:
            raise RuntimeError('Private backup state did not match the handed-over state')
        linux = subprocess.run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '512m', '--cpus', '1', '--user', str(os.getuid()) + ':' + str(os.getgid()),
            '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=128m,mode=1777', '-e', 'HOME=/tmp',
            '-v', str(BASE) + ':/src/proxmox/bootstrap:ro', '-v', str(evidence) + ':/evidence',
            'homelab-bootstrap-test:1', 'python3', '/src/proxmox/bootstrap/tests/backend_fixture.py',
            '--linux-lock'], capture_output=True, text=True, timeout=60)
        (evidence / 'linux-lock-fixture.log').write_text(linux.stdout + linux.stderr)
        if linux.returncode:
            raise RuntimeError('Inspect the native Linux local-state lock fixture')
        result = {'status': 'passed', 'backend': 'local', 'database_required': False,
                  'competing_writer_refused': True, 'runner_fresh_noop': True,
                  'same_lineage_and_serial': True, 'workstation_frozen': True,
                  'workstation_lock_checked': True, 'native_linux_state_lock_checked': True,
                  'private_backup_checked': True, 'network': 'none', 'NAS_or_PVE_or_GitHub_contacted': False}
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS: real local state, locking, runner handover/no-op and private backup.')
        print('Evidence:', evidence / 'result.json')
    finally:
        # Never equate a timed-out local Docker client with container closure.
        if writer is not None and writer.poll() is None:
            print('Fixture writer remains unresolved; preserve exact container:', container_name)


def linux_lock_test():
    """Check OpenTofu's own locking on a Linux filesystem, without host mounts."""
    area = Path(tempfile.mkdtemp(prefix='linux-state-lock-'))
    evidence = Path('/evidence')
    (area / 'main.tf').write_text('''terraform {
  backend "local" {}
}
resource "terraform_data" "fixture" {
  provisioner "local-exec" { command = "touch /evidence/linux-held; sleep 8" }
}
''')
    initial = subprocess.run(['tofu', 'init', '-input=false', '-no-color'], cwd=area, capture_output=True, text=True)
    (evidence / 'linux-init.log').write_text(initial.stdout + initial.stderr)
    if initial.returncode:
        raise RuntimeError('Inspect linux-init.log')
    with (evidence / 'linux-writer.log').open('w') as log:
        writer = subprocess.Popen(['tofu', 'apply', '-auto-approve', '-input=false', '-no-color'],
                                  cwd=area, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(80):
                if (evidence / 'linux-held').exists():
                    break
                if writer.poll() is not None:
                    raise RuntimeError('Linux writer exited before the lock test')
                time.sleep(0.1)
            else:
                raise RuntimeError('Linux writer did not reach its locked operation')
            blocked = subprocess.run(['tofu', 'plan', '-input=false', '-lock-timeout=1s', '-no-color'],
                                     cwd=area, capture_output=True, text=True, timeout=10)
            (evidence / 'linux-competing-plan.log').write_text(blocked.stdout + blocked.stderr)
            if blocked.returncode == 0 or 'state lock' not in (blocked.stdout + blocked.stderr).lower():
                raise RuntimeError('Native Linux state lock did not refuse the competing writer')
        finally:
            # Let this bounded synthetic writer finish normally before exiting.
            if writer.wait(timeout=20) != 0:
                raise RuntimeError('Linux fixture writer failed')
    print('PASS: native Linux OpenTofu state lock refused a competing writer.')


if __name__ == '__main__':
    linux_lock_test() if sys.argv[1:] == ['--linux-lock'] else run()
