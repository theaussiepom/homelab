"""Small caller for ordinary OpenTofu init/plan/saved-apply/verify.

Credentials use the tools' normal environment variables. There is no custom
Session, signing service, profile registry or replacement state implementation.
"""
import hashlib
import json
import os
from contextlib import contextmanager
import fcntl
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile

from bootstrap import HERE, Refused, read, sha, write


@contextmanager
def workspace_lock(work, backup=False, name='.bootstrap.lock'):
    """Serialize the local caller with the one-time copy to the runner."""
    with (work / name).open('a') as stream:
        os.fchmod(stream.fileno(), 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('Another bootstrap operation is active in this workspace') from None
        try:
            if not backup and (work / 'HANDOVER.json').exists():
                raise Refused('Runner handover has started; this workstation copy is now a backup. Inspect HANDOVER.json and the retained logs.')
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def state_file(work):
    """Require the existing state and validate its lineage, serial and private mode."""
    path = work / 'tofu/terraform.tfstate'
    if path.is_symlink() or not path.is_file():
        raise Refused('The existing local state file is required; do not recreate it')
    state = read(path)
    if (not isinstance(state.get('lineage'), str) or not state['lineage']
            or type(state.get('serial')) is not int or state['serial'] < 0):
        raise Refused('The local state has no valid lineage/serial')
    path.chmod(0o600)
    return path, state


def copy_workspace(work, destination):
    """Copy configuration and the exact state, excluding plans and tool caches."""
    state, metadata = state_file(work)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for source in (work / 'tofu').rglob('*'):
        relative = source.relative_to(work / 'tofu')
        if '.terraform' in relative.parts or 'tests' in relative.parts:
            continue
        if source.is_symlink():
            raise Refused('Symlinks are not part of a state handover or backup')
        if source.is_file() and (source.suffix in ('.tf', '.json', '.hcl') or source == state):
            target = destination / 'tofu' / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o600)
            with target.open('rb') as stream:
                os.fsync(stream.fileno())
    if sha(destination / 'tofu/terraform.tfstate') != sha(state):
        raise Refused('The state copy changed; preserve this attempt before investigating')
    return {'state_sha256': sha(state), 'lineage': metadata['lineage'], 'serial': metadata['serial']}


def backup(work, destination):
    """Copy exact state and configuration under the shared workspace lock."""
    work, destination = work.resolve(), destination.absolute()
    source_root = HERE.parents[1] if (HERE.parents[1] / 'proxmox/bootstrap').is_dir() else HERE
    if destination.resolve().is_relative_to(source_root):
        raise Refused('Keep private state backups outside the public checkout')
    with workspace_lock(work, backup=True):
        receipt = copy_workspace(work, destination)
        write(destination / 'backup.json', receipt)
    return receipt


def check_plan(plan):
    """Refuse changes outside creation of the selected deployment guest."""
    allowed = {'module.guests["deploy"].proxmox_virtual_environment_container.guest',
               'module.guests["deploy"].proxmox_virtual_environment_firewall_options.guest',
               'module.guests["deploy"].proxmox_virtual_environment_firewall_rules.ssh'}
    changes = plan.get('resource_changes', [])
    if not changes or any(c['address'] not in allowed or
                          c['change']['actions'] not in (['create'], ['no-op']) for c in changes):
        raise Refused('Bootstrap accepts only creation of its own guest or no changes; review other changes separately')


def binding(work):
    """Hash the active OpenTofu configuration while excluding tool caches."""
    files = sorted(p for p in (work / 'tofu').rglob('*') if p.is_file()
                   and '.terraform' not in p.parts and p.suffix in ('.tf', '.json', '.hcl'))
    return hashlib.sha256(b''.join(str(p.relative_to(work)).encode() + b'\0' + p.read_bytes()
                                   for p in files)).hexdigest()


def run(action, directory):
    """Serialize a native operation against workstation writes and handover."""
    with workspace_lock(directory.resolve()):
        return run_locked(action, directory)


def apply_process(args, cwd, stdout, stderr):
    """Give a timed-out apply time to save state, while retaining UNKNOWN."""
    proc = subprocess.Popen(args, cwd=cwd, stdout=stdout, stderr=stderr)
    try:
        proc.wait(timeout=900)
    except subprocess.TimeoutExpired:
        try:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=300)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass  # Local cleanup cannot establish the remote resource outcome.
        raise
    return proc


def run_locked(action, directory):
    """Run one Linux-operator action and preserve failed apply evidence without retry."""
    if platform.system() != 'Linux' or Path('/etc/pve').exists():
        raise Refused('Run the tools in the Linux Docker executor, not on Mac or the PVE host')
    work = directory.resolve()
    if not (work / 'tofu/backend.tf').is_file():
        raise Refused('Prepare a bootstrap bundle first')
    if (work / 'HOLD.json').exists() and action == 'apply':
        raise Refused('A previous operation failed; inspect HOLD.json and its logs before another apply')
    logs = work / 'operations'; logs.mkdir(mode=0o700, exist_ok=True)
    attempt = Path(tempfile.mkdtemp(prefix=action + '-', dir=logs))
    result = {'action': action, 'status': 'attempted', 'logs': str(attempt), 'native_verified': False}
    write(attempt / 'result.json', result)

    def command(args, name, accepted=(0,)):
        """Capture one tool invocation privately and enforce its allowed exit codes."""
        out, err = attempt / (name + '.stdout'), attempt / (name + '.stderr')
        for path in (out, err): path.touch(mode=0o600)
        with out.open('w') as stdout, err.open('w') as stderr:
            if name == 'apply':
                proc = apply_process(args, work / 'tofu', stdout, stderr)
            else:
                proc = subprocess.run(args, cwd=work / 'tofu', stdout=stdout, stderr=stderr, timeout=900)
        if proc.returncode not in accepted:
            raise Refused('Command failed; inspect private logs at ' + str(attempt))
        return proc.returncode, out

    try:
        command(['tofu', 'init', '-input=false', '-lockfile=readonly', '-no-color'], 'init')
        if action == 'plan':
            plan = attempt / 'bootstrap.tfplan'
            command(['tofu', 'plan', '-input=false', '-lock=true', '-lock-timeout=30s', '-no-color', '-out=' + str(plan)], 'plan')
            _, shown = command(['tofu', 'show', '-json', str(plan)], 'show')
            check_plan(read(shown))
            write(work / 'saved-plan.json', {'plan': str(plan), 'sha256': sha(plan), 'inputs_sha256': binding(work)})
            result['saved_plan'] = str(plan)
        elif action == 'apply':
            saved = read(work / 'saved-plan.json'); plan = Path(saved['plan'])
            if sha(plan) != saved['sha256'] or binding(work) != saved['inputs_sha256']:
                raise Refused('Saved plan or its configuration changed; prepare and review a new plan')
            _, shown = command(['tofu', 'show', '-json', str(plan)], 'show')
            check_plan(read(shown))
            command(['tofu', 'apply', '-input=false', '-lock=true', '-lock-timeout=30s', '-no-color', str(plan)], 'apply')
        elif action == 'verify':
            code, _ = command(['tofu', 'plan', '-input=false', '-lock=true', '-lock-timeout=30s', '-detailed-exitcode',
                               '-no-color', '-out=' + str(attempt / 'verify.tfplan')], 'verify', (0, 2))
            if code != 0:
                raise Refused('The fresh provider plan contains changes; inspect the private plan')
            _, output = command(['tofu', 'output', '-json'], 'output')
            result.update(provider_noop=True, identity=read(output)['deploy_identity']['value'])
        else:
            raise Refused('Unknown native bootstrap command')
        result['status'] = 'passed'
    except (Refused, OSError, subprocess.TimeoutExpired) as exc:
        result.update(status='UNKNOWN' if isinstance(exc, subprocess.TimeoutExpired) else 'held',
                      reason=str(exc) if isinstance(exc, Refused) else 'Inspect private operation logs; no automatic retry')
        if action == 'apply': write(work / 'HOLD.json', result)
        write(attempt / 'result.json', result)
        raise Refused(result['reason']) from exc
    write(attempt / 'result.json', result)
    return result
