"""Saved-plan host/bootstrap CD with existing state; no import or recovery mode."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile

from bootstrap_cd import API
import host_firewall as contract
from host_firewall import require

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'applications'))
import private_io as io

ROOT = Path('/var/lib/homelab-bootstrap')
CA = Path('/usr/local/share/ca-certificates/homelab-pve.crt')
TARGET = ('endpoint', 'node', 'host_address')


def environment(token, rc):
    return {'PATH': '/opt/homelab-tools/bin:/usr/local/bin:/usr/bin:/bin',
            'PROXMOX_VE_API_TOKEN': token, 'SSL_CERT_FILE': str(CA),
            'TF_CLI_CONFIG_FILE': str(rc), 'TF_IN_AUTOMATION': '1',
            'CHECKPOINT_DISABLE': '1'}


def snapshot(api, c):
    host = api.call('/nodes/' + c['node'] + '/firewall/rules')['data']
    cluster = api.call('/cluster/firewall/options')['data']
    return ({'rules': contract.native_rules(host), 'cluster': contract.native_cluster(cluster)},
            {'host': host, 'cluster': cluster})


def state(raw, c, before):
    value = contract.authored_config.parse(raw, '.json')
    require(type(value) is dict and value.get('version') == 4
            and type(value.get('serial')) is int and value['serial'] >= 0
            and type(value.get('lineage')) is str and value['lineage'])
    rows = value.get('resources')
    require(type(rows) is list and len(rows) == 2)
    selected = {}
    for row in rows:
        require(type(row) is dict and not row.get('module') and row.get('mode') == 'managed'
                and row.get('provider') == 'provider["registry.opentofu.org/bpg/proxmox"]')
        key = row.get('type', '') + '.' + row.get('name', '')
        require(key in (contract.HOST, contract.CLUSTER) and key not in selected
                and type(row.get('instances')) is list and len(row['instances']) == 1
                and 'deposed' not in row['instances'][0])
        attrs = row['instances'][0]['attributes']
        require(type(attrs) is dict and type(attrs.get('id')) is str and attrs['id'])
        selected[key] = attrs
    host = selected[contract.HOST]
    require(host['node_name'] == c['node'] and host['vm_id'] is None and host['container_id'] is None
            and contract.plan_rules(host['rule']) == before['rules']
            and contract.cluster_values(selected[contract.CLUSTER]) == before['cluster'])
    return {'lineage': value['lineage'], 'serial': value['serial']}


def sources():
    return {name: io.regular(HERE / relative) for name, relative in (
        ('main.tf', 'host-firewall/main.tf'), ('variables.tf', 'host-firewall/variables.tf'),
        ('versions.tf', 'docker/versions.tf'), ('.terraform.lock.hcl', 'docker/.terraform.lock.hcl'))}


def source_digest(path, c):
    require(contract.authored_config.read(path) == c)
    return hashlib.sha256(io.regular(path, limit=contract.authored_config.MAX_BYTES)).hexdigest()


@contextmanager
def locked(root):
    io.private_directory(root)
    with io.private_writer(root / '.host-firewall.lock', append=True) as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def run(c, work, source, *, root=ROOT):
    contract.validate(c)
    require(platform.system() == 'Linux' and not Path('/etc/pve').exists())
    require(work == root / 'host-firewall')
    previous_umask = os.umask(0o077)
    try:
        with locked(root):
            return run_locked(c, work, source, root)
    finally:
        os.umask(previous_umask)


def run_locked(c, work, source, root):
    io.private_directory(work)
    hold, marker = root / 'BOOTSTRAP-CD-HOLD.json', root / 'CONFIGURING'
    require(not any(p.exists() or p.is_symlink() for p in (hold, marker)))
    old_policy = io.read_json(work / 'policy.auto.tfvars.json', private=True)
    contract.closed(old_policy, ('policy',))
    contract.validate(old_policy['policy'])
    require(all(old_policy['policy'][k] == c[k] for k in TARGET))
    backend = work / 'terraform.tfstate'
    original = io.regular(backend, private=True)
    source_sha = source_digest(source, c)
    template = sources()
    operations = work / 'operations'
    io.private_directory(operations, create=not operations.exists())
    attempt = Path(tempfile.mkdtemp(prefix='host-firewall-', dir=operations))
    claim = {'schema': 'homelab-host-firewall-attempt-v1', 'attempt': attempt.name, 'source_sha256': source_sha}
    claim_raw = io.encoded(claim)
    io.write_new(marker, claim_raw)
    io.write_new(hold, claim_raw)
    release_started = False
    try:
        token = os.environ['PROXMOX_BOOTSTRAP_TOKEN']
        api = API(c['endpoint'], token, CA)
        before, api_before = snapshot(api, c)
        identity = state(original, c, before)
        for name, raw in template.items():
            io.write_new(attempt / name, raw)
        io.write_new(attempt / 'policy.auto.tfvars.json', io.encoded({'policy': c}))
        rc = attempt / 'tofu.rc'
        io.write_new(rc, b'disable_checkpoint = true\nprovider_installation { direct { include = ["registry.opentofu.org/bpg/proxmox"] } }\n')
        env = environment(token, rc)
        tofu = ['/usr/local/bin/tofu', '-chdir=' + str(attempt)]

        def command(name, args, accepted=(0,)):
            with io.private_writer(attempt / (name + '.stdout'), exclusive=True) as out, \
                 io.private_writer(attempt / (name + '.stderr'), exclusive=True) as err:
                p = (apply_process(tofu + args, attempt, out, err, env) if name == 'apply' else
                     subprocess.run(tofu + args, stdout=out, stderr=err, env=env, timeout=900))
            require(p.returncode in accepted)
            return attempt / (name + '.stdout')

        command('init', ['init', '-input=false', '-lockfile=readonly', '-backend-config=path=' + str(backend)])
        version = io.read_json(command('version', ['version', '-json']), private=True)
        require(version['terraform_version'] == '1.13.1' and version['provider_selections'] == {'registry.opentofu.org/bpg/proxmox': '0.117.0'})
        plan = attempt / 'host.tfplan'
        command('plan', ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(plan)])
        shown = io.read_json(command('show', ['show', '-json', str(plan)]), private=True)
        contract.check_plan(shown, c, before)
        plan_sha = io.sha(plan)
        io.write_new(attempt / 'plan-binding.json', io.encoded({'source_sha256': source_sha, 'plan_sha256': plan_sha,
                     'state_sha256': hashlib.sha256(original).hexdigest(), **identity}))
        require(source_digest(source, c) == source_sha and sources() == template
                and io.regular(backend, private=True) == original and snapshot(api, c) == (before, api_before)
                and io.sha(plan) == plan_sha and io.regular(marker, private=True) == io.regular(hold, private=True) == claim_raw)
        command('apply', ['apply', '-input=false', '-lock-timeout=30s', str(plan)])
        after, _ = snapshot(api, c)
        require(after == {'rules': contract.rules(c), 'cluster': c['cluster']})
        current = state(io.regular(backend, private=True), c, after)
        require(current['lineage'] == identity['lineage'] and current['serial'] >= identity['serial'])
        verified = attempt / 'verified.tfplan'
        command('verify', ['plan', '-input=false', '-lock-timeout=30s', '-detailed-exitcode', '-out=' + str(verified)])
        final_plan = io.read_json(command('verify-show', ['show', '-json', str(verified)]), private=True)
        contract.check_plan(final_plan, c, after)
        require(all(r['change']['actions'] == ['no-op'] for r in final_plan['resource_changes'])
                and source_digest(source, c) == source_sha and sources() == template)
        require(io.regular(marker, private=True) == io.regular(hold, private=True) == claim_raw)
        io.write(work / 'policy.auto.tfvars.json', {'policy': c})
        result = {'status': 'passed', 'api_verified': True, 'provider_noop': True, 'kernel_verified': False}
        io.write_new(attempt / 'api-result.json', io.encoded(dict(result, status='api-verified')))
        require(io.regular(marker, private=True) == io.regular(hold, private=True) == claim_raw)
        release_started = True
        hold.unlink()
        marker.unlink()
        io.sync(root)
        io.write_new(attempt / 'result.json', io.encoded(result))
        return result
    except Exception:
        if release_started:
            try:
                io.write_new(hold, claim_raw)
            except FileExistsError:
                pass  # Never replace another marker, including a foreign claim.
        io.write_new(attempt / 'failure.json', io.encoded({'status': 'held', 'automatic_retry': False}))
        raise ValueError(contract.ERROR) from None


def apply_process(args, cwd, stdout, stderr, env):
    """Use the bootstrap's bounded SIGINT-before-kill policy with a scrubbed env."""
    p = subprocess.Popen(args, cwd=cwd, stdout=stdout, stderr=stderr, env=env)
    try:
        p.wait(timeout=900)
    except subprocess.TimeoutExpired:
        try:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=300)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise
    return p
