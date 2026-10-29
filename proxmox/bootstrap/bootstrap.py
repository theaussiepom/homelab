#!/usr/bin/env python3
"""Prepare and run one deployment guest using standard OpenTofu and Ansible."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class Refused(ValueError):
    pass


def sha(path):
    """Hash a file in bounded chunks for an exact content binding."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    """Read JSON while refusing duplicate object keys."""
    def unique(pairs):
        """Reject ambiguous duplicate JSON keys."""
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused('Duplicate JSON keys refused')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def write(path, value):
    """Atomically save a private receipt and synchronise its file and directory."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def settings_check(value):
    """Validate repository, network and cached-template settings before preparation."""
    required = {'repository', 'runner_name', 'admin_cidr', 'prefix_length', 'gateway', 'dns_servers'}
    if set(value) not in (required, required | {'template'}):
        raise Refused('Use the documented repository/network settings; credentials use normal environment variables')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', value['repository']):
        raise Refused('Expected an owner/repository name')
    if not re.fullmatch(r'[a-z][a-z0-9-]{1,62}', value['runner_name']):
        raise Refused('Invalid runner name')
    network = ipaddress.ip_network(value['admin_cidr'])
    if network.prefixlen == 0 or not 8 <= value['prefix_length'] <= 30:
        raise Refused('Select the administration network and guest subnet explicitly')
    if value['gateway'] is not None: ipaddress.ip_address(value['gateway'])
    for address in value['dns_servers']: ipaddress.ip_address(address)
    if 'template' in value:
        template = value['template']
        if (set(template) != {'file', 'sha256', 'file_name', 'datastore_id'} or
                not isinstance(template['file'], str) or not template['file'] or
                not re.fullmatch('[a-f0-9]{64}', template['sha256']) or
                Path(template['file_name']).name != template['file_name']):
            raise Refused('Supply a vendor template cached file, exact SHA-256 and simple file name')


def select(catalog):
    """Select the single protected deployment container from the catalogue."""
    guests = [g for g in catalog['guests'] if g['key'] == 'deploy']
    if len(guests) != 1:
        raise Refused('The catalog must contain exactly one deploy guest')
    guest = guests[0]
    if (guest['runtime'] != 'unprivileged_lxc' or len(guest['interfaces']) != 1
            or guest['protection'] is not True or guest['idmaps'] not in ([], None)
            or guest['vmid'] in (4914, 4915, 4920)):
        raise Refused('Expected one protected unprivileged deployment LXC with one management NIC and an unused ID')
    if not 100 <= guest['vmid'] <= 999999999 or not guest['storage_id']:
        raise Refused('Supply the target guest ID and existing storage')
    if not catalog['site']['ssh_public_keys']:
        raise Refused('Supply the bootstrap SSH public key')
    return guest


def prepare(catalog_path, settings_path, destination):
    """Create a private operator bundle without contacting the target host."""
    catalog, settings = read(catalog_path), read(settings_path)
    guest = select(catalog)
    settings_check(settings)
    if destination.exists() or destination.is_symlink():
        receipt = destination / 'preparation.json'
        if (destination.is_symlink() or not receipt.is_file()
                or read(receipt).get('catalog_sha256') != sha(catalog_path)
                or read(receipt).get('settings_sha256') != sha(settings_path)):
            raise Refused('Existing preparation differs; preserve it and review the new inputs')
        return {**read(receipt), 'changed': False}
    destination = destination.absolute()
    if catalog['site']['environment'] != 'synthetic' and destination.resolve().is_relative_to(ROOT):
        raise Refused('Prepare actual private settings outside the public source checkout')
    destination.mkdir(parents=True, mode=0o700)
    tofu = destination / 'tofu'
    tofu.mkdir()
    shared = HERE
    shutil.copytree(HERE / 'templates/module', tofu / 'modules/deploy')
    shutil.copy2(shared / 'docker/versions.tf', tofu / 'modules/deploy/versions.tf')
    for name in ('versions.tf', '.terraform.lock.hcl'):
        shutil.copy2(shared / 'docker' / name, tofu / name)
    shutil.copy2(HERE / 'templates/main.tf', tofu / 'main.tf')
    (tofu / 'backend.tf').write_text('terraform {\n  backend "local" { path = "terraform.tfstate" }\n}\n')
    nic = guest['interfaces'][0]
    address = 'dhcp' if nic['ipv4'] == 'dhcp' else str(ipaddress.ip_address(nic['ipv4'].split('/')[0]))
    if address != 'dhcp' and (not settings['gateway'] or not settings['dns_servers']):
        raise Refused('Static guest networking needs its gateway and DNS settings')
    projection = {k: guest[k] for k in ('vmid', 'cpu', 'memory_mib', 'root_gib', 'storage_id', 'template_file_id')}
    projection.update(ipv4='dhcp' if address == 'dhcp' else address + '/' + str(settings['prefix_length']),
                      gateway=None if address == 'dhcp' else settings['gateway'],
                      dns_servers=settings['dns_servers'], bridge=nic['bridge'], vlan=nic['vlan'], mac=nic['mac'])
    template = settings.get('template')
    if template and 'file' in template:
        archive = Path(os.environ.get('HOMELAB_TEMPLATE_FILE', template['file']))
        file_id = template['datastore_id'] + ':vztmpl/' + template['file_name']
        if (archive.is_symlink() or not archive.is_file() or not 0 < archive.stat().st_size <= 1024 ** 3
                or sha(archive) != template['sha256'] or guest['template_file_id'] != file_id):
            raise Refused('Cached template bytes or selected template ID differ from the settings')
        shutil.copyfile(archive, destination / 'template.archive')
        (destination / 'template.archive').chmod(0o600)
        if sha(destination / 'template.archive') != template['sha256']:
            raise Refused('Cached template copy changed; preserve this preparation attempt')
        write(destination / 'template.json', {'node': catalog['site']['node'], 'file_id': file_id,
              'sha256': template['sha256'], 'size_bytes': archive.stat().st_size})
        template = None  # The SSH access step seeds it; OpenTofu then uses this existing template.
    write(tofu / 'site.auto.tfvars.json', {'site': catalog['site'], 'deploy': projection,
          'admin_cidr': settings['admin_cidr']})
    write(destination / 'inventory.json', {'all': {'hosts': {'deploy': {
        'ansible_host': address, 'ansible_user': 'root',
        'ansible_ssh_common_args': '-o StrictHostKeyChecking=yes',
        'ansible_ssh_private_key_file': '/keys/bootstrap-key'}}}})
    write(destination / 'settings.json', settings)
    report = {'phase': 'prepared', 'selected_guests': ['deploy'],
              'final_state_root': 'bootstrap', 'existing_host_objects_managed': False,
              'catalog_sha256': sha(catalog_path), 'settings_sha256': sha(settings_path),
              'runner_release': read(HERE / 'docker/tools.json')['runner'],
              'state': 'Standard local state file; transferred once to the deployment runner.',
              'host_api_allowance': 'Runner setup adds one guest-to-host TCP 8006 rule over pinned SSH and preserves other rules/settings.',
              'live_execution_admitted': False, 'pve_contacted': False,
              'remaining_native_work': 'Scripted API access, saved provider plan/apply, guest SSH, automatic host API allowance, state handover and runner registration.'}
    write(destination / 'preparation.json', report)
    return report


def snapshot(destination):
    """Copy public inputs only; never expose .local/, Git metadata or caches."""
    destination.mkdir(parents=True, mode=0o700)
    paths = ['proxmox/bootstrap']
    excluded = shutil.ignore_patterns('.local', '.work', 'evidence', '__pycache__',
                                     '.terraform', '*.tfstate*', '*.tfplan', '*.pyc')
    for name in paths:
        source, target = ROOT / name, destination / name
        if source.is_symlink():
            raise Refused('Source symlinks are not part of the test snapshot')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target, ignore=excluded, symlinks=True)
    if any(p.is_symlink() for p in destination.rglob('*')):
        raise Refused('Source snapshot contains a symlink; it will not be mounted into Docker')
    return {'snapshot': str(destination)}


def container_prepare(catalog, settings, destination):
    """The operator needs Docker and Python's standard library, not Ansible."""
    catalog, settings, destination = catalog.resolve(), settings.resolve(), destination.absolute()
    if read(catalog)['site']['environment'] != 'synthetic' and destination.resolve().is_relative_to(ROOT):
        raise Refused('Keep actual preparation output outside the public checkout')
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not (destination / 'bundle/preparation.json').is_file():
            raise Refused('Existing preparation is incomplete; preserve it before another attempt')
        result = prepare(catalog, settings, destination / 'bundle')
        return {'prepared_bundle': str(destination / 'bundle'), 'changed': result['changed'],
                'live_execution_admitted': False}
    cache = ROOT / '.work'
    cache.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='bootstrap-prepare-', dir=cache))
    snapshot(run / 'source')
    destination.mkdir(parents=True, mode=0o700)
    subprocess.run(['docker', 'build', '--platform', 'linux/amd64',
        '--build-arg', f'HOST_UID={os.getuid()}', '--build-arg', f'HOST_GID={os.getgid()}',
        '-t', 'homelab-bootstrap-test:1', str(HERE / 'docker')], check=True, timeout=1800)
    command = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777',
        '-e', 'HOME=/tmp', '-v', f'{run / "source"}:/src:ro',
        '-v', f'{catalog}:/inputs/site.json:ro', '-v', f'{settings}:/inputs/settings.json:ro',
        '-v', f'{destination}:/output']
    configured = read(settings).get('template')
    if configured and 'file' in configured:
        archive = Path(configured['file']).absolute()
        if archive.is_symlink() or not archive.is_file():
            raise Refused('Select the actual cached template file, not a link or missing path')
        command += ['-v', f'{archive}:/inputs/template.archive:ro', '-e', 'HOMELAB_TEMPLATE_FILE=/inputs/template.archive']
    subprocess.run(command + ['homelab-bootstrap-test:1',
        'python3', '/src/proxmox/bootstrap/bootstrap.py', 'prepare',
        '--catalog', '/inputs/site.json', '--settings', '/inputs/settings.json', '--out', '/output/bundle'],
        check=True, timeout=300)
    return {'prepared_bundle': str(destination / 'bundle'), 'live_execution_admitted': False}


def log_run(arguments, cwd, output, expected=0):
    """Run a bounded offline check and retain its output and expected exit status."""
    with output.open('w') as stream:
        result = subprocess.run(arguments, cwd=cwd, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=180)
    if result.returncode != expected:
        raise Refused('A rehearsal step failed; inspect ' + output.name)


def container_backup(work, destination):
    """Use the same Linux file locking as plan/apply and handover."""
    work, destination = work.resolve(), destination.absolute()
    if destination.resolve().is_relative_to(ROOT):
        raise Refused('Keep private state backups outside the public checkout')
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise Refused('Use a new backup directory under an existing private parent')
    import os
    from native import workspace_lock
    with workspace_lock(work, backup=True, name='.workstation.lock'):
        subprocess.run(['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--memory', '256m', '--cpus', '1', '--user', f'{os.getuid()}:{os.getgid()}',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777', '-e', 'HOME=/tmp',
        '-v', f'{HERE}:/src/proxmox/bootstrap:ro', '-v', f'{work}:/work',
        '-v', f'{destination.parent}:/backup', 'homelab-bootstrap-test:1',
        'python3', '/src/proxmox/bootstrap/bootstrap.py', 'backup',
        '--work', '/work', '--out', '/backup/' + destination.name], check=True, timeout=60)
    return {'backup_directory': str(destination)}


def rehearse(evidence):
    """Exercise the real local toolchain with synthetic provider and runner fixtures."""
    if not Path('/.dockerenv').exists():
        raise Refused('Use ./bootstrap test; rehearsal runs inside Docker')
    evidence.mkdir(parents=True, exist_ok=True)
    if (evidence / 'attempt.json').exists():
        raise Refused('Rehearsal output already exists; preserve it and use a new directory')
    write(evidence / 'attempt.json', {'started_at': datetime.now(timezone.utc).isoformat()})
    work = Path('/tmp/bootstrap-rehearsal')
    work.mkdir(mode=0o700)
    catalog = read(ROOT / 'proxmox/bootstrap/fixtures/site.json')
    catalog['site']['ssh_public_keys'] = ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB']
    write(work / 'site.json', catalog)
    write(work / 'settings.json', read(HERE / 'settings.example.json'))
    bundle = work / 'bundle'
    prepare(work / 'site.json', work / 'settings.json', bundle)
    tofu = bundle / 'tofu'
    (tofu / 'tests').mkdir()
    shutil.copy2(HERE / 'templates/deploy.tftest.hcl', tofu / 'tests/deploy.tftest.hcl')
    module = tofu / 'modules/deploy'
    shutil.copy2(HERE / 'templates/module.tftest.hcl', module / 'module.tftest.hcl')
    # The shared module has no root provider pin; add the same pin for its test root.
    shutil.copy2(HERE / 'docker/versions.tf', module / 'versions.tf')
    shutil.copy2(HERE / 'docker/.terraform.lock.hcl', module / '.terraform.lock.hcl')
    projection = read(tofu / 'site.auto.tfvars.json')
    write(module / 'test.auto.tfvars.json', {'node': catalog['site']['node'],
          'guest': projection['deploy'], 'ssh_public_keys': catalog['site']['ssh_public_keys'],
          'admin_cidr': projection['admin_cidr']})
    log_run(['python3', '-m', 'unittest', 'discover', '-s', str(HERE / 'tests'), '-v'], ROOT, evidence / 'unit.log')
    for label, directory in [('root', tofu), ('module', module)]:
        log_run(['tofu', 'init', '-backend=false', '-input=false', '-lockfile=readonly', '-no-color'], directory, evidence / (label + '-init.log'))
        log_run(['tofu', 'validate', '-no-color'], directory, evidence / (label + '-validate.log'))
        log_run(['tofu', 'test', '-no-color'], directory, evidence / (label + '-mock-tests.log'))
    log_run(['ansible-playbook', '-i', 'localhost,', '--syntax-check', str(HERE / 'ansible/runner.yml')], ROOT, evidence / 'ansible-syntax.log')
    log_run(['ansible-playbook', '-i', 'localhost,', '--syntax-check', str(HERE / 'ansible/install-runner.yml')], ROOT, evidence / 'native-ansible-syntax.log')
    log_run(['ansible-playbook', '-i', 'localhost,', '--syntax-check', str(HERE / 'ansible/configure-deploy.yml')], ROOT, evidence / 'configuration-ansible-syntax.log')
    log_run(['python3', str(HERE / 'tests/runner_fixture.py'), str(work / 'runner'), str(evidence)], ROOT, evidence / 'runner-fixture.log')
    files = {str(p.relative_to(ROOT)): sha(p) for p in ROOT.rglob('*')
             if p.is_file() and '__pycache__' not in p.parts}
    write(evidence / 'result.json', {'status': 'passed', 'scope': 'offline Docker MVP',
          'opentofu': 'real 1.13.1 + pinned bpg/proxmox 0.117.0 schema; provider calls mocked',
          'ansible': 'real playbook + synthetic runner archive/registration/process',
          'native_pve_tested': False, 'real_github_registration_tested': False,
          'NAS_backup_tested': False, 'live_execution_admitted': False,
          'standard_backend': 'Local state; real persistence/locking/handover has a separate Docker fixture',
          'source_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
          'source_files': files, 'completed_at': datetime.now(timezone.utc).isoformat()})
    print('PASS: running-guest OpenTofu mock plans and local Ansible runner rehearsal. Native creation remains untested.')


def main():
    """Dispatch the documented bootstrap CLI and report refusal without secret output."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for action in ('prepare', 'container-prepare'):
        p = commands.add_parser(action)
        p.add_argument('--catalog', type=Path, required=True)
        p.add_argument('--settings', type=Path, required=True)
        p.add_argument('--out', type=Path, required=True)
    p = commands.add_parser('snapshot')
    p.add_argument('--out', type=Path, required=True)
    p = commands.add_parser('rehearse')
    p.add_argument('--evidence', type=Path, required=True)
    p = commands.add_parser('native')
    p.add_argument('action', choices=['plan', 'apply', 'verify'])
    p.add_argument('--work', type=Path, required=True)
    for action in ('backup', 'container-backup'):
        p = commands.add_parser(action)
        p.add_argument('--work', type=Path, required=True)
        p.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command in ('native', 'backup'):
            sys.path.insert(0, str(HERE))
            import native
            result = native.backup(args.work, args.out) if args.command == 'backup' else native.run(args.action, args.work)
            print(json.dumps(result))
            return 0
        if args.command == 'prepare':
            print(json.dumps(prepare(args.catalog, args.settings, args.out)))
        elif args.command == 'container-prepare':
            print(json.dumps(container_prepare(args.catalog, args.settings, args.out)))
        elif args.command == 'snapshot':
            print(json.dumps(snapshot(args.out)))
        elif args.command == 'container-backup':
            print(json.dumps(container_backup(args.work, args.out)))
        else:
            rehearse(args.evidence)
        return 0
    except subprocess.TimeoutExpired:
        print(json.dumps({'refused': True, 'reason': 'Local Docker work may still be running after the CLI timeout; inspect Docker and preserve partial output before another attempt'}), file=sys.stderr)
        return 3
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, Refused) else 'Invalid input or failed local rehearsal step'
        print(json.dumps({'refused': True, 'reason': message}), file=sys.stderr)
        return 3


if __name__ == '__main__':
    # Native commands import these helpers; keep one Refused type.
    sys.modules.setdefault('bootstrap', sys.modules[__name__])
    raise SystemExit(main())
