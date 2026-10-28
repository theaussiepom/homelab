"""Verify one accepted PostgreSQL service member; never execute a cutover.

The original network implementation and installed sources remain pinned. The
completed request is provenance, not an instruction to resume its phases. Each
Actions job checks only its own member, so independent guests can run together.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROLES = ('postgresql', 'identity', 'db-tools')
SCHEMA = 'homelab-postgresql-service-verification-v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def selection(value, packet, catalogue, desired, acceptance):
    """Validate static source provenance without contacting any target."""
    require(isinstance(value, dict) and set(value) == {
        'schema', 'request_sha256', 'complete_sha256', 'catalogue_sha256',
        'acceptance_sha256', 'network_revision', 'service_revision'}, 'Use the closed service selection')
    require(value['schema'] == SCHEMA, 'Unknown service selection')
    for key in ('request_sha256', 'complete_sha256', 'catalogue_sha256', 'acceptance_sha256'):
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{64}', value[key]), 'Invalid evidence hash')
    for key in ('network_revision', 'service_revision'):
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{40}', value[key]), 'Pin each source')
    require(sha(packet) == value['request_sha256'] and sha(catalogue) == value['catalogue_sha256']
            and sha(acceptance) == value['acceptance_sha256'], 'Preserve the accepted original evidence')
    request = json.loads(packet)
    require(request.get('schema') == 'homelab-postgresql-cutover-v1'
            and set(request.get('members', {})) == set(ROLES)
            and request.get('catalogue_sha256') == value['catalogue_sha256'], 'Invalid original group')
    original, current = json.loads(catalogue), json.loads(desired)
    require(original.get('schema') == current.get('schema') == 'homelab-database-networks-v1'
            and original['networks']['postgresql'] == current['networks']['postgresql'],
            'The accepted PostgreSQL network or its client declarations changed')
    accepted = json.loads(acceptance)
    require(accepted.get('status') == 'network31_group_and_saved_credential_SQL_accepted'
            and accepted.get('qualified_request_sha256') == value['request_sha256']
            and accepted.get('qualified_completion_sha256') == value['complete_sha256'],
            'Require explicit completed service acceptance')
    return request


def source_revision(path, expected):
    require(subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'],
            text=True, timeout=10).strip() == expected, 'A selected source checkout changed')


def load_worker(helper):
    """A fresh process keeps the historical network module imports isolated."""
    root = helper / 'proxmox/applications'
    require('database_network_worker' not in sys.modules and 'deploy' not in sys.modules,
            'Use a fresh interpreter for each guest')
    sys.path.insert(0, str(root))
    worker = importlib.import_module('database_network_worker')
    require(Path(worker.__file__).resolve() == root / 'database_network_worker.py',
            'Load only the pinned network worker')
    return worker


def completed(worker, request, value, cfg, state):
    """Read original local/NAS custody and refuse failed or incomplete work."""
    from database_network_cutover import private_directory
    private_directory(state)
    group = state / ('database-network-cutover-' + request['operation'])
    private_directory(group)
    for directory in state.glob('database-network-cutover-*'):
        private_directory(directory)
        for name in ('HOLD.json', 'VERIFYING.json', 'ACTIVATION-FINISH-HOLD.json'):
            require(not (directory / name).exists() and not (directory / name).is_symlink(),
                    'Preserve unresolved group failure evidence')
        require((directory / 'complete.json').is_file(), 'An incomplete group still owns its guests')
    # Reuse the original NAS identity/readback check without constructing a
    # driver or exposing any coordinator action method.
    mount = Path(cfg['paths']['backup_mount'])
    require(os.path.ismount(mount), 'The existing NAS mount is unavailable')
    rows = subprocess.check_output(['findmnt', '-rn', '-o', 'FSTYPE,SOURCE', '--target', str(mount)],
                                   text=True, timeout=10).splitlines()
    rows = [r.split() for r in rows if r.split() and r.split()[0] in {'nfs', 'nfs4', 'cifs'}]
    require(len(rows) == 1 and rows[0] == [rows[0][0], cfg['paths']['backup_source']], 'The NAS route changed')
    remote = Path(cfg['paths']['backup_directory']) / group.name
    require(mount.resolve() in remote.resolve().parents
            and not any(p.is_symlink() for p in [remote, *remote.parents]), 'Preserve the existing NAS custody path')
    private_directory(remote)
    for name in ('request.json', 'claim.json', 'complete.json'):
        raw = worker.regular(group / name)
        require(raw == worker.regular(remote / name), 'Local and NAS completion custody differ')
        expected = value['complete_sha256'] if name == 'complete.json' else value['request_sha256']
        require(sha(raw) == expected, 'The accepted request or completion changed')
    result = json.loads(worker.regular(group / 'complete.json'))
    require(result == {'status': 'passed', 'operation': request['operation'],
                       'packet_sha256': value['request_sha256'], 'roles': list(ROLES)}, 'Invalid group completion')
    return group, remote


@contextmanager
def verification_hold(worker, work, value):
    """Keep failed verification durable without modifying cutover history."""
    path = work / 'SERVICE-VERIFYING.json'
    failure = work / 'SERVICE-VERIFY-HOLD.json'
    marker = encoded({'request_sha256': value['request_sha256'], 'automatic_retry': False,
                      'phase': 'normal-service-verification'})
    require(not failure.exists() and not failure.is_symlink(), 'Preserve the failed normal service check')
    # An in-progress claim is not a failure. The pinned network verifier
    # correctly refuses *HOLD.json, including a failure from this normal check.
    worker.maintenance.write_new(path, marker)
    worker.network_apply.sync(work)
    try:
        yield
        require(worker.regular(path) == marker, 'Verification hold ownership changed')
        path.unlink()
        worker.network_apply.sync(work)
    except BaseException:
        worker.maintenance.write_new(failure, marker)
        worker.network_apply.sync(work)
        # Keep the claim too: an interrupted or failed check cannot replay.
        raise


def verify(role, value, request, helper, installer, source, catalogue, *, state=Path('/var/lib/homelab-applications')):
    require(role in ROLES, 'Select one declared service')
    source_revision(helper, value['network_revision'])
    source_revision(source, value['service_revision'])
    source_revision(installer, request['members'][role]['installer_revision'])
    worker = load_worker(helper)
    member = request['members'][role]
    cfg_path = worker.site_path(role)
    cfg = json.loads(worker.regular(cfg_path))
    require(cfg['app']['kind'] == role and cfg['guest']['vmid'] == member['vmid']
            and cfg['paths']['state_root'] == str(state), 'The installed service identity changed')
    # Shared group admission allows independent member jobs. A network cutover
    # still needs the original exclusive lock; each guest retains its own locks.
    with os.fdopen(os.open(state / 'database-network.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        group, remote = completed(worker, request, value, cfg, state)
        work = state / str(member['vmid'])
        from database_network_cutover import private_directory
        private_directory(work)
        with verification_hold(worker, work, value):
            # The helper imports its pure catalogue reader first. Do not let
            # that module substitute for an installed foundation source.
            sys.modules.pop('site_config', None)
            sys.path.insert(0, str(installer / 'proxmox/applications'))
            deployment = importlib.import_module('deploy')
            require(Path(deployment.__file__).resolve() == installer / 'proxmox/applications/deploy.py',
                    'Use only the commissioned installer')
            deployment.validate(cfg)
            directory = work / ('database-network-runtime-' + request['operation'])
            private_directory(directory)
            packet_path = directory / 'network-packet.json'
            require(worker.regular(packet_path) == encoded(member['network_packet']), 'The original member packet changed')
            args = (deployment, cfg_path, catalogue, work / member['plan_directory'], packet_path, sha(worker.regular(packet_path)))
            context = worker.network_apply.load(*args)
            worker.bind_runtime(role, member['runtime_packet'], context, source,
                                [request['members'][r]['vmid'] for r in ROLES[1:]])
            worker.network_apply.verify(*args)
            worker.startup_probe(deployment, cfg, json.loads(worker.regular(directory / 'startup-after.json')))
            if role == 'identity':
                original = worker.identity_recovery(member, directory)
                require(original == worker.regular(remote / 'identity-original-compose.yml'), 'Original Compose custody changed')
            if role != 'db-tools':
                result = worker.runtime(deployment, cfg, source, role, member, directory, 'verify')
            else:
                name = '01-quiesce-db-tools.json'
                raw = worker.regular(group / name)
                require(raw == worker.regular(remote / name), 'Original pgAdmin quiesce custody changed')
                receipt = json.loads(raw)
                require(receipt.get('phase') == 'quiesce' and receipt.get('role') == role
                        and receipt.get('result', {}).get('status') == 'passed'
                        and receipt['result'].get('action') == 'quiesce', 'Invalid original quiesce receipt')
                projected = dict(member['runtime_packet'], quiesced=receipt['result']['quiesced'])
                output = directory / ('service-binding-' + str(time.time_ns()) + '.json')
                worker.ansible(deployment, cfg, source, 'pgadmin-service-binding.yml',
                    {'app': cfg['app'], 'pgadmin_service_request': projected,
                     'pgadmin_service_result_path': str(output)}, directory, 'service-binding')
                binding = json.loads(worker.regular(output))
                require(binding.get('status') == 'passed' and binding.get('kind') == 'pgadmin-accepted-binding',
                        'The original backup projection did not pass')
                output = directory / ('service-verify-' + str(time.time_ns()) + '.json')
                worker.ansible(deployment, cfg, source, 'pgadmin-service-verify.yml',
                    {'app': cfg['app'], 'pgadmin_service_binding': binding['binding'],
                     'pgadmin_service_result_path': str(output)}, directory, 'service-verify')
                result = json.loads(worker.regular(output))
            require(result.get('status') == 'passed' and result.get('changed') is False,
                    'The accepted service did not verify without changes')
            return {'status': 'passed', 'role': role, 'changed': False, 'current_browser_sql_tested': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'packet', 'catalogue', 'desired-catalogue', 'acceptance'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--role', choices=ROLES)
    for name in ('helper', 'installer'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(args.selection.read_bytes())
        request = selection(value, args.packet.read_bytes(), args.catalogue.read_bytes(),
                            args.desired_catalogue.read_bytes(), args.acceptance.read_bytes())
        if args.validate_only:
            result = {'status': 'source_validated', 'target_contacted': False}
        else:
            require(args.role and args.helper and args.installer, 'Supply one member and its original source')
            result = verify(args.role, value, request, args.helper.resolve(), args.installer.resolve(),
                            Path(__file__).resolve().parents[2], args.catalogue.resolve())
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Accepted service verification held; preserve evidence. No automatic recovery or replay.') from None


if __name__ == '__main__':
    main()
