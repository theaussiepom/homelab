"""Coordinate one existing PostgreSQL server and its two existing SQL clients.

The driver supplies the reviewed saved-plan and service-specific boundaries.
This module owns ordering and durable group custody, not guest installation,
database restoration, automatic recovery or permission to perform the change.
"""
from contextlib import ExitStack
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from database_network_maintenance import digest, encoded, regular, require, write_new

ROLES = ('postgresql', 'identity', 'db-tools')
SERVER_ROLES = ('mariadb', 'influxdb')


def roles_of(value):
    if value.get('schema') == 'homelab-database-server-cutover-v1':
        members = value.get('members', {})
        require(isinstance(members, dict) and len(members) == 1
                and next(iter(members)) in SERVER_ROLES, 'Select exactly one existing database server')
        return tuple(members)
    return ROLES


def engine_of(value):
    return roles_of(value)[0]


def client_ids(value):
    roles = roles_of(value)
    if roles == ROLES:
        return sorted(value['members'][role]['vmid'] for role in ROLES[1:])
    rows = value['members'][roles[0]]['runtime_packet'].get('clients')
    require(isinstance(rows, list) and rows and all(isinstance(row, dict) and type(row.get('vmid')) is int for row in rows),
            'Bind the server catalogue client subset; this does not activate clients')
    ids = [row['vmid'] for row in rows]
    require(len(ids) == len(set(ids)), 'Duplicate catalogue client selection')
    return sorted(ids)


def packet(value):
    require(isinstance(value, dict) and set(value) == {
        'schema', 'operation', 'catalogue_sha256', 'members'}, 'Use the closed coordinated cutover packet')
    roles = roles_of(value); engine = engine_of(value)
    require(value['schema'] in {'homelab-postgresql-cutover-v1', 'homelab-database-server-cutover-v1'}
            and isinstance(value['operation'], str)
            and re.fullmatch(engine + r'-[a-z0-9][a-z0-9-]{0,63}', value['operation'])
            and isinstance(value['catalogue_sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', value['catalogue_sha256'])
            and isinstance(value['members'], dict) and set(value['members']) == set(roles),
            'Select one finite PostgreSQL/server-client operation')
    ids = []
    for role in roles:
        member = value['members'][role]
        require(isinstance(member, dict) and set(member) == {
            'vmid', 'installer_revision', 'adapter_revision', 'plan_directory',
            'network_packet', 'runtime_packet', 'startup'}, 'Bind each complete member operation')
        require(type(member['vmid']) is int and member['vmid'] >= 100
                and member['vmid'] not in {900, 4914, 4915, 4920}
                and all(isinstance(member[k], str) and re.fullmatch('[0-9a-f]{40}', member[k])
                        for k in ('installer_revision', 'adapter_revision'))
                and isinstance(member['plan_directory'], str)
                and re.fullmatch(r'database-network-plan-[a-zA-Z0-9-]{1,100}', member['plan_directory'])
                and isinstance(member['network_packet'], dict)
                and member['network_packet'].get('vmid') == member['vmid']
                and member['network_packet'].get('allow_guest_restart') is True
                and isinstance(member['runtime_packet'], dict)
                and isinstance(member['startup'], dict)
                and set(member['startup']) == {'gate_sha256', 'dependency_sha256'}
                and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                        for v in member['startup'].values()), 'Invalid member binding or lifecycle selection')
        ids.append(member['vmid'])
    require(len(set(ids)) == len(roles), 'Every cutover role must select a different existing guest')
    if roles != ROLES:
        client_ids(value)
        import database_server_network_runtime
        database_server_network_runtime.validate(value['members'][engine]['runtime_packet'])
    return value


def validate_catalogue(value, catalogue):
    """Source-only exact server membership check, before native driver creation."""
    if roles_of(value) == ROLES:
        return
    import database_networks
    from database_network_server import clients
    engine = engine_of(value); member = value['members'][engine]
    network = database_networks.selected(catalogue, engine)
    require(member['vmid'] == network['server']['vmid']
            and member['runtime_packet']['endpoint'] == database_networks.endpoint(catalogue, engine)
            and member['runtime_packet']['clients'] == clients(catalogue, engine, client_ids(value)),
            'Bind this server and its explicit catalogue client subset; no app activation')


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Use an existing owned private cutover directory')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(directory, name, value, driver):
    """A failed NAS copy is a hold, never permission for a local-only action."""
    raw = encoded(value)
    write_new(directory / name, raw)
    sync(directory)
    driver.custody(name, raw)


def run(value, state, driver, *, verify_only=False):
    """One-use ordered execution; completed later runs invoke only verification.

    Driver.preflight must inspect all three guests and validate every saved
    plan/runtime binding before either SQL client is quiesced. Driver methods
    raise on ambiguity/failure. There is deliberately no automatic continuation.
    """
    selected = packet(value)
    roles = roles_of(selected)
    state = Path(state); private_directory(state)
    directory = state / ('database-network-cutover-' + selected['operation'])
    raw = encoded(selected)
    with ExitStack() as stack:
        lock = stack.enter_context(os.fdopen(os.open(state / 'database-network.lock',
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+'))
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for previous in state.glob('database-network-cutover-*'):
            private_directory(previous)
            require(not (previous / 'HOLD.json').exists()
                    and not (previous / 'HOLD.json').is_symlink()
                    and not (previous / 'VERIFYING.json').exists()
                    and not (previous / 'VERIFYING.json').is_symlink()
                    and ((previous / 'complete.json').is_file() or previous == directory),
                    'Preserve the failed or interrupted coordinated cutover; no automatic replay')
        if directory.exists() or directory.is_symlink():
            private_directory(directory)
            require((directory / 'complete.json').is_file(), 'This coordinated attempt is already claimed')
            marker = encoded({'packet_sha256': digest(raw), 'automatic_retry': False})
            write_new(directory / 'VERIFYING.json', marker); sync(directory)
            try:
                require(regular(directory / 'request.json') == regular(directory / 'claim.json') == raw,
                        'Completed cutover request/claim changed')
                driver.check_custody('request.json', raw)
                driver.check_custody('claim.json', raw)
                driver.check_custody('complete.json', regular(directory / 'complete.json'))
                for role in roles:
                    result = driver.verify(role, selected['members'][role])
                    require(isinstance(result, dict) and result.get('status') == 'passed',
                            'A maintained member did not verify successfully')
                require(regular(directory / 'VERIFYING.json') == marker, 'Verification marker changed')
                (directory / 'VERIFYING.json').unlink(); sync(directory)
                return {'status': 'passed', 'changed': False, 'operation': selected['operation']}
            except Exception as error:
                write_new(directory / 'HOLD.json', encoded({'phase': 'later-verification',
                    'error_type': type(error).__name__, 'automatic_retry': False}))
                sync(directory)
                raise
        require(not verify_only, 'The selected cutover has not completed; verification cannot apply it')
        directory.mkdir(mode=0o700); sync(state)
        phase = 'admission'
        try:
            record(directory, 'request.json', selected, driver)
            # All admission is performed before the first service interruption.
            for role in roles:
                result = driver.preflight(role, selected['members'][role])
                require(isinstance(result, dict) and result.get('status') in {'passed', 'admitted'},
                        'A coordinated member did not pass admission')
            record(directory, 'claim.json', selected, driver)
            sequence = [('quiesce', role) for role in roles[1:]]
            # PG keeps eth0/eth1 names, so update its gate while the old
            # listener is still healthy. A provider NIC update may cycle the
            # guest before its new listener configuration can be activated.
            sequence += [('startup', roles[0])]
            sequence += [('network', role) for role in roles]
            sequence += [('startup', role) for role in roles[1:]]
            sequence += [('activate', role) for role in roles]
            sequence += [('verify', role) for role in roles]
            for index, (phase, role) in enumerate(sequence):
                result = getattr(driver, phase)(role, selected['members'][role])
                require(isinstance(result, dict) and result.get('status') in {'passed', 'network_overlay_verified'},
                        'A coordinated phase did not pass')
                record(directory, f'{index:02d}-{phase}-{role}.json',
                       {'phase': phase, 'role': role, 'result': result}, driver)
            complete = {'status': 'passed', 'operation': selected['operation'],
                        'packet_sha256': digest(raw), 'roles': list(roles)}
            record(directory, 'complete.json', complete, driver)
            return {'status': 'passed', 'changed': True, 'operation': selected['operation']}
        except Exception as error:
            # Never resume clients on a guessed partially changed SQL path.
            # The request also catches SIGKILL/power loss before this marker.
            write_new(directory / 'HOLD.json', encoded({'phase': phase,
                'error_type': type(error).__name__, 'automatic_retry': False}))
            sync(directory)
            raise


class NativeDriver:
    """Fixed worker calls; packets cannot supply executable commands or paths."""
    def __init__(self, selected, state, helper, catalogue, installers, adapters):
        from database_network_worker import INPUTS, site_path, source_revision
        self.selected = packet(selected)
        roles, engine = roles_of(selected), engine_of(selected)
        self.state, self.helper, self.catalogue = Path(state), Path(helper), Path(catalogue)
        self.installers, self.adapters = installers, adapters
        self.directory = self.state / ('database-network-cutover-' + selected['operation'])
        require(digest(regular(self.catalogue, private=False)) == selected['catalogue_sha256'],
                'The exact private database catalogue changed')
        configs, requests = [], []
        for role in roles:
            member = selected['members'][role]
            source_revision(installers[role], member['installer_revision'])
            source_revision(adapters[role], member['adapter_revision'])
            cfg = json.loads(regular(site_path(role)))
            require(cfg['app']['kind'] == role and cfg['guest']['vmid'] == member['vmid']
                    and cfg['paths']['state_root'] == str(self.state), 'A coordinated member identity differs')
            configs.append(cfg)
            request = json.loads(regular(self.state / str(member['vmid']) / member['plan_directory'] / 'request.json'))
            requests.append(request)
            require(request.get('engine') == engine and request.get('phase') == 'cutover'
                    and request.get('catalogue_sha256') == selected['catalogue_sha256']
                    and sorted(request.get('client_vmids', [])) == client_ids(selected),
                    'Every plan must bind exactly this group and catalogue, without future clients')
        require(len({r['legacy_server_address'] for r in requests}) == 1
                and all(c['site'] == configs[0]['site'] for c in configs),
                'All members must bind the same old PostgreSQL endpoint and Proxmox site')
        # Membership and endpoint identity come from the one private catalogue.
        import database_networks
        catalogue_value = json.loads(regular(self.catalogue, private=False))
        network = database_networks.selected(catalogue_value, engine)
        require(network['server']['vmid'] == selected['members'][roles[0]]['vmid'],
                'Select the catalogue PostgreSQL server')
        for vmid in client_ids(selected):
            database_networks.selected(catalogue_value, engine, vmid)
        fields = ('backup_mount', 'backup_directory', 'backup_source')
        require(all(tuple(c['paths'][f] for f in fields) == tuple(configs[0]['paths'][f] for f in fields)
                    for c in configs), 'All selected members must share their established NAS custody route')
        self.paths = configs[0]['paths']
        self.remote = Path(self.paths['backup_directory']) / ('database-network-cutover-' + selected['operation'])

    def nas(self, *, create=False):
        mount = Path(self.paths['backup_mount'])
        require(mount.is_absolute() and os.path.ismount(mount), 'The existing NAS custody mount is unavailable')
        rows = subprocess.check_output(['findmnt', '-rn', '-o', 'FSTYPE,SOURCE', '--target', str(mount)],
                                       text=True, timeout=10).strip().splitlines()
        selected = [row.split() for row in rows if row.split() and row.split()[0] in {'nfs', 'nfs4', 'cifs'}]
        require(len(selected) == 1 and len(selected[0]) == 2
                and selected[0][1] == self.paths['backup_source'], 'The existing NAS route differs')
        require(mount.resolve() in self.remote.resolve().parents
                and not any(p.is_symlink() for p in [self.remote, *self.remote.parents]),
                'Keep group custody below the established NAS directory')
        if create and not self.remote.exists():
            self.remote.mkdir(mode=0o700); sync(self.remote.parent)
        private_directory(self.remote)

    def custody(self, name, raw):
        self.nas(create=True)
        write_new(self.remote / name, raw); sync(self.remote)
        require(regular(self.remote / name) == raw, 'NAS group custody readback differs')

    def check_custody(self, name, raw):
        self.nas()
        require(regular(self.remote / name) == raw, 'NAS completed group custody differs')

    def call(self, action, role, member):
        if role == 'identity' and action in {'quiesce', 'activate', 'verify'}:
            self.check_custody('identity-original-compose.yml', self.identity_recovery(member))
        member_path = self.directory / (role + '-member.json')
        if member_path.exists() or member_path.is_symlink():
            require(regular(member_path) == encoded(member), 'Group member custody changed')
        else:
            write_new(member_path, encoded(member))
        command = ['python3', str(self.helper / 'proxmox/applications/database_network_worker.py'),
            '--action', action, '--role', role, '--member', str(member_path),
            '--installer', str(self.installers[role]), '--adapter', str(self.adapters[role]),
            '--catalogue', str(self.catalogue), '--operation', self.selected['operation']]
        for vmid in client_ids(self.selected): command += ['--client-vmid', str(vmid)]
        if role == 'db-tools' and action in {'activate', 'verify'}:
            phase_name = '01-quiesce-db-tools.json'
            self.check_custody(phase_name, regular(self.directory / phase_name))
            command += ['--quiesce-receipt', str(self.directory / phase_name)]
        result = subprocess.run(command, capture_output=True, check=True, timeout=900, umask=0o077)
        require(len(result.stdout) <= 1024 * 1024, 'Oversized private member result')
        return json.loads(result.stdout)

    def identity_recovery(self, member):
        from database_network_worker import identity_recovery
        path = self.state / str(member['vmid']) / ('database-network-runtime-' + self.selected['operation'])
        return identity_recovery(member, path)

    def preflight(self, role, member):
        result = self.call('preflight', role, member)
        if role == 'identity':
            raw = self.identity_recovery(member)
            require(result.get('recovery_sha256') == digest(raw), 'The admitted Compose recovery copy differs')
            self.custody('identity-original-compose.yml', raw)
        return result
    def quiesce(self, role, member): return self.call('quiesce', role, member)
    def network(self, role, member): return self.call('network', role, member)
    def startup(self, role, member): return self.call('startup', role, member)
    def activate(self, role, member): return self.call('activate', role, member)
    def verify(self, role, member): return self.call('verify', role, member)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--catalogue', type=Path, required=True)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    for role in (*ROLES, *SERVER_ROLES):
        parser.add_argument('--' + role + '-installer', type=Path)
        parser.add_argument('--' + role + '-adapter', type=Path)
    args = parser.parse_args(); os.umask(0o077)
    try:
        selected = packet(json.loads(regular(args.packet, private=False)))
        require(digest(regular(args.catalogue, private=False)) == selected['catalogue_sha256'],
                'The private catalogue differs from the selected packet')
        validate_catalogue(selected, json.loads(regular(args.catalogue, private=False)))
        if args.validate_only:
            print(json.dumps({'status': 'source_validated', 'target_contacted': False}))
            return
        installers, adapters = {}, {}
        for role in roles_of(selected):
            installer, adapter = (getattr(args, role.replace('-', '_') + '_' + suffix)
                                  for suffix in ('installer', 'adapter'))
            require(installer is not None and adapter is not None, 'Supply each independent pinned checkout')
            installers[role], adapters[role] = installer.resolve(), adapter.resolve()
        state, helper = Path('/var/lib/homelab-applications'), Path(__file__).resolve().parents[2]
        driver = NativeDriver(selected, state, helper, args.catalogue.resolve(), installers, adapters)
        result = run(selected, state, driver, verify_only=args.verify_only)
        print(json.dumps(result))
    except Exception as error:
        raise SystemExit('Coordinated database cutover held (' + type(error).__name__ + '); no automatic replay') from None


if __name__ == '__main__': main()
