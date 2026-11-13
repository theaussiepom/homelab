#!/usr/bin/env python3
"""Guest-local capture/readback worker; no live restore, deployment or repair."""
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import select
import time
import stat
import shutil
import subprocess
import sys
import uuid

import backup_capture
from private_io import decode_json, encoded, digest, private_directory, private_writer, read_json, regular, require, sync, write_new

CONFIG = Path('/etc/homelab-backup')


class Engine:
    """Run bounded fixed commands with output private and no inherited credentials."""
    def __init__(self, log, limits, abort_stream=None):
        """Bind private command output, selected limits and the coordinator pipe."""
        self.log, self.limits, self.abort_stream = log, limits, abort_stream
        self.begin_phase()

    def begin_phase(self):
        """Start a fresh bounded budget for the next native phase."""
        self.deadline = time.monotonic() + self.limits['timeout_seconds']

    def run(self, argv, *, output=None, environment=None, restore=False):
        def bounded():
            """Set the child output-file size limit before executing a native command."""
            resource.setrlimit(resource.RLIMIT_FSIZE, (self.limits['max_bytes'], self.limits['max_bytes']))
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(self.log.parent), 'LC_ALL': 'C'}
        env.update(environment or {})
        require(not restore or argv[:2] == ['docker', 'compose'] and ('start' in argv or 'ps' in argv),
                'Only restarting the admitted paused service may use the completion allowance')
        timeout = 90 if restore else self.deadline - time.monotonic()
        require(timeout > 0, 'The backup operation exceeded its duration budget')
        with private_writer(self.log, append=True) as log:
            with ExitStack() as stack:
                target = log if output is None else stack.enter_context(private_writer(output, exclusive=True))
                child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=target, stderr=log, env=env,
                    start_new_session=True, preexec_fn=bounded)
                try:
                    end = time.monotonic()+timeout
                    while True:
                        remaining = end-time.monotonic()
                        require(remaining > 0, 'The native command exceeded its operation budget')
                        try:
                            code = child.wait(timeout=min(remaining, .25) if self.abort_stream is not None and not restore else remaining)
                            break
                        except subprocess.TimeoutExpired:
                            if self.abort_stream is None or restore: raise
                            require(not select.select([self.abort_stream], [], [], 0)[0],
                                    'The backup coordinator disconnected or violated its command barrier')
                except BaseException:
                    os.killpg(child.pid, signal.SIGTERM)
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait()
                    raise
        require(code == 0, 'A native backup command failed; preserve the protected generation')


def inventory(paths, exclusions, limits):
    """Refuse missing/special inputs and bound the selected tree before capture."""
    count, total = 0, 0
    for row in paths:
        root = Path(row['path'])
        require(all(stat.S_ISDIR(parent.lstat().st_mode) for parent in root.parents),
                'Selected capture roots cannot traverse a symlink ancestor')
        info = root.lstat()
        require((stat.S_ISREG(info.st_mode) if row['kind'] == 'file' else stat.S_ISDIR(info.st_mode)),
                'A selected recovery root has the wrong type or is a symlink')
        pending = [root]
        while pending:
            path = pending.pop()
            if any(str(path) == exclude or str(path).startswith(exclude + '/') for exclude in exclusions):
                continue
            info = path.lstat(); count += 1
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode),
                    'Selected backup material contains a socket or device')
            if stat.S_ISDIR(info.st_mode):
                require(info.st_dev == root.lstat().st_dev, 'Do not traverse an undeclared nested mount')
                for child in path.iterdir():
                    require(count+len(pending)+1 <= limits['max_files'], 'Bound directory intake before queuing entries')
                    pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
            require(count <= limits['max_files'] and total <= limits['max_bytes'],
                    'The selected backup exceeds its admitted file/byte bound')
    return {'files': count, 'bytes': total}


def manifest(directory, limits):
    """Digest a bounded completed generation; never follow links in an export."""
    result = {}; total = 0; entries = 0
    for path in directory.rglob('*'):
        entries += 1
        require(entries <= limits['max_files'], 'Bound complete export entries before materialising a manifest')
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                'A native export contains an unsupported filesystem entry')
        if stat.S_ISDIR(info.st_mode):
            continue
        total += info.st_size
        require(total <= limits['max_bytes'] and len(result) < limits['max_files'],
                'The complete native export exceeds its admitted capacity')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1048576), b''):
                digest.update(block)
        after = path.lstat()
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'A completed native artifact changed during verification')
        result[str(path.relative_to(directory))] = {'bytes': info.st_size, 'sha256': digest.hexdigest()}
    require(result, 'A recovery generation cannot be empty')
    return result


def release_copy(directory, expected, limits):
    """Release only this operation's byte-verified temporary capture/readback."""
    require(manifest(directory, limits) == expected, 'Preserve a changed temporary recovery copy')
    for path in sorted(directory.rglob('*'), key=lambda path: len(path.parts), reverse=True):
        if path.is_dir():
            path.rmdir()
        else:
            path.unlink()
    directory.rmdir(); sync(directory.parent)


def ready(rows, operation, engine):
    """After all members restart, read container health without another start attempt."""
    deadline = time.monotonic()+60
    for index in range(60):
        healthy = True
        for row in rows:
            output = operation/(row['app']+'-health-'+str(index)+'.json')
            engine.run(backup_capture.compose(row, 'health'), output=output)
            raw = regular(output, private=True)
            states = decode_json(raw) if raw.lstrip().startswith(b'[') else [decode_json(line) for line in raw.splitlines()]
            require(isinstance(states, list) and len(states) == len(row['services'])
                    and all(isinstance(state, dict) for state in states)
                    and {state.get('Service') for state in states} == set(row['services'])
                    and all(state.get('State') == 'running' and state.get('Health', '') in ('', 'healthy', 'starting')
                        for state in states), 'A resumed owned service exited or became unhealthy')
            healthy = healthy and all(state.get('Health', '') != 'starting' for state in states)
        if healthy: return
        require(time.monotonic() < deadline, 'Resumed container health did not become ready within its allowance')
        time.sleep(1)
    raise ValueError('Resumed container health exceeded the bounded check count')


def run(value, *, root=None, config=CONFIG, engine=None, generation=None, barrier=None,
        backup_time=None, group_config=None, control_files=None, abort_stream=None, preflight=False):
    """Publish success only after export, local manifest, upload and snapshot check."""
    os.umask(0o077)
    require(type(preflight) is bool and (not preflight or barrier is None),
            'Readiness checks cannot open a coordinated capture window')
    root = Path(value['job']['staging']['path'])/'.homelab-backup' if root is None else root
    private_directory(root); private_directory(config)
    require(not (root/'PENDING').exists() and not (root/'PENDING').is_symlink(),
            'Preserve the prior failed or incomplete backup; never replay it')
    import backup_policy
    backup_policy.validate(value['job'])
    backup_policy.owner(value['owner'])
    if barrier is not None:
        import backup_group
        backup_group.configuration(group_config)
        require(value['job']['group']['member'] in group_config['members']
                and value['job']['group']['name'] == group_config['name']
                and all(group_config['members'][value['job']['group']['member']][key] == value['owner'][key]
                    for key in ('node', 'vmid', 'hostname')), 'Bind this coordinated recovery group')
    selected = backup_capture.normalize(value)
    recipes = backup_capture.recipes(value)
    limits = value['job']['limits']
    generation = uuid.uuid4().hex if generation is None else generation
    require(isinstance(generation, str) and len(generation) == 32
            and all(char in '0123456789abcdef' for char in generation), 'Use a fresh backup generation')
    backup_time = int(time.time()) if backup_time is None else backup_time
    require(type(backup_time) is int and backup_time > 0, 'Use the coordinated capture time')
    operation = root/generation
    require(shutil.disk_usage(root).free >= 3*limits['max_bytes'],
            'Reserve capacity for capture, encrypted transfer readback and retained failures')
    private_directory(operation, create=True)
    payload = operation/'payload'; private_directory(payload, create=True)
    engine = Engine(operation/'native.log', limits, abort_stream) if engine is None else engine
    paused = []
    receipt = {'schema': 'homelab-pbs-attempt-v1', 'generation': generation,
        'owner': value['owner'], 'status': 'started', 'completed_databases': [],
        'database_associations': {key: app['databases'] for key, app in value['applications'].items()}}
    write_new(operation/'started.json', encoded(receipt))
    try:
        # Validate inputs and repository reachability before any application interruption.
        dest = value['job']['destination']; owner = value['owner']
        backup_id = dest['backup_id']
        namespace = dest['namespace']+'/'+backup_id
        password = regular(config/'pbs-password', private=True).decode().strip()
        require(password and not any(char in password for char in '\r\n\x00'), 'Use a private PBS token secret')
        regular(config/'pbs-key', private=True)
        recovery = regular(config/'pbs-recovery-public.pem', private=True, limit=4096)
        require(digest(recovery) == value['job']['recovery_public_key']['sha256'],
                'Preserve the selected recovery public-key identity')
        env = {'PBS_PASSWORD': password, 'PBS_FINGERPRINT': dest['fingerprint']}
        if 'key_password' in value['job']['secrets']:
            env['PBS_ENCRYPTION_PASSWORD'] = regular(config/'pbs-key-password', private=True).decode().strip()
        common = ['--repository', dest['auth_id']+'@'+dest['server']+':'+str(dest['port'])+':'+dest['datastore'],
            '--ns', namespace]
        engine.run(['ip', '-j', 'route', 'get', dest['server']], output=operation/'route.json')
        route = read_json(operation/'route.json', private=True)
        require(isinstance(route, list) and len(route) == 1
                and route[0].get('dev') == value['job']['transport']['device']
                and route[0].get('prefsrc') == value['job']['transport']['address'],
                'Refuse an unselected backup route or management-network fallback')
        engine.run(['proxmox-backup-client', 'snapshot', 'list', '--output-format', 'json', *common],
            output=operation/'preflight-snapshots.json', environment=env)
        existing = read_json(operation/'preflight-snapshots.json', private=True)
        require(isinstance(existing, list) and all(isinstance(row, dict) for row in existing)
                and not any(row.get('backup-id') == backup_id and row.get('backup-time') == backup_time
                    for row in existing), 'Refuse an existing or malformed selected snapshot before capture')
        inventory(selected['include'], selected['exclude'], limits)
        if control_files is not None: controls(recipes, control_files)
        for row in recipes['pause']:
            output = operation/(row['app']+'-preflight-running.txt')
            engine.run(backup_capture.compose(row, 'ps'), output=output)
            running = output.read_text().splitlines()
            require(len(running) == len(row['services']) and set(running) == set(row['services']),
                    'Every selected service must be running before opening a capture window')
        if preflight:
            write_new(operation/'ready.json', encoded({**receipt, 'status': 'ready'}))
            return {'status': 'ready', 'generation': generation}
        if barrier is not None:
            barrier('prepared', {})
            engine.begin_phase()
        # Before this point every native operation was a preflight read. A new
        # scheduled attempt may follow a failed preflight, never replay its UUID.
        write_new(root/'PENDING', encoded({'generation': generation}))
        try:
            # Stop only services explicitly admitted by the job, never an app peer.
            for row in recipes['pause']:
                engine.run(backup_capture.compose(row, 'ps'), output=operation/(row['app']+'-running.txt'))
                running = (operation/(row['app']+'-running.txt')).read_text().splitlines()
                require(len(running) == len(row['services']) and set(running) == set(row['services']), 'Do not start a previously stopped or missing service')
                paused.append(row)
                engine.run(backup_capture.compose(row, 'stop'))
            if barrier is not None:
                barrier('paused', {})
            for row in recipes['databases']:
                target = payload/row['app']; private_directory(target, create=True)
                argv, output = backup_capture.database(row, target)
                database_env = None
                if row['type'] == 'influxdb':
                    token = regular(config/('influx-'+row['app']), private=True).decode().strip()
                    require(token and not any(char in token for char in '\r\n\x00'), 'Use one private Influx token')
                    database_env = {'INFLUX_TOKEN': token}
                engine.run(argv, output=None if output is None else target/output, environment=database_env)
                require(any(p.is_file() and p.stat().st_size for p in target.rglob('*')),
                        'A native database producer returned no recovery data')
                receipt['completed_databases'].append(row['app'])
            receipt['selected'] = inventory(selected['include'], selected['exclude'], limits)
            engine.run(backup_capture.archive(selected, payload/'configuration-and-state.tar'))
            # Include exact source ownership, consistency classifications and database relationships.
            write_new(payload/'inventory.json', encoded(value))
            data_manifest = encoded(manifest(payload, limits))
            data_sha = digest(data_manifest)
            write_new(payload/'data-manifest.json', data_manifest)
            if barrier is not None:
                barrier('captured', {'data_manifest_sha256': data_sha})
        finally:
            failures = []
            for row in reversed(paused):
                try:
                    engine.run(backup_capture.compose(row, 'start'), restore=True)
                    output = operation/(row['app']+'-restored.txt')
                    engine.run(backup_capture.compose(row, 'ps'), output=output, restore=True)
                    require(set(output.read_text().splitlines()) == set(row['services']),
                            'The previously running services did not return')
                except Exception:
                    failures.append(row['app'])
            require(not failures, 'A paused service did not restart; preserve backup and service evidence')
            paused.clear()
        if barrier is not None:
            import backup_group
            group = barrier('resumed', {})
            backup_group.received_set(group_config, generation, backup_time, group)
            require(group['members'][value['job']['group']['member']]['data_manifest_sha256'] == data_sha
                    and {key: group['members'][backup_id][key] for key in ('server', 'port', 'datastore', 'namespace')}
                        == {**{key: dest[key] for key in ('server', 'port', 'datastore')}, 'namespace': namespace},
                    'Preserve this guest completed native capture binding')
            write_new(payload/'group.json', encoded(group))
        engine.begin_phase()
        ready(recipes['pause'], operation, engine)
        expected_files = manifest(payload, limits)
        write_new(operation/'manifest.json', encoded(expected_files))
        engine.run(['proxmox-backup-client', 'backup', 'recovery.pxar:'+str(payload),
            '--backup-time', str(backup_time),
            '--backup-id', backup_id, '--crypt-mode', 'encrypt', '--keyfile', str(config/'pbs-key'),
            '--master-pubkey-file', str(config/'pbs-recovery-public.pem'),
            *common], environment=env)
        engine.run(['proxmox-backup-client', 'snapshot', 'list', '--output-format', 'json', *common],
            output=operation/'snapshots.json', environment=env)
        snapshots = read_json(operation/'snapshots.json', private=True)
        require(isinstance(snapshots, list) and any(row.get('backup-id') == backup_id
                and row.get('backup-type') == 'host' and row.get('backup-time') == backup_time
                for row in snapshots), 'PBS did not report the selected backup group')
        readback = operation/'readback'
        stamp = datetime.datetime.fromtimestamp(backup_time, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        envelope = operation/'rsa-encrypted.key'
        engine.run(['proxmox-backup-client', 'restore', 'host/'+backup_id+'/'+stamp,
            'rsa-encrypted.key', '-', '--keyfile', str(config/'pbs-key'), *common],
            output=envelope, environment=env)
        wrapped = regular(envelope, private=True, limit=512)
        require(len(wrapped) == 512, 'The snapshot is missing its complete RSA-4096 recovery envelope')
        engine.run(['proxmox-backup-client', 'restore', 'host/'+backup_id+'/'+stamp,
            'recovery.pxar', str(readback), '--keyfile', str(config/'pbs-key'), *common], environment=env)
        require(manifest(readback, limits) == expected_files and manifest(payload, limits) == expected_files,
                'Encrypted PBS archive readback does not match the complete immutable generation')
        if barrier is not None:
            barrier('uploaded', {'data_manifest_sha256': data_sha})
        release_copy(readback, expected_files, limits)
        release_copy(payload, expected_files, limits)
        receipt.update(status='uploaded', backup_time=backup_time, namespace=namespace, finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            archive_readback_verified=True, recovery_envelope_sha256=digest(wrapped),
            recovery_public_fingerprint=value['job']['recovery_public_key']['fingerprint'],
            restore_verified=False, cross_guest_transaction=False,
            coordinated_window=barrier is not None, data_manifest_sha256=data_sha)
        write_new(operation/'complete.json', encoded(receipt))
        # Keep every earlier receipt/manifest and every failed payload. Remote
        # history, pruning and retention belong to the separate PBS server owner.
        pointer = root/('success-'+generation+'.json')
        write_new(pointer, encoded(receipt))
        (root/'PENDING').unlink(); sync(root)
        return {'status': 'uploaded', 'generation': generation, 'restore_verified': False}
    except Exception as error:
        receipt.update(status='failed', error_type=type(error).__name__)
        write_new(operation/'failed.json', encoded(receipt))
        raise


def controls(recipes, expected):
    """Do not stop/start a foreign or edited Compose control file."""
    from private_io import sha
    paths = {row[key] for row in recipes['pause'] for key in ('file', 'overlay') if key in row}
    require(isinstance(expected, dict) and set(expected) == paths, 'Bind all selected Compose control files')
    for path, digest in expected.items():
        info = Path(path).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and not stat.S_IMODE(info.st_mode) & 0o022 and sha(path) == digest,
                'The installed Compose source differs from its completed deployment')


def staging(value):
    """The production entry requires the exact dedicated managed filesystem."""
    row = value['job']['staging']; path = Path(row['path'])
    require(path.is_dir() and not path.is_symlink() and os.path.ismount(path),
            'Backup staging must be its own managed mounted volume')
    info = os.statvfs(path)
    require(info.f_blocks*info.f_frsize <= row['size_bytes']
            and set(p.name for p in path.iterdir()) <= {'lost+found', '.homelab-backup'},
            'Refuse a foreign or shared staging filesystem')


def serve(value, incoming, outgoing, *, runner=run, receive=None):
    """Only an authenticated coordinator can advance a worker's capture barriers."""
    import backup_group
    receive = backup_group.message if receive is None else receive
    begin = receive(incoming, timeout=60)
    require(set(begin) == {'action', 'generation', 'backup_time', 'group', 'inventory_sha256', 'lease_seconds', 'controls'}
            and begin['action'] == 'begin' and type(begin['lease_seconds']) is int
            and 1 <= begin['lease_seconds'] <= 3*86400+180*1024+300, 'Bind the coordinated worker invocation')
    backup_group.configuration(begin['group'])
    member = value['job']['group']['member']
    require(member in begin['group']['members'] and begin['group']['name'] == value['job']['group']['name']
            and backup_group.inventory_digest(value) == begin['inventory_sha256'],
            'The worker configuration differs from its admitted source generation')
    pause_deadline = None
    def barrier(stage, metadata):
        nonlocal pause_deadline
        expected = dict(backup_group.STAGES)[stage]
        backup_group.send(outgoing, {'stage': stage, 'generation': begin['generation'],
            'member': member, **metadata})
        timeout = (pause_deadline-time.monotonic() if stage in ('paused', 'captured') else begin['lease_seconds'])
        command = receive(incoming, timeout=timeout)
        fields = {'action', 'generation'} | ({'group'} if expected == 'upload' else set())
        require(set(command) == fields and command['action'] == expected
                and command['generation'] == begin['generation'], 'Preserve the ordered backup barriers')
        if expected == 'pause': pause_deadline = time.monotonic()+value['job']['limits']['timeout_seconds']
        return command.get('group')
    return runner(value, generation=begin['generation'], backup_time=begin['backup_time'], barrier=barrier,
                  group_config=begin['group'], control_files=begin['controls'], abort_stream=incoming)


def main():
    """Serve only the installed coordinator protocol and coverage configuration."""
    require(sys.argv[1:] in (['--serve'], ['--check-ready']),
            'Use only the bounded coordinator protocol or non-capturing readiness check')
    value = read_json(CONFIG/'coverage.json', private=True)
    import backup_policy
    backup_policy.validate(value['job']); staging(value)
    def interrupted(signum, frame):
        """Abort through finally cleanup so originally running services can restart."""
        raise InterruptedError('Recovery worker interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    if sys.argv[1:] == ['--check-ready']:
        print(json.dumps(run(value, preflight=True)))
    else:
        serve(value, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Backup failed; inspect protected evidence. No automatic replay.') from None
