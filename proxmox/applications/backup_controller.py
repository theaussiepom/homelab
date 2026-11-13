#!/usr/bin/env python3
"""Coordinate one recovery set under existing deployment custody, never deploy."""
import argparse
import base64
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import selectors
import signal
import subprocess
import time
from types import SimpleNamespace
import uuid

import backup_group
import backup_policy
import backup_capture
import backup_source
import backup_user
import component_generation
import deployment_state
from custody_records import no_markers
from private_io import encoded, private_directory, private_writer, read_json, regular, require, sha, write_new, sync


def schedule(value):
    """Validate the single versioned root schedule and physical membership."""
    backup_policy.exact(value, ('schema', 'group', 'schedule', 'limits'), ('coverage',))
    require(value['schema'] in ('homelab-pbs-schedule-v1', 'homelab-pbs-schedule-v2'),
            'Use the versioned recovery schedule')
    backup_group.configuration(value['group'])
    backup_policy.schedule(value['schedule']); backup_policy.limits(value['limits'])
    require((value['schema'] == 'homelab-pbs-schedule-v1' and 'coverage' not in value)
            or (value['schema'] == 'homelab-pbs-schedule-v2' and isinstance(value.get('coverage'), dict)
                and set(value['coverage']) == set(value['group']['members'])
                and all(isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)
                        for item in value['coverage'].values())),
            'Bind expected coverage for every enrolled recovery member')
    return value


def continuity(previous, current):
    """Adding members is explicit source; omission cannot retire existing protection."""
    schedule(previous); schedule(current)
    require(previous['group']['name'] == current['group']['name']
            and all(current['group']['members'].get(key) == row
                for key, row in previous['group']['members'].items()),
            'Retire or move protected members separately; do not silently omit them')


def admit(name, row):
    """Read the real completed generation, including disabled or older-source guests."""
    root = Path(row['state_root']); work = root/str(row['vmid'])
    for directory in [root, work, *root.glob('database-network-cutover-*'),
            *root.glob('database-server-cutover-*'), *work.glob('database-*'), *work.glob('ordinary-*')]:
        if directory.is_dir():
            private_directory(directory); no_markers(directory)
    receipt_path = work/'ordinary-complete.json'
    receipt = read_json(receipt_path, private=True)
    source = Path(receipt['binding']['app_inputs_directory']).parent/'site.json'
    cfg = read_json(source, private=True)
    api = cfg['site']['api_endpoint']
    require(cfg['paths']['state_root'] == row['state_root']
            and cfg['site']['node'] == row['node']
            and cfg['guest']['vmid'] == row['vmid'] and cfg['guest']['hostname'] == row['hostname']
            and api.rstrip('/') == 'https://'+row['api_address']+':'+str(row['api_port']),
            'Preserve the configured member, endpoint and state ownership')
    attempt = SimpleNamespace(cfg=cfg, work=work, receipt=receipt_path, vmid=row['vmid'])
    previous = component_generation.previous(attempt)
    require(previous is not None and previous[0] == receipt, 'Require genuine canonical and immutable completion')
    # previous() verifies the sealed config, runtime and every phase payload.
    # Recheck external bindings without substituting today's framework source hash.
    require(all(sha(path) == expected for path, expected in receipt['binding']['input_hashes'].items()),
            'A deployed private input or trust binding changed')
    state_hash, identity = component_generation.backend(work, row)
    require(state_hash == receipt['state_sha256'] and identity == receipt['state_identity'],
            'Preserve the completed backend generation; backup cannot repair state')
    from proxmox_guest import guest_trust
    guest_trust(cfg, work, persist=False)
    inventory = cfg['app']['backup']; job = backup_policy.validate(inventory['job'])
    require(job['group']['member'] == name, 'Bind the stable recovery member')
    return cfg, sha(receipt_path)


def controls(cfg):
    """Bind installed Compose control bytes to sealed ordinary phase inputs."""
    from component_payload import AppPayload
    receipt = read_json(Path(cfg['paths']['state_root'])/str(cfg['guest']['vmid'])/'ordinary-complete.json', private=True)
    selected = {}
    for row in backup_capture.recipes(cfg['app']['backup'])['pause']:
        selected[row['file']] = sha(Path(cfg['deployment']['input_directory'])/Path(row['file']).name)
        if 'overlay' in row:
            proofs = [proof for proof in receipt['phase_inputs'].values() if proof is not None and proof['app'] == row['app']]
            require(len(proofs) == 1, 'Bind the exact app environment phase')
            payload = AppPayload.load(Path(receipt['binding']['app_inputs_directory'])/row['app'], proofs[0])
            selected[row['overlay']] = sha(payload.directory/'environment.yml')
    return selected


def command(cfg):
    """Build a finite noninteractive SSH invocation using existing pinned trust."""
    return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'UserKnownHostsFile='+cfg['paths']['known_hosts'], '-o', 'ControlMaster=no',
        '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
        '-i', cfg['paths']['private_key'], 'root@'+cfg['app']['address'],
        '/usr/bin/python3 /opt/homelab-backup/backup_worker.py --serve']


class Exchange:
    """Concurrent bounded pipe I/O; a silent or partial peer cannot freeze others."""
    def __init__(self, peers, generation, deadline):
        """Bind peer pipes and their shared operation deadline."""
        self.peers, self.generation, self.deadline = peers, generation, deadline
        for peer in peers.values():
            os.set_blocking(peer.stdin.fileno(), False); os.set_blocking(peer.stdout.fileno(), False)

    def transfer(self, outgoing=None, stage=None):
        result = {}; buffers = {}
        with selectors.DefaultSelector() as selected:
            for name, peer in self.peers.items():
                raw = encoded(outgoing[name]).replace(b'\n', b'')+b'\n' if outgoing is not None else b''
                require(len(raw) <= backup_group.LIMIT, 'Bound coordinator commands before writing')
                buffers[name] = raw
                selected.register(peer.stdin if outgoing is not None else peer.stdout,
                    selectors.EVENT_WRITE if outgoing is not None else selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = self.deadline-time.monotonic()
                require(remaining > 0, 'The coordinated backup exceeded its total deadline')
                events = selected.select(remaining)
                require(events, 'A recovery peer exceeded the coordinator lease')
                for key, _ in events:
                    name = key.data; stream = key.fileobj
                    if outgoing is not None:
                        count = os.write(stream.fileno(), buffers[name]); buffers[name] = buffers[name][count:]
                        complete = not buffers[name]
                    else:
                        raw = os.read(stream.fileno(), min(65536, backup_group.LIMIT+1-len(buffers[name])))
                        require(raw, 'A recovery peer disconnected before completing its barrier')
                        buffers[name] += raw
                        require(len(buffers[name]) <= backup_group.LIMIT, 'A recovery peer exceeded its message bound')
                        complete = b'\n' in buffers[name]
                        if complete:
                            import io
                            require(buffers[name].count(b'\n') == 1 and buffers[name].endswith(b'\n'),
                                    'A recovery peer pipelined or appended unexpected protocol data')
                            value = backup_group.message(io.BytesIO(buffers[name]))
                            fields = {'stage', 'generation', 'member'} | ({'data_manifest_sha256'}
                                if stage in ('captured', 'uploaded') else set())
                            require(set(value) == fields and value['stage'] == stage
                                    and value['generation'] == self.generation and value['member'] == name,
                                    'Preserve ordered, complete, correctly owned recovery barriers')
                            result[name] = value
                    if complete: selected.unregister(stream)
        return result


def reap(peers, *, success, deadline):
    """EOF aborts workers; give their finally blocks time to restart paused apps."""
    for peer in peers.values():
        if not peer.stdin.closed: peer.stdin.close()
    failed = False
    for peer in peers.values():
        try:
            code = peer.wait(timeout=max(1, deadline-time.monotonic()))
            failed = failed or code != 0
        except subprocess.TimeoutExpired:
            os.killpg(peer.pid, signal.SIGTERM)
            try: peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(peer.pid, signal.SIGKILL); peer.wait()
            failed = True
        finally:
            peer.stdout.close()
    require(not success or not failed, 'A recovery worker did not confirm successful completion')


def run(path, *, launch=subprocess.Popen, admission=admit):
    os.umask(0o077)
    value = schedule(read_json(path, private=True)); group = value['group']
    deployment_state.bootstrap_closed()
    peers = {}; holds = {}; completed = False
    generation = uuid.uuid4().hex; stamp = int(time.time())
    with ExitStack() as opened:
        scopes = sorted({(row['state_root'], row['vmid']) for row in group['members'].values()})
        paths = [(Path(root)/'database-network.lock', True) for root in sorted({root for root, _ in scopes})]
        paths += [(Path(root)/str(vmid)/leaf, False) for root, vmid in scopes
                  for leaf in ('workflow.lock', 'deployment.lock')]
        # Same per-guest order as CD; all acquisitions are nonblocking.
        for lock, shared in paths:
            stream = opened.enter_context(private_writer(lock, append=True, create=False))
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        admitted = {name: admission(name, row) for name, row in group['members'].items()}
        require(all(cfg['app']['backup']['job']['group']['name'] == group['name']
                for cfg, _ in admitted.values()), 'Preserve the root recovery group identity')
        import backup_readiness
        backup_readiness.verify(value, admitted)
        root = Path(scopes[0][0]); private_directory(root)
        attempts = root/'backup-groups'; private_directory(attempts, create=not attempts.exists())
        operation = attempts/generation; private_directory(operation, create=True)
        write_new(operation/'started.json', encoded({'group': group, 'generation': generation,
            'backup_time': stamp, 'deployment_receipts': {name: proof for name, (_, proof) in admitted.items()}}))
        budgets = [cfg['app']['backup']['job']['limits']['timeout_seconds'] for cfg, _ in admitted.values()]
        lease = 3*max(budgets)+180*sum(len(cfg['app']['backup']['job']['capture']['pause'])
            for cfg, _ in admitted.values())+300
        require(lease <= 3*86400+180*1024+300, 'Bound the total recovery group interruption budget')
        deadline = time.monotonic()+lease
        try:
            for name, (cfg, _) in admitted.items():
                log = opened.enter_context(private_writer(operation/(name+'.log'), exclusive=True))
                peers[name] = launch(command(cfg), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                    env={'PATH': '/usr/bin:/bin', 'HOME': str(operation)}, start_new_session=True, bufsize=0)
            exchange = Exchange(peers, generation, deadline)
            exchange.transfer({name: {'action': 'begin', 'generation': generation, 'backup_time': stamp,
                'group': group, 'inventory_sha256': backup_group.inventory_digest(cfg['app']['backup']),
                'lease_seconds': lease, 'controls': controls(cfg)} for name, (cfg, _) in admitted.items()})
            captures = {}; recovery = None
            for stage, action in backup_group.STAGES:
                rows = exchange.transfer(stage=stage)
                if stage == 'prepared':
                    for name, row in group['members'].items():
                        work = Path(row['state_root'])/str(row['vmid'])
                        raw = encoded({'schema': 'homelab-backup-window-v1', 'generation': generation,
                            'operation': str(operation), 'member': name})
                        write_new(work/'BACKUP-HOLD.json', raw); holds[work] = raw
                if stage == 'captured':
                    captures = {name: row['data_manifest_sha256'] for name, row in rows.items()}
                if stage == 'resumed':
                    destinations = {name: {**{field: cfg['app']['backup']['job']['destination'][field]
                        for field in ('server', 'port', 'datastore')}, 'namespace':
                        cfg['app']['backup']['job']['destination']['namespace']+'/'+name}
                        for name, (cfg, _) in admitted.items()}
                    recovery = backup_group.recovery_set(group, generation, stamp, captures, destinations)
                    write_new(operation/'recovery-set.json', encoded(recovery))
                if stage == 'uploaded':
                    require(captures == {name: row['data_manifest_sha256'] for name, row in rows.items()},
                            'Every uploaded archive must bind the same completed data manifest')
                exchange.transfer({name: {'action': action, 'generation': generation,
                    **({'group': recovery} if action == 'upload' else {})} for name in peers})
            finished = dict(peers); peers.clear()
            reap(finished, success=True, deadline=deadline)
            for work, raw in holds.items():
                require(regular(work/'BACKUP-HOLD.json', private=True) == raw, 'Preserve a foreign backup hold')
            for work, raw in holds.items():
                write_new(operation/(str(work.name)+'-'+hashlib.sha256(str(work).encode()).hexdigest()[:16]+'.closed.json'), raw)
                (work/'BACKUP-HOLD.json').unlink(); sync(work)
            write_new(operation/'complete.json', encoded({'status': 'passed', 'generation': generation,
                'recovery_set_sha256': sha(operation/'recovery-set.json'), 'restore_verified': False}))
            completed = True
        finally:
            if peers: reap(peers, success=False, deadline=time.monotonic()+180*max(1, len(group['members'])))
            if not completed:
                write_new(operation/'failed.json', encoded({'status': 'failed', 'generation': generation,
                    'window_opened': bool(holds), 'automatic_replay': False}))
    return {'status': 'passed', 'generation': generation, 'restore_verified': False}


def units(value, source_directory, user, home=None):
    """Render one account-owned schedule without changing membership or capture behavior."""
    schedule(value)
    require(type(user) is int and user > 0, 'Use the existing non-root CD actor')
    home = backup_user.account(user)['home'] if home is None else home
    base = str(Path(min(row['state_root'] for row in value['group']['members'].values()))/'backup-controller')
    require(all(isinstance(path, str) and path.startswith('/')
            and str(Path(path)) == path and '..' not in Path(path).parts
            and not any(ord(char) < 32 or char in '%"\\$' for char in path)
            for path in (source_directory, home, base)),
            'Use the pinned source and existing CD actor')
    name = 'homelab-backup-'+value['group']['name']
    path = base+'/schedules/'+name+'.json'
    # The trusted unit verifies the complete bundle as data before importing it.
    verifier = base64.b64encode(Path(backup_source.__file__).read_bytes()).decode('ascii')
    selected_hash = source_directory.rsplit('/', 3)[-3]
    require(len(selected_hash) == 64 and all(c in '0123456789abcdef' for c in selected_hash),
            'Select the versioned public source directory')
    entry = ("import base64,runpy,sys;v={'__name__':'backup_source_verifier'};exec(base64.b64decode('"
        +verifier+"'),v);v['verify'](sys.argv[1],sys.argv[2]);sys.path.insert(0,sys.argv[1]);"
        "sys.argv=[sys.argv[1]+'/backup_controller.py','--group',sys.argv[3]];"
        "runpy.run_path(sys.argv[0],run_name='__main__')")
    calendar = value['schedule']['calendar']
    calendar = {'hourly': '*-*-* *:00:00', 'daily': '*-*-* 00:00:00'}.get(calendar, '*-*-* '+calendar+':00')+' UTC'
    timeout = 3*86400+180*1024+300
    service = ('[Unit]\nDescription=Coordinated guest recovery\nAfter=network-online.target\n'
        '[Service]\nType=oneshot\nNoNewPrivileges=true\nUMask=0077\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
        'ExecStart=/usr/bin/python3 -I -B -c "'+entry+'" "'+source_directory+'" "'+selected_hash+'" "'+path+'"\n'
        'TimeoutStartSec='+str(timeout)+'\nKillMode=process\nTimeoutStopSec=190\n')
    timer = ('[Unit]\nDescription=Guest recovery schedule\n[Timer]\nOnCalendar='+calendar
        +'\nRandomizedDelaySec='+str(value['schedule']['jitter_seconds'])
        +'\nPersistent=false\n[Install]\nWantedBy=timers.target\n')
    # The existing owner identity survives the internal v1 -> v2 schedule upgrade.
    return {'name': name, 'service': service, 'timer': timer, 'owner': {'schema': 'homelab-pbs-schedule-v1',
        'name': value['group']['name'], 'actor': user}, 'configuration': value, 'user': user,
        'base': base, 'group_path': path, 'owner_path': base+'/schedules/'+name+'.owner.json',
        'unit_directory': home+'/.config/systemd/user'}


def installation(value):
    """Verify the owned installed schedule and bundle before completing activation or capturing."""
    from deployment_inputs import source_hash
    actor = backup_user.verify('homelab-backup-'+value['group']['name'])
    directory = str(Path(min(row['state_root'] for row in value['group']['members'].values()))/
        'backup-controller/framework'/source_hash()/'proxmox/applications')
    expected = units(value, directory, actor['uid'], actor['home'])
    backup_source.verify(directory, source_hash(), actor['uid'])
    for path in (expected['group_path'], expected['owner_path']):
        backup_user.ancestors(Path(path).parent, actor['uid'])
    require(json.loads(backup_user.read(expected['group_path'], {actor['uid']}, {0o600}, backup_group.LIMIT)) == value
            and json.loads(backup_user.read(expected['owner_path'], {actor['uid']}, {0o600})) == expected['owner'],
            'Preserve the installed schedule owner and exact current group')
    for suffix in ('service', 'timer'):
        path = Path(expected['unit_directory'])/(expected['name']+'.'+suffix)
        backup_user.ancestors(path.parent, actor['uid'])
        require(backup_user.read(path, {actor['uid']}, {0o644}).decode() == expected[suffix],
                'Preserve the declared user unit bytes')
        status = backup_user.show(path.name, ['LoadState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload'],
            scope='user', environment=actor['environment'])
        require(status == {'LoadState': 'loaded', 'FragmentPath': str(path), 'DropInPaths': '',
                'NeedDaemonReload': 'no'}, 'Use only the loaded declared user unit')
    timer = backup_user.show(expected['name']+'.timer', ['ActiveState', 'UnitFileState'],
        scope='user', environment=actor['environment'])
    require(timer == {'ActiveState': 'active', 'UnitFileState': 'enabled'}, 'Keep the declared user timer enabled')


def main():
    """Run one declared recovery group from its protected schedule descriptor."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', type=Path, required=True)
    args = parser.parse_args()
    backup_user.execution()
    def interrupted(signum, frame):
        """Abort through the operation cleanup path when the timer is interrupted."""
        raise InterruptedError('Recovery coordinator interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    print(json.dumps(run(args.group)))


if __name__ == '__main__':
    try: main()
    except Exception:
        raise SystemExit('Backup refused or failed; inspect protected evidence. No automatic replay.') from None
