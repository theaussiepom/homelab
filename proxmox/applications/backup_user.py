"""Read-only admission for the existing CD account's hardened systemd manager."""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

POLICY = b'[Service]\nNoNewPrivileges=true\nCapabilityBoundingSet=\nAmbientCapabilities=\n'


def require(condition, message):
    """Refuse an incomplete platform prerequisite without changing it."""
    if not condition:
        raise ValueError(message)


def metadata(path, owners, *, directory=False, modes=None):
    """Check exact owners, file kinds and non-writable ancestors without following links."""
    info = Path(path).lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid in owners and not stat.S_IMODE(info.st_mode) & 0o022
            and (directory or info.st_nlink == 1)
            and (modes is None or stat.S_IMODE(info.st_mode) in modes),
            'Preserve foreign user-manager metadata')
    return info


def ancestors(path, uid):
    """Permit only root or the selected actor to own existing canonical ancestors."""
    path = Path(path)
    require(path.is_absolute() and str(path) == str(path.resolve(strict=False)),
            'Use canonical user-manager paths')
    for parent in reversed([path, *path.parents]):
        if parent.exists() or parent.is_symlink():
            metadata(parent, {0, uid}, directory=True)


def read(path, owners, modes, bound=8192):
    """Read one bounded stable regular metadata file, never an executable source."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = metadata(path, owners, modes=modes)
        require(identity(os.fstat(stream.fileno())) == identity(before) and before.st_size <= bound,
                'Preserve changed user-manager metadata')
        raw = stream.read(bound+1)
        require(len(raw) <= bound and identity(os.fstat(stream.fileno())) == identity(before)
                and identity(path.lstat()) == identity(before), 'Preserve changed user-manager metadata')
    return raw


def identity(info):
    """Exclude read-induced atime changes while binding object and security metadata."""
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def account(uid):
    """Resolve one existing non-root account without trusting HOME or XDG overrides."""
    require(type(uid) is int and uid > 0, 'Use an existing non-root CD account')
    row = pwd.getpwuid(uid)
    require(row.pw_uid == uid and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', row.pw_name),
            'Bind the exact CD account')
    home = Path(row.pw_dir)
    ancestors(home, uid)
    metadata(home, {uid}, directory=True)
    require(stat.S_IMODE(home.stat().st_mode) & 0o700 == 0o700,
            'The CD account must own its writable home')
    runtime = '/run/user/' + str(uid)
    return {'uid': uid, 'name': row.pw_name, 'home': str(home),
            'unit_directory': str(home/'.config/systemd/user'), 'runtime': runtime,
            'environment': {'XDG_RUNTIME_DIR': runtime,
                            'DBUS_SESSION_BUS_ADDRESS': 'unix:path='+runtime+'/bus'}}


def show(unit, properties, *, scope='system', environment=None):
    """Read only named scalar properties from the system or selected user manager."""
    require(scope in ('system', 'user'), 'Select a standard systemd scope')
    result = subprocess.run(['/usr/bin/systemctl', '--'+scope, 'show', unit,
        *['--property='+key for key in properties]], capture_output=True, text=True,
        check=False, timeout=10, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', **(environment or {})})
    require(not result.stderr and len(result.stdout) <= 16384, 'Read a closed systemd response')
    pairs = [line.split('=', 1) for line in result.stdout.splitlines()]
    require(all(len(row) == 2 for row in pairs) and len(pairs) == len(properties)
            and {row[0] for row in pairs} == set(properties), 'Read every selected systemd property')
    value = dict(pairs)
    require(result.returncode == 0 or (result.returncode == 1
            and value.get('LoadState') == 'not-found'
            and all(not item for key, item in value.items() if key != 'LoadState')),
            'Read a successful systemd observation')
    return value


def kernel(pid, uid):
    """Prove the effective process UID, inherited no-new-privileges and zero capabilities."""
    require(type(pid) is int and pid > 0, 'Select the actual manager process')
    raw = read(Path('/proc')/str(pid)/'status', {0, uid}, {0o444}).decode('ascii')
    names = {'Uid', 'NoNewPrivs', 'CapEff', 'CapPrm', 'CapAmb'}
    pairs = [line.split(':', 1) for line in raw.splitlines() if line.partition(':')[0] in names]
    require(len(pairs) == len(names) and {key for key, _ in pairs} == names,
            'Read complete kernel privilege metadata')
    values = {key: value.split() for key, value in pairs}
    require(values['Uid'] == [str(uid)]*4 and len(values['NoNewPrivs']) == 1
            and values['NoNewPrivs'][0] in ('0', '1')
            and all(len(values[key]) == 1 and re.fullmatch('[0-9a-fA-F]{1,64}', values[key][0])
                    for key in ('CapEff', 'CapPrm', 'CapAmb')),
            'Keep the manager an ordinary non-root process')
    return (values['NoNewPrivs'] == ['1']
            and all(int(values[key][0], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapAmb')))


def inspect(uid):
    """Observe bootstrap eligibility; inactive managers are not started or repaired."""
    selected = account(uid)
    policy = Path('/etc/systemd/system')/('user@'+str(uid)+'.service.d/50-homelab-cd.conf')
    ancestors(policy.parent, 0)
    try:
        content = read(policy, {0}, {0o644})
    except FileNotFoundError:
        content = None
    unit = 'user@'+str(uid)+'.service'
    properties = ['LoadState', 'ActiveState', 'MainPID', 'NoNewPrivileges', 'NeedDaemonReload']
    state = show(unit, properties)
    require(state['LoadState'] == 'loaded' and state['ActiveState'] in ('active', 'inactive')
            and re.fullmatch('[0-9]+', state['MainPID'])
            and state['NoNewPrivileges'] in ('yes', 'no')
            and state['NeedDaemonReload'] in ('yes', 'no'), 'Preserve an ambiguous user manager')
    active = state['ActiveState'] == 'active'
    hardened = kernel(int(state['MainPID']), uid) if active else False
    require(not active or show(unit, properties) == state, 'The user manager changed during inspection')
    return {**selected, 'active': active, 'policy_present': content is not None,
            'policy_matches': content == POLICY, 'kernel_hardened': hardened,
            'configured_hardened': state['NoNewPrivileges'] == 'yes',
            'reload_needed': state['NeedDaemonReload'] == 'yes'}


def ready(uid):
    """Require the root-hardened persistent manager and private user-session bus."""
    value = inspect(uid)
    require(value['active'] and value['policy_present'] and value['policy_matches']
            and value['kernel_hardened'] and value['configured_hardened'] and not value['reload_needed'],
            'Prepare the hardened persistent CD user manager before backup activation')
    linger = Path('/var/lib/systemd/linger')/value['name']
    ancestors(linger.parent, 0)
    require(read(linger, {0}, {0o644}) == b'', 'Keep persistent user-manager ownership')
    runtime = Path(value['runtime'])
    ancestors(runtime.parent, 0)
    metadata(runtime, {uid}, directory=True, modes={0o700})
    bus = (runtime/'bus').lstat()
    require(stat.S_ISSOCK(bus.st_mode) and bus.st_uid == uid and bus.st_nlink == 1,
            'Use the private existing user-session bus')
    return value


def execution():
    """Keep controller execution non-root with the kernel protection already in force."""
    uid = os.getuid()
    require(uid > 0 and os.geteuid() == uid and kernel(os.getpid(), uid),
            'Run backup control as the hardened existing CD account')
    return uid


def verify(name):
    """Admit the manager and refuse a system-scope namesake before any backup write."""
    require(re.fullmatch(r'homelab-backup-[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name),
            'Select one declared backup unit')
    value = ready(execution())
    for suffix in ('.service', '.timer'):
        require(show(name+suffix, ['LoadState']) == {'LoadState': 'not-found'},
                'Retire a system-scope backup namesake separately')
        path = Path(value['unit_directory'])/(name+suffix)
        selected = show(name+suffix, ['LoadState', 'FragmentPath', 'DropInPaths'],
            scope='user', environment=value['environment'])
        require(selected == {'LoadState': 'not-found', 'FragmentPath': '', 'DropInPaths': ''}
                or selected == {'LoadState': 'loaded', 'FragmentPath': str(path), 'DropInPaths': ''},
                'Preserve a foreign or overridden user-scope backup unit')
        if selected['LoadState'] == 'loaded':
            ancestors(path.parent, value['uid'])
            metadata(path, {value['uid']}, modes={0o644})
    return value


def main():
    """Expose only bounded local bootstrap observations; never start a manager or backup."""
    require(len(sys.argv) == 3 and sys.argv[1] in ('inspect', 'ready')
            and re.fullmatch('[1-9][0-9]*', sys.argv[2]), 'Select one existing user-manager observation')
    uid = int(sys.argv[2])
    require(os.geteuid() in (0, uid), 'Inspect only the existing CD account')
    print(json.dumps((inspect if sys.argv[1] == 'inspect' else ready)(uid), sort_keys=True))


if __name__ == '__main__':
    main()
