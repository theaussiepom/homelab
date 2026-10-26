"""Bootstrap-owned NFS mount and one narrow bind into the unprivileged runner."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

HOST_MOUNT = Path('/mnt/homelab_backups')
GUEST_MOUNT = '/srv/homelab-backups'
UNIT = 'mnt-homelab_backups.mount'
AUTOMOUNT = 'mnt-homelab_backups.automount'


def command(args):
    """Run a bounded ordinary host operation without a shell."""
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('NAS setup command failed; ' + result.stderr.strip())
    return result.stdout


def validate(value):
    """Admit one explicit NFS export/version and one private backup subdirectory."""
    if set(value) != {'server', 'export', 'version', 'directory'}:
        raise RuntimeError('Use server, export, version and directory for the NAS connection')
    address = ipaddress.IPv4Address(value['server'])
    if not address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified:
        raise RuntimeError('Use the selected private NAS IPv4 address')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', value['export']) or '..' in value['export'].split('/'):
        raise RuntimeError('Use the exact NAS export path')
    if value['version'] not in ('3', '4', '4.1', '4.2'):
        raise RuntimeError('Select the supported NFS version explicitly; no fallback')
    if not re.fullmatch(r'[a-z][a-z0-9_-]{1,62}', value['directory']):
        raise RuntimeError('Use one dedicated backup directory name')


def units(nas):
    """Use an automount so an unavailable NAS is not a Proxmox boot dependency."""
    validate(nas)
    source = nas['server'] + ':' + nas['export']
    mount = ('[Unit]\nDescription=HomeLab deployment state recovery\n'
             '[Mount]\nWhat=' + source + '\nWhere=' + str(HOST_MOUNT) +
             '\nType=nfs\nOptions=vers=' + nas['version'] +
             ',hard,nosuid,nodev,noexec\nTimeoutSec=30\n')
    auto = ('[Unit]\nDescription=HomeLab deployment recovery automount\n'
            '[Automount]\nWhere=' + str(HOST_MOUNT) +
            '\n[Install]\nWantedBy=multi-user.target\n')
    return {UNIT: mount, AUTOMOUNT: auto}


def plan(nas, guest_config, root=Path('/'), execute=command):
    """Refuse takeover of existing units or other mounts before writing anything."""
    wanted = units(nas)
    directory = str(HOST_MOUNT / nas['directory'])
    binding = directory + ',mp=' + GUEST_MOUNT + ',backup=0'
    if guest_config.get('unprivileged') not in (1, True) or guest_config.get('hostname') != 'deploy':
        raise RuntimeError('NAS binding requires the existing unprivileged deploy guest')
    for key, value in guest_config.items():
        if re.fullmatch(r'mp\d+', key) and (key != 'mp0' or not same_binding(value, binding)):
            raise RuntimeError('An unexpected deployment-guest mount exists; no replacement')
    target = root / str(HOST_MOUNT).lstrip('/')
    for path in [target, *target.parents]:
        if path.is_symlink():
            raise RuntimeError('The NAS mount path must not contain a symlink')
    changed = []
    for name, content in wanted.items():
        path = root / 'etc/systemd/system' / name
        if path.is_symlink() or (path.exists() and path.read_text() != content):
            raise RuntimeError('Existing NAS mount configuration differs; preserve it for review')
        if not path.exists():
            changed.append(name)
    add_bind = not same_binding(guest_config.get('mp0'), binding)
    return {'units_to_create': changed, 'bind_to_add': add_bind,
            'protection_toggle_required': add_bind and guest_config.get('protection') in (1, True),
            'binding': binding, 'guest_mount': GUEST_MOUNT,
            'backup_source': nas['server'] + ':' + nas['export'] + '[' + '/' + nas['directory'] + ']'}


def same_binding(actual, wanted):
    """Accept Proxmox option ordering and its omitted default backup flag only."""
    def parse(value):
        if not isinstance(value, str):
            return None
        parts = value.split(',')
        result = {'source': parts[0], 'backup': '0'}
        seen = set()
        for part in parts[1:]:
            pair = part.split('=', 1)
            if len(pair) != 2 or pair[0] not in ('mp', 'backup') or pair[0] in seen:
                return None
            seen.add(pair[0])
            result[pair[0]] = pair[1]
        return result
    return parse(actual) is not None and parse(actual) == parse(wanted)


def guest_addresses(vmid, execute=command):
    """Allow DHCP a short, bounded interval after the admitted guest restart."""
    for attempt in range(30):
        addresses = execute(['pct', 'exec', str(vmid), '--', 'hostname', '-I']).split()
        if any(ipaddress.ip_address(x).version == 4 and not ipaddress.ip_address(x).is_loopback
               and not ipaddress.ip_address(x).is_link_local for x in addresses):
            return addresses
        if attempt < 29:
            time.sleep(1)
    raise RuntimeError('The deployment guest has no usable IPv4 address after the bounded DHCP wait')


def ensure(nas, vmid, guest_config, execute=command, root=Path('/'), restart=False, unprotect=False):
    """Add missing configuration; restart only this guest when explicitly selected."""
    result = plan(nas, guest_config, root, execute)
    if result['protection_toggle_required'] and not unprotect:
        raise RuntimeError('Explicitly select temporary deployment-guest unprotection and review a new plan before adding its bind')
    target = root / str(HOST_MOUNT).lstrip('/')
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not os.path.ismount(target) and any(target.iterdir()):
        raise RuntimeError('The unmounted host NAS directory is not empty')
    for name in result['units_to_create']:
        path = root / 'etc/systemd/system' / name
        with path.open('x') as stream:
            os.chmod(path, 0o600)
            stream.write(units(nas)[name]); stream.flush(); os.fsync(stream.fileno())
    if result['units_to_create']:
        execute(['systemctl', 'daemon-reload'])
    execute(['systemctl', 'enable', '--now', AUTOMOUNT])
    execute(['systemctl', 'start', UNIT])
    found = execute(['findmnt', '-rn', '-t', 'nfs,nfs4', '-o', 'FSTYPE,SOURCE', '--mountpoint', str(HOST_MOUNT)]).strip().split()
    source = nas['server'] + ':' + nas['export']
    if len(found) != 2 or found[0] not in ('nfs', 'nfs4') or found[1] != source:
        raise RuntimeError('The mounted filesystem is not the selected NAS export')
    # The target runner account remains unchanged. No broad UID/GID passthrough.
    uid = int(execute(['pct', 'exec', str(vmid), '--', 'id', '-u', 'homelab-runner']).strip())
    gid = int(execute(['pct', 'exec', str(vmid), '--', 'id', '-g', 'homelab-runner']).strip())
    pid = int(execute(['lxc-info', '-n', str(vmid), '-p', '-H']).strip())
    mapped = []
    for kind, value in [('uid', uid), ('gid', gid)]:
        rows = [list(map(int, line.split())) for line in (root / 'proc' / str(pid) / (kind + '_map')).read_text().splitlines()]
        if rows != [[0, 100000, 65536]] or not 0 < value < 65536:
            raise RuntimeError('Use the existing default unprivileged ID map; no remapping')
        mapped.append(100000 + value)
    private = target / nas['directory']
    if private.is_symlink():
        raise RuntimeError('Backup directory must not be a symlink')
    if not private.exists():
        private.mkdir(mode=0o700)
        os.chown(private, *mapped)
        # NAS defaults may widen mkdir's requested mode. Correct only the folder
        # created by this call; existing folders remain inspection-only.
        os.chmod(private, 0o700)
    metadata = private.stat()
    if (metadata.st_uid, metadata.st_gid) != tuple(mapped) or metadata.st_mode & 0o077:
        raise RuntimeError('NAS backup directory permissions differ; existing files are not chowned')
    if result['bind_to_add']:
        if result['protection_toggle_required']:
            # The operator explicitly selected this one drive-change window.
            # Restore protection even if the drive command fails; never retry it.
            try:
                execute(['pct', 'set', str(vmid), '--protection', '0'])
                execute(['pct', 'set', str(vmid), '--mp0', result['binding']])
            finally:
                execute(['pct', 'set', str(vmid), '--protection', '1'])
                protected = json.loads(execute(['pvesh', 'get', '/nodes/' + guest_config['node'] + '/lxc/' + str(vmid) + '/config',
                                                '--output-format', 'json']))
                if protected.get('protection') not in (1, True):
                    raise RuntimeError('Deployment guest protection was not restored; preserve the hold and inspect this guest')
        else:
            execute(['pct', 'set', str(vmid), '--mp0', result['binding']])
    current = json.loads(execute(['pvesh', 'get', '/nodes/' + guest_config['node'] + '/lxc/' + str(vmid) + '/config',
                                  '--current', '1', '--output-format', 'json']))
    def active():
        current_pid = int(execute(['lxc-info', '-n', str(vmid), '-p', '-H']).strip())
        def mounts(path, target_path):
            rows = []
            for line in path.read_text().splitlines():
                fields = line.split(); separator = fields.index('-')
                if fields[4] == target_path and fields[separator + 1] in ('nfs', 'nfs4'):
                    rows.append({'device': fields[2], 'root': fields[3], 'source': fields[separator + 2]})
            return rows
        host = mounts(root / 'proc/self/mountinfo', str(HOST_MOUNT))
        guest = mounts(root / 'proc' / str(current_pid) / 'mountinfo', GUEST_MOUNT)
        if len(host) != 1 or host[0]['source'] != source:
            raise RuntimeError('The current host NAS mount identity differs')
        if not guest:
            return False
        expected = dict(host[0], root=host[0]['root'].rstrip('/') + '/' + nas['directory'])
        if guest != [expected]:
            raise RuntimeError('The existing guest NAS bind is stale or differs; preserve it for review')
        return True
    if not same_binding(current.get('mp0'), result['binding']) or not active():
        if not restart:
            raise RuntimeError('NAS bind needs a deployment-guest restart; select it in the reviewed configuration')
        execute(['pct', 'shutdown', str(vmid), '--timeout', '30'])
        if execute(['pct', 'status', str(vmid)]).strip() != 'status: stopped':
            raise RuntimeError('Graceful deployment-guest stop was not confirmed; no forced stop')
        execute(['pct', 'start', str(vmid)])
        current = json.loads(execute(['pvesh', 'get', '/nodes/' + guest_config['node'] + '/lxc/' + str(vmid) + '/config',
                                     '--current', '1', '--output-format', 'json']))
        if not same_binding(current.get('mp0'), result['binding']) or not active():
            raise RuntimeError('The selected guest restart did not activate its exact NAS bind')
    guest_source = execute(['pct', 'exec', str(vmid), '--', 'findmnt', '-rn', '-t', 'nfs,nfs4',
                            '-o', 'FSTYPE,SOURCE', '--mountpoint', GUEST_MOUNT]).strip().split()
    if len(guest_source) != 2 or guest_source[0] not in ('nfs', 'nfs4'):
        raise RuntimeError('The verified guest NAS bind has no unambiguous filesystem source')
    result['backup_source'] = guest_source[1]
    result.update(changed=bool(result['units_to_create'] or result['bind_to_add']), mapped_uid=mapped[0], mapped_gid=mapped[1])
    return result
