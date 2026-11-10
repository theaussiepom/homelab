"""Validate explicitly selected SSH custody before any host-configuration contact."""
import os
from pathlib import Path
import re
import shlex
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'blueprints'))
import authored_config

ERROR = 'Explicit host SSH trust or custody differs; do not contact the target'


def require(ok):
    """Refuse without printing credential values or untrusted file text."""
    if not ok:
        raise ValueError(ERROR)


def closed(value, fields):
    """Require a complete closed option projection from the actual SSH plugin."""
    require(type(value) is dict and set(value) == set(fields))


def trust(target, options):
    """Check actual SSH option resolution and explicit files before any target contact."""
    closed(target, ('address', 'hostname'))
    closed(options, ('host_key_checking', 'ssh_executable', 'ssh_extra_args', 'sftp_extra_args',
                     'scp_extra_args', 'ssh_args', 'ssh_common_args', 'private_key_file', 'inline_key_absent', 'password_absent'))
    require(options['host_key_checking'] is True
            and options['inline_key_absent'] is True and options['password_absent'] is True
            and options['ssh_executable'] in ('ssh', '/usr/bin/ssh')
            and not options['ssh_extra_args'] and not options['sftp_extra_args']
            and not options['scp_extra_args'])
    try:
        tokens = shlex.split(options['ssh_args']) + shlex.split(options['ssh_common_args'])
        settings = {}
        config_disabled = False
        while tokens:
            flag = tokens.pop(0)
            if flag == '-C':
                continue
            require(flag in ('-o', '-F') and tokens)
            value = tokens.pop(0)
            if flag == '-F':
                require(value == '/dev/null')
                config_disabled = True
            else:
                name, separator, selected = value.partition('=')
                require(separator and name in ('StrictHostKeyChecking', 'ControlMaster', 'BatchMode',
                        'IdentitiesOnly', 'UserKnownHostsFile', 'GlobalKnownHostsFile', 'VerifyHostKeyDNS', 'UpdateHostKeys')
                        and settings.get(name, selected) == selected)
                settings[name] = selected
        require(config_disabled and settings.get('StrictHostKeyChecking') == 'yes'
                and settings.get('ControlMaster') == 'no' and settings.get('BatchMode') == 'yes'
                and settings.get('IdentitiesOnly') == 'yes'
                and settings.get('GlobalKnownHostsFile') == '/dev/null'
                and settings.get('VerifyHostKeyDNS') == 'no' and settings.get('UpdateHostKeys') == 'no')
        key, known = Path(options['private_key_file']), Path(settings['UserKnownHostsFile'])
        require(key.is_absolute() and known.is_absolute())
        k, before = key.lstat(), known.lstat()
        require(stat.S_ISREG(k.st_mode) and k.st_uid == os.geteuid() and k.st_nlink == 1
                and stat.S_IMODE(k.st_mode) == 0o600
                and stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in (0o600, 0o644)
                and before.st_size <= 65536)
        with os.fdopen(os.open(known, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(65537)
            require(authored_config._identity(opened) == authored_config._identity(before)
                    and authored_config._identity(os.fstat(stream.fileno())) == authored_config._identity(before)
                    and authored_config._identity(known.lstat()) == authored_config._identity(before)
                    and len(raw) <= 65536)
        rows = [line.split() for line in raw.decode('ascii').splitlines() if line and not line.startswith('#')]
        require(rows and all(len(row) == 3 and target['address'] in row[0].split(',')
                and all(host in (target['address'], target['hostname']) for host in row[0].split(','))
                and row[1] in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa')
                and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', row[2]) for row in rows))
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError(ERROR) from None

