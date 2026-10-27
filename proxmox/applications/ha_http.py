"""Configure one restored HA proxy without replacing file owners, ACLs or xattrs."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat


def digest(value):
    return hashlib.sha256(value).hexdigest()


def configure(path, backup, expected, proxy):
    ip = ipaddress.IPv4Address(proxy)
    if not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        raise ValueError('Select only the private Traefik backend address')
    block = ('\n# BEGIN HOMELAB HTTP PROXY\nhttp:\n  use_x_forwarded_for: true\n'
             '  trusted_proxies:\n    - ' + str(ip) + '\n# END HOMELAB HTTP PROXY\n').encode()
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 1048576:
            raise ValueError('Expected the bounded restored HA configuration')
        value = stream.read()
        if value.endswith(block) and digest(value[:-len(block)]) == expected:
            return False
        if digest(value) != expected or re.search(rb'(?m)^http\s*:', value):
            raise ValueError('The restored HA HTTP configuration differs; preserve it for review')
        if not value.endswith(b'\n'):
            raise ValueError('The selected HA configuration must end with its original newline')
        attributes = {key: os.getxattr(path, key) for key in os.listxattr(path)}
        if backup.exists():
            if backup.is_symlink() or digest(backup.read_bytes()) != expected:
                raise ValueError('The retained HA proxy backup differs')
        else:
            out = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(out, 'wb') as original:
                original.write(value); original.flush(); os.fsync(original.fileno())
        desired = value + block
        stream.seek(0); stream.write(desired); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        stream.seek(0)
        after = os.fstat(stream.fileno())
        if (stream.read() != desired or (before.st_ino, before.st_uid, before.st_gid, before.st_mode)
                != (after.st_ino, after.st_uid, after.st_gid, after.st_mode)
                or attributes != {key: os.getxattr(path, key) for key in os.listxattr(path)}):
            raise ValueError('HA proxy configuration or metadata readback differs')
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--proxy', required=True)
    args = parser.parse_args()
    try:
        changed = configure(Path('/srv/homelab/data/homeassistant/config/configuration.yaml'),
                            Path('/opt/homelab-app/configuration.before-proxy.yaml'), args.expected_sha256, args.proxy)
        print(json.dumps({'changed': changed}))
    except (OSError, ValueError):
        raise SystemExit('HA proxy configuration held; inspect the retained private original') from None
