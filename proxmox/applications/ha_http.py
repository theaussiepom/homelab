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


def rewrite(path, backup, expected, transform):
    """Change only the bound source bytes, retaining the original inode metadata."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 1048576:
            raise ValueError('Expected the bounded restored HA configuration')
        value = stream.read()
        if digest(value) != expected:
            if (backup.is_file() and not backup.is_symlink() and backup.stat().st_size <= 1048576
                    and digest(backup.read_bytes()) == expected and transform(backup.read_bytes()) == value):
                return False
            raise ValueError('The restored HA configuration differs; preserve it for review')
        desired = transform(value)
        attributes = {key: os.getxattr(path, key) for key in os.listxattr(path)}
        if backup.exists():
            if backup.is_symlink() or digest(backup.read_bytes()) != expected:
                raise ValueError('The retained HA proxy backup differs')
        else:
            out = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(out, 'wb') as original:
                original.write(value); original.flush(); os.fsync(original.fileno())
        stream.seek(0); stream.write(desired); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        stream.seek(0)
        after = os.fstat(stream.fileno())
        if (stream.read() != desired or (before.st_ino, before.st_uid, before.st_gid, before.st_mode)
                != (after.st_ino, after.st_uid, after.st_gid, after.st_mode)
                or attributes != {key: os.getxattr(path, key) for key in os.listxattr(path)}):
            raise ValueError('HA proxy configuration or metadata readback differs')
    return True


def private_proxy(proxy):
    ip = ipaddress.IPv4Address(proxy)
    if not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        raise ValueError('Select only the private Traefik backend address')
    return str(ip)


def configure_store(path, backup, expected, proxy):
    """Adjust the offline restored v2.2 store before the first HA start."""
    proxy = private_proxy(proxy)
    def transform(value):
        store = json.loads(value)
        if (set(store) != {'version','minor_version','key','data'}
                or store['version'] != 2 or store['minor_version'] != 2 or store['key'] != 'http'
                or set(store['data']) != {'stable','pending','yaml_migration_done'}
                or store['data']['pending'] is not None or store['data']['yaml_migration_done'] is not True
                or not isinstance(store['data']['stable'], dict)):
            raise ValueError('Review an unknown or pending HA HTTP configuration')
        stable = store['data']['stable']
        hosts = stable.get('server_host')
        if hosts is not None and (not isinstance(hosts,list) or not 1 <= len(hosts) <= 8
                or not all(ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_unspecified for host in hosts)):
            raise ValueError('Review the existing HA listener before moving it')
        if (stable.get('server_port') != 8123
                or any(k in stable for k in ('ssl_certificate','ssl_key','ssl_peer_certificate'))
                or stable.get('error') is not None):
            raise ValueError('Review the existing HA listener before moving it')
        stable.update(server_host=['0.0.0.0'],use_x_forwarded_for=True, trusted_proxies=[proxy+'/32'])
        return (json.dumps(store,ensure_ascii=False,indent=2)+'\n').encode()
    return rewrite(path,backup,expected,transform)


def configure(path, backup, expected, proxy):
    ip = private_proxy(proxy)
    store = path.parent/'.storage/http'
    if store.exists() or store.is_symlink():
        raise ValueError('Migrated HA HTTP settings require the exact offline store hash')
    block = ('\n# BEGIN HOMELAB HTTP PROXY\nhttp:\n  use_x_forwarded_for: true\n'
             '  trusted_proxies:\n    - ' + str(ip) + '\n# END HOMELAB HTTP PROXY\n').encode()
    def transform(value):
        if re.search(rb'(?m)^http\s*:', value) or not value.endswith(b'\n'):
            raise ValueError('Preserve the existing HA HTTP settings for review')
        return value + block
    return rewrite(path,backup,expected,transform)


def legacy_sensor(root, backup, home_sha, command_sha):
    """Remove only the obsolete raw Influx directory sensor; never fake its size."""
    def allowlist(value):
        line=b'  - /influxdb_data\n'
        if value.count(line) != 1:
            raise ValueError('The selected legacy directory allowlist differs')
        return value.replace(line,b'',1)
    def command(value):
        blocks=re.split(rb'(?m)(?=^- sensor:)',value)
        selected=[i for i,block in enumerate(blocks) if re.search(
            rb'(?m)^\s+unique_id:\s*command_line_influxdb_size\s*$',block)]
        if len(selected) != 1 or b'du -shm /influxdb_data | cut -f1' not in blocks[selected[0]]:
            raise ValueError('The selected legacy directory sensor differs')
        index=selected[0]
        blocks[index]=b''
        return b''.join(blocks)
    first=rewrite(root/'homeassistant.yaml',backup/'homeassistant.before-legacy.yaml',home_sha,allowlist)
    second=rewrite(root/'command_line.yaml',backup/'command-line.before-legacy.yaml',command_sha,command)
    return first or second


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--proxy', required=True)
    parser.add_argument('--legacy-home-sha256')
    parser.add_argument('--legacy-command-sha256')
    parser.add_argument('--http-store-sha256')
    args = parser.parse_args()
    try:
        if args.http_store_sha256:
            configuration=Path('/srv/homelab/data/homeassistant/config/configuration.yaml')
            if (configuration.is_symlink() or not configuration.is_file() or configuration.stat().st_size > 1048576
                    or digest(configuration.read_bytes()) != args.expected_sha256):
                raise ValueError('The original HA YAML changed; preserve it for review')
            changed = configure_store(Path('/srv/homelab/data/homeassistant/config/.storage/http'),
                Path('/opt/homelab-app/http.before-proxy.json'),args.http_store_sha256,args.proxy)
        else:
            changed = configure(Path('/srv/homelab/data/homeassistant/config/configuration.yaml'),
                Path('/opt/homelab-app/configuration.before-proxy.yaml'), args.expected_sha256, args.proxy)
        if args.legacy_home_sha256 or args.legacy_command_sha256:
            if not args.legacy_home_sha256 or not args.legacy_command_sha256:
                raise ValueError('Supply both original legacy configuration hashes')
            changed=legacy_sensor(Path('/srv/homelab/data/homeassistant/config'),Path('/opt/homelab-app'),
                                  args.legacy_home_sha256,args.legacy_command_sha256) or changed
        print(json.dumps({'changed': changed}))
    except (OSError, ValueError):
        raise SystemExit('HA proxy configuration held; inspect the retained private original') from None
