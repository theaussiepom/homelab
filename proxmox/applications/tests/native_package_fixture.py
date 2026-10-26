"""Check exact native DB packages and synthetic restore in disposable Docker.

No guest, production data, host mount/device/port or privileged container is used.
Networking is disconnected before the synthetic database is started. This does
not prove systemd or LXC startup. Run one engine at a time.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import uuid

BASE_IMAGE = 'debian@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad'
PROFILES = {
    'mariadb': {
        'user': 'mysql', 'group': 'mysql', 'account_mode': 'package', 'home': '/var/lib/mysql',
        'key_url': 'https://mariadb.org/mariadb_release_signing_key.asc',
        'key_sha256': '00adb387f4c12e8982cfc28165d225695621494354cd58108c6845063bfb74b5',
        'fingerprint': '177F4010FE56CA3336300305F1656F24C74CD1D8',
        'repository': 'https://dlm.mariadb.com/repo/mariadb-server/12.3.3/repo/debian',
        'suite': 'trixie',
        'pins': ['mariadb-server=1:12.3.3+maria~deb13', 'mariadb-client=1:12.3.3+maria~deb13'],
        'fixture': 'mariadb_fixture.py',
    },
    'postgresql': {
        'user': 'postgres', 'group': 'postgres', 'uid': 70, 'gid': 1000, 'home': '/var/lib/postgresql',
        'key_url': 'https://www.postgresql.org/media/keys/ACCC4CF8.asc',
        'key_sha256': '0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76',
        'fingerprint': 'B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8',
        'repository': 'https://apt-archive.postgresql.org/pub/repos/apt',
        'suite': 'trixie-pgdg-archive',
        'pins': ['postgresql-16=16.10-1.pgdg13+1', 'postgresql-client-16=16.10-1.pgdg13+1', 'libpq5=16.10-1.pgdg13+1'],
        'fixture': 'pg_native_fixture.py',
    },
}


def package_script(profile):
    """Only fixed public profiles enter this shell, never operator input."""
    names = ' '.join(pin.split('=')[0] for pin in profile['pins'])
    if profile.get('account_mode') == 'package':
        identity = '''getent group 999 && exit 13 || test "$?" -eq 2
groupadd --system --gid 999 systemd-journal
getent group systemd-journal > /tmp/journal-before
'''
    else:
        identity = f'''getent passwd {profile['uid']} && exit 12 || test "$?" -eq 2
getent group {profile['gid']} && exit 13 || test "$?" -eq 2
groupadd --system --gid {profile['gid']} {profile['group']}
useradd --system --uid {profile['uid']} --gid {profile['group']} --home-dir {profile['home']} --no-create-home --shell /usr/sbin/nologin {profile['user']}
'''
    return f'''set -eu
export DEBIAN_FRONTEND=noninteractive
{identity}printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get update
apt-get install -y --no-install-recommends ca-certificates gnupg python3
mkdir -p /etc/apt/keyrings
gpg --show-keys --with-colons /tmp/vendor.asc > /tmp/key-info
grep '^fpr:::::::::{profile['fingerprint']}:' /tmp/key-info
cp /tmp/vendor.asc /etc/apt/keyrings/vendor.asc
printf 'Types: deb\\nURIs: {profile['repository']}\\nSuites: {profile['suite']}\\nComponents: main\\nArchitectures: amd64\\nSigned-By: /etc/apt/keyrings/vendor.asc\\n' > /etc/apt/sources.list.d/vendor.sources
apt-get update
apt-get --simulate --no-install-recommends install {' '.join(profile['pins'])}
apt-get install -y --no-install-recommends {' '.join(profile['pins'])}
dpkg-query -W -f='${{Package}}=${{Version}}\\n' {names}
getent passwd {profile['user']}
getent group {profile['group']}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('engine', choices=PROFILES)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    context = json.loads(subprocess.check_output(['docker', 'context', 'inspect'], text=True, timeout=30))
    endpoint = context[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://') or not os.environ.get('DOCKER_HOST', 'unix://').startswith('unix://'):
        raise ValueError('Use a local Docker socket, never a remote household Docker host')
    root = args.evidence.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = PROFILES[args.engine]
    with urllib.request.urlopen(profile['key_url'], timeout=30) as response:
        key_bytes = response.read(65537)
    if len(key_bytes) > 65536 or hashlib.sha256(key_bytes).hexdigest() != profile['key_sha256']:
        raise ValueError('Vendor key changed; review the signing key before running this fixture')
    (root / 'vendor.asc').write_bytes(key_bytes)
    name = 'homelab-db-package-' + args.engine + '-' + uuid.uuid4().hex[:8]
    receipt = {'engine': args.engine, 'container': name, 'image': BASE_IMAGE,
               'limits': {'cpus': 2, 'memory': '2g', 'pids': 256}, 'pins': profile['pins'],
               'native_lxc_qualified': False}
    created = False
    try:
        with (root / 'fixture.log').open('xb') as output:
            def docker(*command, **kwargs):
                return subprocess.run(['docker'] + list(command), check=True, timeout=60,
                                      stdout=output, stderr=output, **kwargs)
            docker('run', '-d', '--platform', 'linux/amd64', '--cpus', '2', '--memory', '2g',
                   '--pids-limit', '256', '--name', name, BASE_IMAGE, 'sleep', '900')
            created = True
            docker('cp', str(root / 'vendor.asc'), name + ':/tmp/vendor.asc')
            installed = subprocess.run(['docker', 'exec', '-i', name, 'sh', '-s'],
                input=package_script(profile).encode(), stdout=output, stderr=output, timeout=600)
            receipt['package_exit_code'] = installed.returncode
            receipt['packages_installed'] = installed.returncode == 0
            if installed.returncode == 0:
                docker('cp', name + ':/var/lib/dpkg/status', str(root / 'installed-status'))
                docker('network', 'disconnect', 'bridge', name)
                application = Path(__file__).resolve().parents[1]
                for relative in ['database.py', 'pg_clean.py', 'restore.py', 'tests/' + profile['fixture']]:
                    destination = '/fixture/' + relative
                    docker('exec', name, 'mkdir', '-p', str(Path(destination).parent))
                    docker('cp', str(application / relative), name + ':' + destination)
                restored = subprocess.run(['docker', 'exec', name, 'python3', '/fixture/tests/' + profile['fixture']],
                                          stdout=output, stderr=output, timeout=180)
                receipt['synthetic_restore_exit_code'] = restored.returncode
                if restored.returncode == 0 and profile.get('account_mode') == 'package':
                    docker('cp', name + ':/tmp/mariadb-native-identity-restore.json',
                           str(root / 'mariadb-native-identity-restore.json'))
    finally:
        if created:
            inspected = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True, timeout=30)
            (root / 'container-inspect.json').write_text(inspected.stdout)
            removed = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, text=True, timeout=30)
            receipt['container_removed'] = removed.returncode == 0
            (root / 'cleanup.stderr').write_text(removed.stderr)
        (root / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))
    if receipt.get('package_exit_code') != 0 or receipt.get('synthetic_restore_exit_code') != 0 or not receipt.get('container_removed'):
        raise SystemExit('Native package fixture failed; inspect the retained evidence')


if __name__ == '__main__':
    main()
