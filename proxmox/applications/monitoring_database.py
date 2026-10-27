"""Create only the clean Zabbix database/role and its scoped pg_hba allowance.

Run locally on the commissioned PostgreSQL guest through Ansible/CD. Passwords
arrive on stdin and are never put in command arguments, stdout or receipts.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import base64
import subprocess
import tempfile


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sql(statement):
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At',
                             '-v', 'ON_ERROR_STOP=1', '-d', 'postgres'], input=statement,
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError('PostgreSQL monitoring operation failed; preserve its hold and private evidence')
    return result.stdout.strip()


def save(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def hba_content(original, address):
    import ipaddress
    ip = ipaddress.IPv4Address(address)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError('Use the selected monitoring backend address')
    if b'# HomeLab Zabbix' in original:
        raise ValueError('Existing monitoring HBA configuration needs its retained receipt')
    prefix = ('# HomeLab Zabbix: dedicated database and single guest\n'
              'local all zabbix reject\n'
              f'host zabbix zabbix {ip}/32 scram-sha-256\n'
              'host all zabbix 0.0.0.0/0 reject\n'
              'host all zabbix ::/0 reject\n')
    return prefix.encode() + original


def provision(root, hba, expected, address, password):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', password):
        raise ValueError('Use a new random URL-safe database credential of at least 32 characters')
    if hba.is_symlink() or not hba.is_file() or root.is_symlink():
        raise ValueError('Expected regular PostgreSQL input and state paths')
    root.mkdir(mode=0o700, exist_ok=True)
    owner = {'hba': str(hba), 'before_sha256': expected, 'address': address,
             'database': 'zabbix', 'role': 'zabbix'}
    if (root / 'HOLD.json').exists():
        raise ValueError('A database attempt is held; no automatic replay')
    if (root / 'READY.json').exists():
        ready = json.loads((root / 'READY.json').read_text())
        if ready['owner'] != owner or ready['hba_sha256'] != digest(hba.read_bytes()):
            raise ValueError('Database input or HBA drift; no normalization')
        check = ready['credential_check']
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(check['salt']), n=16384, r=8, p=1).hex()
        if not hmac.compare_digest(actual, check['scrypt']):
            raise ValueError('Database credential drift; no implicit rotation')
        verify()
        return {'created': False}
    if list(root.iterdir()):
        raise ValueError('Partial database evidence needs review')
    original = hba.read_bytes()
    if digest(original) != expected:
        raise ValueError('PostgreSQL HBA differs from the reviewed baseline')
    updated = hba_content(original, address)
    if sql("SELECT count(*) FROM pg_roles WHERE rolname='zabbix'") != '0' or sql("SELECT count(*) FROM pg_database WHERE datname='zabbix'") != '0':
        raise ValueError('Zabbix database or role already exists; no adoption')
    save(root / 'pg_hba.before', original)
    metadata = hba.stat()
    attributes = {name: base64.b64encode(os.getxattr(hba, name)).decode() for name in os.listxattr(hba)}
    save(root / 'pg_hba.metadata.json', json.dumps({'uid': metadata.st_uid, 'gid': metadata.st_gid,
        'mode': metadata.st_mode & 0o7777, 'xattrs': attributes}).encode())
    backup = subprocess.run(['runuser', '-u', 'postgres', '--', 'pg_dumpall', '--globals-only'], capture_output=True, timeout=30, check=True)
    save(root / 'globals.before.sql', backup.stdout)
    save(root / 'HOLD.json', json.dumps({'owner': owner, 'automatic_retry': False}).encode())
    # Restricted URL-safe password above prevents SQL injection. Keep it off argv.
    sql("SET password_encryption='scram-sha-256'; CREATE ROLE zabbix LOGIN PASSWORD '" + password + "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;")
    sql('CREATE DATABASE zabbix OWNER zabbix;')
    info = hba.stat()
    fd, name = tempfile.mkstemp(prefix='.homelab-zabbix-', dir=hba.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), info.st_mode & 0o777)
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            stream.write(updated); stream.flush(); os.fsync(stream.fileno())
        shutil.copystat(hba, name, follow_symlinks=False)
        if {key: base64.b64encode(os.getxattr(name, key)).decode() for key in os.listxattr(name)} != attributes:
            raise ValueError('PostgreSQL HBA metadata could not be preserved')
        os.replace(name, hba)
        sync(hba.parent)
    finally:
        Path(name).unlink(missing_ok=True)
    if sql('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL') != '0':
        raise ValueError('PostgreSQL HBA parser rejected the proposal; retain the original and hold')
    if sql('SELECT pg_reload_conf()') != 't':
        raise ValueError('PostgreSQL configuration reload failed; retain hold')
    verify()
    salt = os.urandom(16)
    credential_check = {'salt': salt.hex(), 'scrypt': hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()}
    save(root / 'READY.json', json.dumps({'owner': owner, 'hba_sha256': digest(updated), 'credential_check': credential_check}).encode())
    (root / 'HOLD.json').unlink()
    sync(root)
    return {'created': True}


def verify():
    if sql("SELECT count(*) FROM pg_roles WHERE rolname='zabbix' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls") != '1':
        raise ValueError('Zabbix role privileges differ')
    if sql("SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname='zabbix' AND r.rolname='zabbix'") != '1':
        raise ValueError('Zabbix database ownership differs')


if __name__ == '__main__':
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hba-sha256', required=True)
    parser.add_argument('--address', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(provision(Path('/var/lib/homelab-zabbix-db'), Path('/etc/postgresql/16/main/pg_hba.conf'),
                                   args.hba_sha256, args.address, sys.stdin.read().strip())))
    except Exception:
        raise SystemExit('Zabbix database preparation stopped. Preserve its evidence and hold; no automatic replay.') from None
