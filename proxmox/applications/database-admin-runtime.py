#!/usr/bin/env python3
"""Create only a declared, owned native database administrator through guest CD."""
import base64
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/var/lib/homelab-database-administrators')


def need(ok):
    if not ok:
        raise ValueError('Native database administration held')


def fingerprint(password, owner):
    context = ('homelab-database-custody-v1\0'+json.dumps(owner, sort_keys=True, separators=(',', ':'))).encode()
    return hashlib.pbkdf2_hmac('sha256', password.encode(), context, 600000).hex()


def run(args, text):
    return subprocess.run(args, input=text, text=True, capture_output=True, check=True, timeout=30).stdout.strip()


def pg(statement):
    return run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At', '-h', '/var/run/postgresql',
                '-p', '5432', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres'], statement)


def maria(statement):
    return run(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names'], statement)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(value, sort_keys=True)+'\n').encode()); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536)
        value = stream.read(65537)
        after = os.fstat(stream.fileno())
        need(len(value) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return json.loads(value)


def scram(password, verifier):
    match = re.fullmatch(r'SCRAM-SHA-256\$([0-9]+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)', verifier or '')
    need(match is not None and 4096 <= int(match[1]) <= 1000000)
    salt, stored, server = [base64.b64decode(match[index], validate=True) for index in (2, 3, 4)]
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, int(match[1]))
    need(hmac.compare_digest(stored, hashlib.sha256(hmac.digest(salted, b'Client Key', 'sha256')).digest())
         and hmac.compare_digest(server, hmac.digest(salted, b'Server Key', 'sha256')))


def postgres_state(user):
    return json.loads(pg("SELECT json_agg(json_build_object('name',rolname,'login',rolcanlogin,'super',rolsuper,"
        "'createdb',rolcreatedb,'createrole',rolcreaterole,'replication',rolreplication,'bypassrls',rolbypassrls,"
        "'password',rolpassword,'connection_limit',rolconnlimit,'expires',rolvaliduntil,"
        "'memberships',(SELECT count(*) FROM pg_auth_members WHERE member=r.oid))) FROM pg_authid r WHERE rolname='"+user+"';") or 'null') or []


def postgres_verify(item, password):
    user, source = item['username'], item['owner']['source_address']
    need(pg('SHOW ssl;') == 'on')
    values = postgres_state(user); need(len(values) == 1)
    row = values[0]
    need(row['name'] == user and all(row[key] is True for key in ('login', 'super', 'createdb', 'createrole', 'replication', 'bypassrls'))
         and row['connection_limit'] == -1 and row['expires'] is None and row['memberships'] == 0)
    scram(password, row['password'])
    postgres_hba(item)


def postgres_hba(item):
    user, source = item['username'], item['owner']['source_address']
    need(pg('SELECT count(*) = 0 FROM pg_hba_file_rules WHERE error IS NOT NULL;') == 't')
    rows = json.loads(pg("SELECT json_agg(json_build_object('type',type,'database',database,'user_name',user_name,"
        "'address',address,'netmask',netmask,'method',auth_method,'options',options,'error',error) ORDER BY rule_number) "
        "FROM pg_hba_file_rules WHERE '"+user+"'=ANY(user_name);") or 'null')
    expected = [('hostssl', source, '255.255.255.255', 'scram-sha-256'), ('local', None, None, 'reject'),
                ('host', '0.0.0.0', '0.0.0.0', 'reject'), ('host', '::', '::', 'reject')]
    need(isinstance(rows, list) and len(rows) == len(expected))
    for row, (kind, address, mask, method) in zip(rows, expected):
        need(row['type'] == kind and row['database'] == ['all', 'replication'] and row['user_name'] == [user]
             and row['address'] == address and row['netmask'] == mask and row['method'] == method
             and row['options'] is None and row['error'] is None)


def postgres_reload():
    before = pg('SELECT pg_conf_load_time()::text;')
    need(bool(before) and len(before) <= 128 and pg('SELECT pg_reload_conf();') == 't')
    for attempt in range(20):
        current = pg('SELECT pg_conf_load_time()::text;')
        need(bool(current) and len(current) <= 128)
        if current != before:
            return
        if attempt < 19:
            time.sleep(0.1)
    need(False)


def mysql_state(user):
    raw = maria("SELECT JSON_OBJECT('name',User,'host',Host,'plugin',plugin,'password',authentication_string,'ssl',ssl_type) "
                "FROM mysql.user WHERE User='"+user+"';")
    return [json.loads(row) for row in raw.splitlines()]


def parsec_plugin(required=False):
    raw = maria("SELECT JSON_OBJECT('name',PLUGIN_NAME,'status',PLUGIN_STATUS,'type',PLUGIN_TYPE,'library',PLUGIN_LIBRARY) "
                "FROM information_schema.PLUGINS WHERE PLUGIN_NAME='parsec';")
    rows = [json.loads(row) for row in raw.splitlines()]
    need(rows == [] or rows == [{'name':'parsec', 'status':'ACTIVE', 'type':'AUTHENTICATION', 'library':'auth_parsec.so'}])
    need(not required or bool(rows))
    return bool(rows)


def parsec_verifier(password, stored=None):
    # MariaDB 12.3.3 accepts P0..P3 only. Use its strongest supported P3
    # (8192 rounds), a fresh salt, and the generated 256-bit machine secret.
    # The separate custody fingerprint uses 600000 rounds.
    if stored is None:
        salt = os.urandom(18)
    else:
        need(isinstance(stored, str) and re.fullmatch(r'P3:[A-Za-z0-9+/]{24}:[A-Za-z0-9+/]{43}', stored))
        salt = base64.b64decode(stored.split(':')[1], validate=True)
        need(len(salt) == 18)
    seed = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 8192, dklen=32)
    private_der = bytes.fromhex('302e020100300506032b657004220420')+seed
    result = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                            input=private_der, capture_output=True, check=True, timeout=10).stdout
    prefix = bytes.fromhex('302a300506032b6570032100')
    need(len(result) == len(prefix)+32 and result.startswith(prefix))
    return 'P3:'+base64.b64encode(salt).decode()+':'+base64.b64encode(result[len(prefix):]).decode().rstrip('=')


def mysql_verify(item, password):
    parsec_plugin(required=True)
    need(maria("SHOW GLOBAL VARIABLES LIKE 'have_ssl';").split() == ['have_ssl', 'YES'])
    user, source = item['username'], item['owner']['source_address']
    rows = mysql_state(user); need(len(rows) == 1)
    expected = parsec_verifier(password, rows[0]['password'])
    need(rows[0] == {'name': user, 'host': source, 'plugin': 'parsec', 'password': expected, 'ssl': 'ANY'})
    grants = maria("SHOW GRANTS FOR '"+user+"'@'"+source+"';").splitlines()
    need(len(grants) == 1 and grants[0].startswith("GRANT ALL PRIVILEGES ON *.* TO `"+user+"`@`"+source+"`")
         and ' REQUIRE SSL' in grants[0] and grants[0].endswith(' WITH GRANT OPTION'))


def validate(value):
    need(os.geteuid() == 0 and isinstance(value, dict) and set(value) == {'engine', 'account', 'credential'})
    engine, item, credential = value['engine'], value['account'], value['credential']
    need(isinstance(engine, str) and engine in {'postgresql', 'mariadb'} and isinstance(item, dict)
         and set(item) == {'username', 'source_guest', 'credential_id', 'credential_file', 'access', 'transport', 'owner'}
         and item['access'] == 'server-administration' and item['transport'] == 'tls'
         and isinstance(item['username'], str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', item['username'])
         and isinstance(item['credential_id'], str) and re.fullmatch('[a-z][a-z0-9-]{2,63}', item['credential_id']))
    own = item['owner']
    need(isinstance(own, dict) and set(own) == {'node', 'engine', 'database_vmid', 'source_vmid', 'server_address',
            'source_address', 'username', 'purpose'} and own['engine'] == engine and own['username'] == item['username']
         and own['purpose'] == 'database-administration' and isinstance(own['node'], str)
         and re.fullmatch('[A-Za-z0-9_.-]{1,128}', own['node'])
         and all(type(own[key]) is int and own[key] >= 100 for key in ('database_vmid', 'source_vmid')))
    for field in ('source_address', 'server_address'):
        need(isinstance(own[field], str))
        address = ipaddress.IPv4Address(own[field])
        need(address.is_private and not (address.is_multicast or address.is_loopback or address.is_unspecified or address.is_link_local))
    need(isinstance(credential, dict) and set(credential) == {'schema', 'owner', 'password'}
         and credential['schema'] == 'homelab-application-account-v1' and credential['owner'] == own
         and isinstance(credential['password'], str) and re.fullmatch('[0-9a-f]{64}', credential['password']))
    return engine, item, credential


def apply(value):
    engine, item, credential = validate(value)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    info = ROOT.lstat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    receipt, hold = ROOT/(item['credential_id']+'.json'), ROOT/(item['credential_id']+'-HOLD.json')
    need(not hold.exists() and not hold.is_symlink())
    proof = {'owner': item['owner'], 'credential_fingerprint': fingerprint(credential['password'], item['owner']),
             'access': 'server-administration', 'transport': 'tls'}
    rows = postgres_state(item['username']) if engine == 'postgresql' else mysql_state(item['username'])
    plugin_exists = parsec_plugin() if engine == 'mariadb' else False
    existing = receipt.exists() or receipt.is_symlink()
    need(len(rows) == (1 if existing else 0))
    if existing:
        need(private(receipt) == proof)
        if engine == 'postgresql':
            postgres_verify(item, credential['password'])
    else:
        need((pg('SHOW ssl;') == 'on') if engine == 'postgresql'
             else maria("SHOW GLOBAL VARIABLES LIKE 'have_ssl';").split() == ['have_ssl', 'YES'])
    if engine == 'postgresql':
        postgres_hba(item)
        write_new(hold, proof)
        # Preparation may already have written the file. Load it before any
        # new LOGIN role, including when service startup itself was a no-op.
        postgres_reload()
        postgres_hba(item)
    elif not existing:
        write_new(hold, proof)
    if not existing:
        user, source = item['username'], item['owner']['source_address']
        if engine == 'postgresql':
            pg('CREATE ROLE "'+user+'" LOGIN SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS;')
            run(['runuser', '-u', 'postgres', '--', 'setsid', '--wait', 'psql', '-X', '-h', '/var/run/postgresql',
                '-p', '5432', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres', '-c', "SET password_encryption='scram-sha-256'",
                '-c', '\\password "'+user+'"'], credential['password']+'\n'+credential['password']+'\n')
        else:
            if not plugin_exists:
                maria("INSTALL SONAME 'auth_parsec';")
                parsec_plugin(required=True)
            maria("CREATE USER '"+user+"'@'"+source+"' IDENTIFIED VIA parsec USING '"+parsec_verifier(credential['password'])+"' REQUIRE SSL;\n"
                  "GRANT ALL PRIVILEGES ON *.* TO '"+user+"'@'"+source+"' WITH GRANT OPTION;")
    (postgres_verify if engine == 'postgresql' else mysql_verify)(item, credential['password'])
    if not existing:
        write_new(receipt, proof)
    if engine == 'postgresql' or not existing:
        hold.unlink(); sync(ROOT)
    return {'administrator': 'verified', 'transport': 'tls', 'source_restricted': True}


def preflight(value):
    """Read before ordinary database configuration or service reconciliation."""
    engine, item, credential = validate(value)
    receipt, hold = ROOT/(item['credential_id']+'.json'), ROOT/(item['credential_id']+'-HOLD.json')
    if ROOT.exists() or ROOT.is_symlink():
        info = ROOT.lstat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    need(not hold.exists() and not hold.is_symlink())
    existing = receipt.exists() or receipt.is_symlink()
    rows = postgres_state(item['username']) if engine == 'postgresql' else mysql_state(item['username'])
    if engine == 'mariadb':
        parsec_plugin()
    need(len(rows) == (1 if existing else 0))
    if existing:
        need(private(receipt) == {'owner': item['owner'], 'credential_fingerprint': fingerprint(credential['password'], item['owner']),
             'access': 'server-administration', 'transport': 'tls'})
        (postgres_verify if engine == 'postgresql' else mysql_verify)(item, credential['password'])
    need((pg('SHOW ssl;') == 'on') if engine == 'postgresql'
         else maria("SHOW GLOBAL VARIABLES LIKE 'have_ssl';").split() == ['have_ssl', 'YES'])
    return {'administrator_preflight': 'verified'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(1024*1024+1); need(len(raw) <= 1024*1024)
        result = (preflight if args.preflight else apply)(json.loads(raw))
    except Exception:
        raise SystemExit('Database administrator deployment held; inspect privately.') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
