"""Native adapter for the existing, qualified PostgreSQL clean dump contract.

See services/database-backup/POSTGRESQL-CLEAN-RECOVERY.md. Never rewrite SQL.
"""
import json
import os
import re
import secrets
import subprocess

from restore import sync_directory


def check_diagnostics(stderr, returncode):
    """Permit only the exact ordered bootstrap-OID exceptions already qualified."""
    prefix = r'^(?:psql:[^\n]+?:[0-9]+:\s*)?'
    errors = list(re.finditer(prefix + r'(ERROR|FATAL|PANIC):\s+([A-Z0-9]{5}): ([^\n]+)$', stderr, re.M))
    all_headers = re.findall(prefix + r'(?:ERROR|FATAL|PANIC):', stderr, re.M)
    expected = [('2BP01', 'cannot drop role postgres because it is required by the database system', 'checkSharedDependencies', 'pg_shdepend.c'),
                ('42710', 'role "postgres" already exists', 'CreateRole', 'user.c')]
    if returncode != 0 or len(errors) != 2 or len(all_headers) != 2:
        raise ValueError('Clean restore contains an unexpected SQL/client failure')
    for index, (match, (state, message, function, file)) in enumerate(zip(errors, expected)):
        block = stderr[match.start():errors[index + 1].start() if index + 1 < len(errors) else len(stderr)]
        if match.group(1) != 'ERROR' or match.group(2) != state or match.group(3) != message or not re.search(r'LOCATION:\s+' + function + r', ' + re.escape(file) + r':[0-9]+', block):
            raise ValueError('Clean restore diagnostics differ from the qualified bootstrap exception pair')


def restore_clean(capture, root, execute=subprocess.run):
    """Use a temporary local maintenance identity/database, then remove only those."""
    with capture.open('rb') as stream:
        if b'PostgreSQL database cluster dump' not in stream.read(1024):
            raise ValueError('Supply the unchanged, uncompressed pg_dumpall clean SQL input')
    base = ['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '--dbname=postgres']
    fresh = execute(base + ['-Atc', "SELECT COALESCE(json_agg(datname), '[]') FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"], capture_output=True, text=True, check=True)
    if json.loads(fresh.stdout) != []:
        raise ValueError('Clean restore requires the selected fresh database cluster')
    roles = execute(base + ['-Atc', "SELECT COALESCE(json_agg(rolname), '[]') FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_'"], capture_output=True, text=True, check=True)
    if json.loads(roles.stdout) != []:
        raise ValueError('Do not adopt pre-existing application roles into the new restore target')
    suffix = secrets.token_hex(8)
    identity = 'homelab_restore_' + suffix
    password = secrets.token_urlsafe(32)
    metadata = root / 'postgresql-maintenance.json'
    fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'role': identity, 'database': identity, 'state': 'creation-planned'}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(root)
    # Generated identifiers and password have no quote characters; SQL is stdin-only.
    ddl = f'CREATE ROLE {identity} LOGIN SUPERUSER PASSWORD \'{password}\';\nCREATE DATABASE {identity} OWNER {identity};\n'
    execute(base, input=ddl, text=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    environment = dict(os.environ, PGPASSWORD=password)
    command = ['runuser', '-u', 'postgres', '--', 'psql', '-X', '--host=127.0.0.1', '--username=' + identity,
               '--dbname=' + identity, '--set=VERBOSITY=verbose', '--set=ON_ERROR_STOP=off']
    log = root / 'postgresql-clean.stderr'
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with capture.open('rb') as source, os.fdopen(fd, 'w') as stderr:
        result = execute(command, stdin=source, env=environment, stdout=subprocess.DEVNULL, stderr=stderr)
        stderr.flush()
        os.fsync(stderr.fileno())
    if log.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Restore diagnostics exceed their bound; preserve the target for review')
    check_diagnostics(log.read_text(), result.returncode)
    bootstrap = execute(base + ['-Atc', "SELECT oid FROM pg_roles WHERE rolname='postgres'"], capture_output=True, text=True, check=True)
    if bootstrap.stdout.strip() != '10':
        raise ValueError('The protected bootstrap role no longer has OID 10')
    execute(base, input=f'DROP DATABASE {identity};\nDROP ROLE {identity};\n', text=True, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with metadata.open('w') as stream:
        json.dump({'role': identity, 'database': identity, 'state': 'removed'}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(root)
