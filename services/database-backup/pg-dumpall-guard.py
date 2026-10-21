#!/usr/bin/env python3
"""Fail closed before native PG16 cluster dumps if backup coverage is incomplete."""
import json
import os
import subprocess
import sys

NATIVE = '/usr/libexec/postgresql16/pg_dumpall'
PSQL = '/usr/libexec/postgresql16/psql'


def connection_args(arguments):
    values = {}
    for key in ['-h', '-p', '-U']:
        if arguments.count(key) != 1:
            raise RuntimeError('expected_native_backup_connection_arguments')
        index = arguments.index(key)
        if index + 1 >= len(arguments):
            raise RuntimeError('incomplete_native_backup_connection_arguments')
        values[key] = arguments[index + 1]
    if values['-U'] != 'homelab_backup':
        raise RuntimeError('unexpected_postgresql_backup_role')
    return [item for key in ['-h', '-p', '-U'] for item in [key, values[key]]]


def preflight(arguments):
    connection = connection_args(arguments)
    env = dict(os.environ, PGCONNECT_TIMEOUT='10')
    def query(database, sql):
        result = subprocess.run([PSQL, '-X', '-w', *connection, '-d', database,
                                 '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql],
                                env=env, capture_output=True, text=True, timeout=40)
        if result.returncode:
            raise RuntimeError('postgresql_backup_preflight_query_failed')
        return json.loads(result.stdout)
    capabilities = query('postgres',"""SELECT json_build_object(
        'name',current_user,'version',current_setting('server_version_num')::int/10000,
        'superuser',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,
        'replication',rolreplication,'bypassrls',rolbypassrls,'login',rolcanlogin,
        'read_all_data',pg_has_role(current_user,'pg_read_all_data','USAGE'),
        'read_authid',has_table_privilege(current_user,'pg_catalog.pg_authid','SELECT'),
        'connect_all',(SELECT bool_and(has_database_privilege(current_user,oid,'CONNECT'))
                       FROM pg_database WHERE datallowconn))
        FROM pg_roles WHERE rolname=current_user""")
    expected = {'name':'homelab_backup','version':16,'superuser':False,'createdb':False,
                'createrole':False,'replication':False,'bypassrls':True,'login':True,
                'read_all_data':True,'read_authid':True,'connect_all':True}
    if capabilities != expected:
        raise RuntimeError('postgresql_backup_capabilities_changed')
    databases = query('postgres',
        'SELECT json_agg(datname ORDER BY datname) FROM pg_database WHERE datallowconn')
    for database in databases:
        objects = query(database,"""SELECT json_build_object(
            'large_objects',(SELECT count(*) FROM pg_largeobject_metadata),
            'subscriptions',(SELECT count(*) FROM pg_subscription),
            'user_mappings',(SELECT count(*) FROM pg_user_mapping),
            'foreign_tables',(SELECT count(*) FROM pg_foreign_table))""")
        if any(objects.values()):
            raise RuntimeError('postgresql_objects_require_backup_privilege_review')


def main():
    arguments = sys.argv[1:]
    if arguments not in [['--version'], ['-V'], ['--help'], ['-?']]:
        preflight(arguments)
    # The native binary finds its matching pg_dump in the same PG16 directory.
    os.execv(NATIVE, [NATIVE, *arguments])


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error, RuntimeError) else 'postgresql_backup_preflight_failed'
        print(json.dumps({'status':'backup_blocked','reason':reason}), file=sys.stderr)
        raise SystemExit(1)
