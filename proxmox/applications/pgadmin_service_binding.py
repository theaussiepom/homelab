"""Derive accepted metadata only from the original validated quiesce backup.

The caller admits successful completion/SQL acceptance and source/network
provenance. No current profile, container, HTTP or network observation can be
adopted by this builder. Replacement is projected in SQLite memory only.
"""
import copy
import json
import os
import sqlite3
import sys

import pgadmin_database_runtime as runtime
import pgadmin_endpoint as endpoint
import pgadmin_service_verify as service

require=runtime.require


def build_binding(app,request):
    require(isinstance(request,dict) and set(request)==runtime.PREPARED|{'quiesced'},
        'Use the exact original runtime request and quiesce receipt')
    original=runtime.base_request(request);runtime.validate_request(original)
    require(runtime.app_identity(app)==original['identity'],'Original app identity differs')
    receipt,protected=runtime.quiesced(request)
    # quiesced() validates the original private backup bytes and logical state.
    # This second read derives only the selected row from its exact projection;
    # full logical/physical checks bind both reads to the original receipt.
    path=runtime.backup_path(request)
    expected=sqlite3.connect(':memory:')
    try:
        with runtime.database(path) as connection:
            require(runtime.fingerprint(connection)==original['profile_sha256'],
                'Original backup logical state changed')
            connection.backup(expected)
        endpoint.replacement_apply(expected,original['replacement'])
        require(runtime.fingerprint(expected)==protected,'Original replacement projection changed')
        selector=dict(server_id=original['replacement']['created_server_id'],user_id=original['selector']['user_id'])
        schema,row=service.connection_digests(expected,selector,original['target'])
    finally:expected.close()
    require(runtime.file_sha(path)==receipt['backup_sha256'],'Original backup bytes changed during derivation')
    binding={k:copy.deepcopy(original[k]) for k in service.DEPLOYMENT}
    binding.update(schema=service.SCHEMA,selector=selector,target=dict(original['target']),
        server_schema_sha256=schema,server_row_sha256=row,owner_auth_source='oauth2')
    service.validate_binding(binding)
    return dict(status='passed',kind='pgadmin-accepted-binding',binding=binding,
        derived_from=dict(runtime_request_sha256=runtime.sha(runtime.encoded(original)),
            quiesce_backup_sha256=receipt['backup_sha256'],quiesce_profile_sha256=receipt['profile_sha256']))


if __name__=='__main__':
    try:
        require(os.geteuid()==0,'Use the admitted read-only backup projection playbook')
        require(len(sys.argv)==1,'This entry point has no action selector')
        raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'Oversized original binding input')
        values=json.loads(raw);require(isinstance(values,dict) and set(values)=={'app','request'},'Unexpected original binding input')
        print(json.dumps(build_binding(values['app'],values['request']),sort_keys=True))
    except Exception:
        raise SystemExit('Accepted pgAdmin binding derivation held; preserve original evidence. No live adoption or recovery.') from None
