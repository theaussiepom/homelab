"""Read-only accepted-service checks, separate from immutable cutover phases.

The caller admits provenance, source pins and the qualified final network. This
entry point cannot select a migration action or refresh an expected binding.
The complete selected server row remains reviewed configuration; unrelated
history/preferences/accounts are application data and are not fingerprinted.
"""
import ipaddress
import json
import math
import os
import re
import sys

import pgadmin_database_runtime as runtime
import pgadmin_endpoint as endpoint

SCHEMA='homelab-pgadmin-accepted-service-v1'
DEPLOYMENT={'identity','compose_sha256','identity_sha256','config_sha256','image',
            'image_id','container_id','http_address','profile_identity'}
FIELDS=DEPLOYMENT|{'schema','selector','target','server_schema_sha256','server_row_sha256','owner_auth_source'}
require=runtime.require


def typed(value):
    """Unambiguous canonical SQLite scalar encoding; only digests are returned."""
    if value is None:return ['null']
    if type(value) is int:return ['integer',str(value)]
    if type(value) is float:
        require(math.isfinite(value),'Review non-finite selected connection values')
        return ['real',value.hex()]
    if isinstance(value,str):return ['text',value]
    if isinstance(value,bytes):return ['blob',value.hex()]
    raise ValueError('Review unfamiliar selected connection values')


def connection_digests(connection,selector,target):
    endpoint.selection(selector);endpoint.destination(target)
    endpoint.plan(connection,selector,dict(host=target['address'],port=target['port']),target)
    require(connection.execute('SELECT auth_source FROM user WHERE id=?',
        (selector['user_id'],)).fetchall()==[('oauth2',)],'The accepted connection owner is not OAuth')
    columns=connection.execute('PRAGMA table_info(server)').fetchall()
    require(columns and len(columns)<=256,'Review unfamiliar selected connection schema')
    rows=connection.execute('SELECT * FROM server WHERE id=? AND user_id=?',
        (selector['server_id'],selector['user_id'])).fetchall()
    require(len(rows)==1 and len(rows[0])==len(columns),'The accepted connection row is ambiguous')
    schema=runtime.sha(runtime.encoded([[typed(v) for v in row] for row in columns]))
    row=runtime.sha(runtime.encoded({'columns':[r[1] for r in columns],'values':[typed(v) for v in rows[0]]}))
    return schema,row


def validate_binding(binding):
    require(isinstance(binding,dict) and set(binding)==FIELDS and binding['schema']==SCHEMA,
        'Use the closed accepted pgAdmin service binding')
    identity=binding['identity']
    require(isinstance(identity,dict) and set(identity)=={'kind','vmid','hostname','address'}
        and runtime.app_identity(identity)==identity and isinstance(identity['hostname'],str)
        and re.fullmatch('[a-z][a-z0-9-]{0,62}',identity['hostname']), 'Bind the accepted application identity')
    ipaddress.IPv4Address(identity['address']);ipaddress.IPv4Address(binding['http_address'])
    endpoint.selection(binding['selector']);endpoint.destination(binding['target'])
    require(binding['owner_auth_source']=='oauth2','Retain the accepted OAuth owner')
    for key in ('compose_sha256','identity_sha256','config_sha256','server_schema_sha256','server_row_sha256'):
        runtime.hash_value(binding[key])
    require(isinstance(binding['image'],str) and re.fullmatch(r'dpage/pgadmin4@sha256:[0-9a-f]{64}',binding['image'])
        and isinstance(binding['image_id'],str) and re.fullmatch('sha256:[0-9a-f]{64}',binding['image_id'])
        and isinstance(binding['container_id'],str) and re.fullmatch('[0-9a-f]{64}',binding['container_id']),
        'Bind the accepted immutable image and container')
    metadata=binding['profile_identity']
    require(isinstance(metadata,dict) and set(metadata)=={'device','inode','uid','gid','mode','xattrs_sha256'}
        and all(type(metadata[k]) is int and metadata[k]>=0 for k in ('device','inode','uid','gid'))
        and isinstance(metadata['mode'],str) and re.fullmatch('0[0-7]{3}',metadata['mode']),
        'Bind the accepted exact profile file metadata')
    runtime.hash_value(metadata['xattrs_sha256'])
    return True


def verify_accepted_service(app,binding):
    validate_binding(binding)
    require(runtime.app_identity(app)==binding['identity'],'Accepted app identity differs')
    bound,_=runtime.runtime(app,binding,running=True)
    require(all(bound[k]==binding[k] for k in ('identity','container_id','image_id')),
        'Accepted deployment container identity changed')
    metadata=runtime.profile_identity()
    require(metadata==binding['profile_identity'],'Accepted profile file metadata changed')
    with runtime.database(runtime.PROFILE) as connection:
        schema,row=connection_digests(connection,binding['selector'],binding['target'])
    require(schema==binding['server_schema_sha256'] and row==binding['server_row_sha256'],
        'Accepted selected connection schema or settings changed')
    require(runtime.profile_identity()==metadata,'Profile identity changed during service verification')
    runtime.http_ready(binding['http_address'])
    return dict(status='passed',kind='pgadmin-accepted-service',changed=False,
        deployment_verified=True,registration_verified=True,http_verified=True,current_sql_tested=False)


if __name__=='__main__':
    try:
        require(os.geteuid()==0,'Use the admitted read-only guest playbook')
        require(len(sys.argv)==1,'This entry point has no action selector')
        raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'Oversized accepted-service input')
        values=json.loads(raw);require(isinstance(values,dict) and set(values)=={'app','binding'},'Unexpected accepted-service input')
        print(json.dumps(verify_accepted_service(values['app'],values['binding']),sort_keys=True))
    except Exception:
        raise SystemExit('Accepted pgAdmin service verification held; preserve evidence and review its baseline. No recovery or rebinding.') from None
