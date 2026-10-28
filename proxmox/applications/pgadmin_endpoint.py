"""Existing pgAdmin server-row adapter for the shared maintenance controller.

No files, services, networks, receipts or credentials are opened or managed here.
The caller owns guest admission, an offline backup, writer quiescence, source and
packet binding, and the SQLite connection. The endpoint-only API changes only
host/port. The explicit replacement API retires the bound registration inventory
and creates one fresh OAuth-owned row, retaining that owner's connection settings.
"""
import ipaddress
import hashlib
import json
import sqlite3


def quoted(name): return '"'+name.replace('"','""')+'"'


def registrations(connection):
    """Only safe IDs/endpoint literals, with no login or credential values."""
    rows=connection.execute('SELECT id,user_id,host,port FROM server ORDER BY id').fetchall()
    result=[]
    for sid,uid,host,port in rows:
        selection({'server_id':sid,'user_id':uid});origin({'host':host,'port':port})
        result.append(dict(server_id=sid,user_id=uid,host=host,port=port))
    require(result,'Bind the nonempty existing registration inventory')
    return result


def replacement_plan(connection, selector, before, target):
    """Replace the observed registration inventory using one approved OAuth row.

    The new row keeps the selected owner's settings and encrypted values in
    SQLite. Only its ID/name/host/port change. No credential leaves the database.
    Query history belonging to removed registrations is cleared like pgAdmin's
    delete action. The selected registration's per-database schema settings move
    to the fresh ID without changing their contents. Other dependent data holds.
    """
    selected=plan(connection,selector,before,target)
    try:
        removed=registrations(connection)
        require(connection.execute('SELECT auth_source FROM user WHERE id=?',
                (selector['user_id'],)).fetchall()==[('oauth2',)],'Bind the approved existing OAuth owner')
        require(not connection.execute("SELECT 1 FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ('server','query_history','database') LIMIT 1").fetchone(),
                'Review registration/history triggers separately')
        require(not connection.execute('SELECT 1 FROM sharedserver LIMIT 1').fetchone(),
                'Review shared registrations before replacement')
        tables=[r[0] for r in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")]
        ids=[r['server_id'] for r in removed];parameters=','.join('?' for _ in ids)
        history=[];database_rows=[]
        for table in tables:
            for foreign in connection.execute('PRAGMA foreign_key_list('+quoted(table)+')'):
                if foreign[2]!='server': continue
                allowed=foreign[4]=='id' and ((table=='query_history' and foreign[3]=='sid')
                        or (table=='database' and foreign[3]=='server'))
                if not allowed:
                    require(not connection.execute('SELECT 1 FROM '+quoted(table)+' WHERE '+quoted(foreign[3])+
                            ' IN ('+parameters+') LIMIT 1',ids).fetchone(),'Review dependent registration data separately')
            if table=='debugger_function_arguments':
                require(not connection.execute('SELECT 1 FROM '+quoted(table)+' WHERE server_id IN ('+parameters+') LIMIT 1',ids).fetchone(),
                        'Review dependent debugger data separately')
            if table=='query_history':
                history=connection.execute('SELECT * FROM query_history WHERE sid IN ('+parameters+') ORDER BY rowid',ids).fetchall()
            if table=='database':
                require(any(fk[2:5]==('server','server','id') for fk in
                            connection.execute('PRAGMA foreign_key_list("database")')),
                        'Review unfamiliar per-database settings schema')
                require(not connection.execute('SELECT 1 FROM "database" WHERE server IN ('+parameters+
                        ') AND server<>? LIMIT 1',[*ids,selector['server_id']]).fetchone(),
                        'Review another registration owner\'s database settings separately')
                database_rows=connection.execute('SELECT * FROM "database" WHERE server=? ORDER BY rowid',
                                                 (selector['server_id'],)).fetchall()
        rows=connection.execute('SELECT * FROM server ORDER BY id').fetchall()
        digest=hashlib.sha256(repr((rows,history,database_rows)).encode()).hexdigest()
        sequence=0
        if 'sqlite_sequence' in tables:
            sequences=connection.execute("SELECT seq FROM sqlite_sequence WHERE name='server'").fetchall()
            require(len(sequences)<=1,'Ambiguous registration sequence')
            if sequences:
                sequence=sequences[0][0]
                require(type(sequence) is int and sequence>=0,'Invalid registration sequence')
        created=max(*ids,sequence)+1
        if 'database' in tables:
            require(not connection.execute('SELECT 1 FROM "database" WHERE server=? LIMIT 1',(created,)).fetchone(),
                    'The fresh registration would attach unrelated database settings')
    except sqlite3.Error:
        raise ValueError('The registration dependency schema requires review') from None
    return dict(selector=dict(selector),before=dict(before),after=selected['after'],removed_servers=removed,
                created_server_id=created,server_sequence=sequence,
                database_rows_count=len(database_rows),name='PostgreSQL',
                owner_auth_source='oauth2',profile_rows_sha256=digest)


def replacement_apply(connection, proposal, *, validate_update=None):
    """Atomic fresh-ID replacement, under the caller's quiescence and backup."""
    require(isinstance(proposal,dict) and set(proposal)=={'selector','before','after','removed_servers',
            'created_server_id','server_sequence','database_rows_count','name','owner_auth_source','profile_rows_sha256'},'Use the exact replacement proposal')
    require(validate_update is None or callable(validate_update),'Use a trusted update validator')
    require(not connection.in_transaction,'Preserve the caller-owned transaction')
    try:
        connection.execute('BEGIN IMMEDIATE')
        current=replacement_plan(connection,proposal['selector'],proposal['before'],
                                 {'address':proposal['after']['host'],'port':proposal['after']['port']})
        require(current==proposal,'The observed registration inventory or settings changed')
        columns=[r[1] for r in connection.execute('PRAGMA table_info(server)')]
        values=list(connection.execute('SELECT * FROM server WHERE id=? AND user_id=?',
                    (proposal['selector']['server_id'],proposal['selector']['user_id'])).fetchone())
        for key,value in dict(id=proposal['created_server_id'],name=proposal['name'],**proposal['after']).items():
            values[columns.index(key)]=value
        ids=[r['server_id'] for r in proposal['removed_servers']]
        parameters=','.join('?' for _ in ids)
        # Insert first, with an explicitly fresh ID, then retire the bound old
        # registrations. The transaction/callback covers all deletes and insert.
        connection.execute('INSERT INTO server ('+','.join(map(quoted,columns))+') VALUES ('+
                           ','.join('?' for _ in columns)+')',values)
        if 'database' in [r[0] for r in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")]:
            moved=connection.execute('UPDATE "database" SET server=? WHERE server=?',
                    (proposal['created_server_id'],proposal['selector']['server_id']))
            require(moved.rowcount==proposal['database_rows_count'],'Per-database settings count drifted')
        if connection.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='query_history'").fetchone():
            connection.execute('DELETE FROM query_history WHERE sid IN ('+parameters+')',ids)
        deleted=connection.execute('DELETE FROM server WHERE id IN ('+parameters+')',ids)
        require(deleted.rowcount==len(ids),'Replacement did not retire the exact old registrations')
        require(registrations(connection)==[dict(server_id=proposal['created_server_id'],
                user_id=proposal['selector']['user_id'],**proposal['after'])],'Unexpected replacement inventory')
        if validate_update is not None: validate_update(connection)
        connection.commit()
    except BaseException as error:
        connection.rollback()
        if isinstance(error,(sqlite3.Error,TypeError,KeyError)):
            raise ValueError('The registration replacement transaction held') from None
        raise
    return True


def require(value, message):
    if not value:
        raise ValueError(message)


def selection(value):
    require(isinstance(value, dict) and set(value) == {'server_id', 'user_id'}
            and all(type(v) is int and v > 0 for v in value.values()),
            'Select one exact existing server ID and owner ID')


def origin(value):
    require(isinstance(value, dict) and set(value) == {'host', 'port'}
            and isinstance(value['host'], str) and 0 < len(value['host']) <= 253
            and all(32 < ord(c) < 127 for c in value['host'])
            and type(value['port']) is int and 1 <= value['port'] <= 65534,
            'Bind the exact previously observed server host and port')


def destination(value):
    require(isinstance(value, dict) and set(value) == {'address', 'port'}
            and type(value['port']) is int and value['port'] == 5432,
            'Use the PostgreSQL endpoint from the shared network catalogue')
    try:
        require(isinstance(value['address'], str), 'Invalid destination')
        address = ipaddress.IPv4Address(value['address'])
        require(not (address.is_unspecified or address.is_loopback or address.is_link_local
                     or address.is_multicast or address.is_reserved), 'Invalid destination')
    except ValueError:
        raise ValueError('Use a direct PostgreSQL IPv4 destination') from None
    return {'host': str(address), 'port': value['port']}


def plan(connection, selector, before, target):
    """Read only endpoint/transport columns; never return profile or login data."""
    selection(selector); origin(before)
    after = destination(target)
    try:
        rows = connection.execute('SELECT host,port,service,use_ssh_tunnel,shared,connection_params '
            'FROM server WHERE id=? AND user_id=?', (selector['server_id'], selector['user_id'])).fetchall()
        require(len(rows) == 1, 'The selected server and owner do not identify one existing row')
        host, port, service, tunnel, shared, parameters = rows[0]
        require({'host': host, 'port': port} == before, 'The selected saved endpoint drifted')
        # The pinned image imports omitted flags as NULL; its driver treats
        # these exactly like disabled flags. Preserve that representation.
        require(not service and tunnel in (None, 0) and shared in (None, 0),
                'Review service, tunnel or shared-server transport separately')
        require(not connection.execute('SELECT 1 FROM sharedserver WHERE osid=? LIMIT 1',
                (selector['server_id'],)).fetchone(), 'Review dependent shared-server copies separately')
        require(not connection.execute("SELECT 1 FROM sqlite_schema WHERE type='trigger' AND tbl_name='server' LIMIT 1").fetchone(),
                'Review server update triggers separately')
        parameters = json.loads(parameters) if parameters is not None else {}
        if parameters is None:
            parameters = {}
        require(isinstance(parameters, dict) and not {'host', 'hostaddr', 'port', 'service'} & {
                k.lower() for k in parameters}, 'Review connection-parameter endpoint overrides separately')
    except (sqlite3.Error, json.JSONDecodeError, TypeError):
        raise ValueError('The pgAdmin profile schema or connection parameters require review') from None
    return {'selector': dict(selector), 'before': dict(before), 'after': after}


def apply(connection, proposal, *, validate_update=None):
    """One compare-and-set transaction on the caller's admitted SQLite connection.

    A stale/replayed proposal holds. This is an application adapter, not a CD
    entry point: the caller must already have excluded pgAdmin and other writers.
    """
    require(isinstance(proposal, dict) and set(proposal) == {'selector', 'before', 'after'},
            'Use only the reviewed saved-endpoint proposal')
    origin(proposal['after'])
    require(validate_update is None or callable(validate_update), 'Use a trusted update validator')
    require(not connection.in_transaction, 'Preserve the caller-owned transaction')
    try:
        connection.execute('BEGIN IMMEDIATE')
        selected = plan(connection, proposal['selector'], proposal['before'],
                        {'address': proposal['after']['host'], 'port': proposal['after']['port']})
        if selected['before'] == selected['after']:
            if validate_update is not None:
                validate_update(connection)
            connection.commit()
            return False
        changed = connection.execute('UPDATE server SET host=?,port=? WHERE id=? AND user_id=? AND host=? AND port=?',
            (selected['after']['host'], selected['after']['port'], selected['selector']['server_id'],
             selected['selector']['user_id'], selected['before']['host'], selected['before']['port']))
        require(changed.rowcount == 1, 'Saved-endpoint update did not select exactly one row')
        if validate_update is not None:
            validate_update(connection)
        connection.commit()
    except BaseException as error:
        connection.rollback()
        if isinstance(error, sqlite3.Error):
            raise ValueError('Saved-endpoint transaction held; preserve private evidence') from None
        raise
    return True
