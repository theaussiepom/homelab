"""Existing pgAdmin server-row adapter for the shared maintenance controller.

No files, services, networks, receipts or credentials are opened or managed here.
The caller owns guest admission, an offline backup, writer quiescence, source and
packet binding, and the SQLite connection. Only server.host/port may be updated.
"""
import ipaddress
import json
import sqlite3


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


def apply(connection, proposal):
    """One compare-and-set transaction on the caller's admitted SQLite connection.

    A stale/replayed proposal holds. This is an application adapter, not a CD
    entry point: the caller must already have excluded pgAdmin and other writers.
    """
    require(isinstance(proposal, dict) and set(proposal) == {'selector', 'before', 'after'},
            'Use only the reviewed saved-endpoint proposal')
    origin(proposal['after'])
    require(not connection.in_transaction, 'Preserve the caller-owned transaction')
    try:
        connection.execute('BEGIN IMMEDIATE')
        selected = plan(connection, proposal['selector'], proposal['before'],
                        {'address': proposal['after']['host'], 'port': proposal['after']['port']})
        if selected['before'] == selected['after']:
            connection.commit()
            return False
        changed = connection.execute('UPDATE server SET host=?,port=? WHERE id=? AND user_id=? AND host=? AND port=?',
            (selected['after']['host'], selected['after']['port'], selected['selector']['server_id'],
             selected['selector']['user_id'], selected['before']['host'], selected['before']['port']))
        require(changed.rowcount == 1, 'Saved-endpoint update did not select exactly one row')
        connection.commit()
    except BaseException as error:
        connection.rollback()
        if isinstance(error, sqlite3.Error):
            raise ValueError('Saved-endpoint transaction held; preserve private evidence') from None
        raise
    return True
