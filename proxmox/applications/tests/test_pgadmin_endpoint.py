"""One existing profile row changes; lifecycle and receipt custody belong to CD."""
import copy
import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pgadmin_endpoint as endpoint


def profile():
    connection = sqlite3.connect(':memory:')
    connection.executescript('''
        CREATE TABLE user (id INTEGER PRIMARY KEY, email TEXT, password BLOB, auth_source TEXT);
        INSERT INTO user VALUES (1,'one@example.invalid',X'010203','oauth2'),
                                (2,'two@example.invalid',X'040506','oauth2');
        CREATE TABLE server (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT,
            host TEXT, port INTEGER, username TEXT, password BLOB, maintenance_db TEXT,
            service TEXT, use_ssh_tunnel INTEGER, shared INTEGER, connection_params TEXT);
        INSERT INTO server VALUES (7,1,'Existing PostgreSQL','198.18.30.23',5432,
            'retained-role',X'070809','retained-db','',0,0,'{"sslmode":"prefer"}');
        INSERT INTO server SELECT 8,2,name,host,port,username,password,maintenance_db,
            service,use_ssh_tunnel,shared,connection_params FROM server WHERE id=7;
        CREATE TABLE sharedserver (id INTEGER PRIMARY KEY, osid INTEGER, user_id INTEGER);
        CREATE TABLE setting (user_id INTEGER, setting TEXT, value TEXT);
        INSERT INTO setting VALUES (1,'synthetic preference','retained');
    ''')
    return connection


SELECTOR = {'server_id': 7, 'user_id': 1}
BEFORE = {'host': '198.18.30.23', 'port': 5432}
AFTER = {'address': '198.18.31.23', 'port': 5432}  # database_networks.endpoint() shape


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.connection = profile()
        self.addCleanup(self.connection.close)

    def test_only_one_selected_rows_host_and_port_change(self):
        before = '\n'.join(self.connection.iterdump())
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        self.assertEqual('\n'.join(self.connection.iterdump()), before)
        self.assertEqual(proposal, {'selector': SELECTOR, 'before': BEFORE,
            'after': {'host': AFTER['address'], 'port': AFTER['port']}})
        self.assertTrue(endpoint.apply(self.connection, proposal))
        expected = before.replace("'Existing PostgreSQL','198.18.30.23'", "'Existing PostgreSQL','198.18.31.23'", 1)
        self.assertEqual('\n'.join(self.connection.iterdump()), expected)
        self.assertFalse(self.connection.in_transaction)

    def test_replay_or_stale_endpoint_is_held_without_another_write(self):
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        endpoint.apply(self.connection, proposal)
        before = '\n'.join(self.connection.iterdump())
        with self.assertRaises(ValueError): endpoint.apply(self.connection, proposal)
        self.assertEqual('\n'.join(self.connection.iterdump()), before)

    def test_missing_or_wrong_user_selection_is_not_inferred_from_a_server_name(self):
        for selected in ({'server_id': 7, 'user_id': 2}, {'server_id': 999, 'user_id': 1}):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                endpoint.plan(self.connection, selected, BEFORE, AFTER)

    def test_service_tunnel_shared_and_connection_parameter_overrides_hold(self):
        changes = [('service', 'existing-service'), ('use_ssh_tunnel', 1), ('shared', 1)]
        changes += [('connection_params', json.dumps({key: '198.18.0.99'}))
                    for key in ('host', 'hostaddr', 'port', 'service')]
        changes += [('connection_params', '[]'), ('connection_params', 'invalid-json')]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                connection = profile()
                try:
                    connection.execute(f'UPDATE server SET {key}=? WHERE id=7', (value,))
                    connection.commit()
                    before = '\n'.join(connection.iterdump())
                    with self.assertRaises(ValueError): endpoint.plan(connection, SELECTOR, BEFORE, AFTER)
                    self.assertEqual('\n'.join(connection.iterdump()), before)
                finally:
                    connection.close()

    def test_shared_shadow_rows_require_separate_review(self):
        self.connection.execute('INSERT INTO sharedserver VALUES (1,7,2)')
        self.connection.commit()
        with self.assertRaises(ValueError): endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)

    def test_pinned_image_null_disabled_flags_are_preserved(self):
        for parameters in (None, 'null'):
            with self.subTest(parameters=parameters):
                self.connection.execute('UPDATE server SET service=NULL,use_ssh_tunnel=NULL,shared=NULL,connection_params=? WHERE id=7', (parameters,))
                self.connection.commit()
                proposal = endpoint.plan(self.connection, SELECTOR,
                    {'host': self.connection.execute('SELECT host FROM server WHERE id=7').fetchone()[0], 'port':5432}, AFTER)
                endpoint.apply(self.connection, proposal)
                self.assertEqual(self.connection.execute('SELECT service,use_ssh_tunnel,shared,connection_params FROM server WHERE id=7').fetchone(),
                    (None, None, None, parameters))

    def test_rechecks_the_selected_row_under_the_write_transaction(self):
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        self.connection.execute("UPDATE server SET service='changed-after-plan' WHERE id=7")
        self.connection.commit()
        with self.assertRaises(ValueError): endpoint.apply(self.connection, proposal)
        self.assertEqual(self.connection.execute('SELECT host FROM server WHERE id=7').fetchone()[0], BEFORE['host'])

    def test_an_existing_transaction_is_not_committed_or_rolled_back(self):
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        self.connection.execute("UPDATE setting SET value='caller-owned-uncommitted'")
        with self.assertRaises(ValueError): endpoint.apply(self.connection, proposal)
        self.assertTrue(self.connection.in_transaction)
        self.connection.rollback()
        self.assertEqual(self.connection.execute('SELECT value FROM setting').fetchone()[0], 'retained')

    def test_triggers_cannot_expand_the_write_scope(self):
        self.connection.executescript('''CREATE TRIGGER unexpected AFTER UPDATE ON server
            BEGIN UPDATE user SET password=X'0000'; END;''')
        with self.assertRaises(ValueError): endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)

    def test_sql_failure_rolls_back_the_transaction(self):
        self.connection.executescript('''UPDATE server SET host='198.18.31.23' WHERE id=8;
            CREATE UNIQUE INDEX endpoint_unique ON server(host,port);''')
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        before = '\n'.join(self.connection.iterdump())
        with self.assertRaisesRegex(ValueError, 'transaction held'):
            endpoint.apply(self.connection, proposal)
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual('\n'.join(self.connection.iterdump()), before)

    def test_unknown_fields_and_bool_ids_cannot_expand_the_proposal(self):
        for selected in ({'server_id': True, 'user_id': 1}, dict(SELECTOR, table='user')):
            with self.assertRaises(ValueError): endpoint.plan(self.connection, selected, BEFORE, AFTER)
        proposal = endpoint.plan(self.connection, SELECTOR, BEFORE, AFTER)
        bad = copy.deepcopy(proposal); bad['after']['password'] = 'replacement'
        with self.assertRaises(ValueError): endpoint.apply(self.connection, bad)

    def test_destination_is_a_direct_postgresql_ipv4_endpoint(self):
        for address, port in [('0.0.0.0', 5432), ('127.0.0.1', 5432), ('db.invalid', 5432),
                              ('198.18.31.23', 3306), ('198.18.31.23', True)]:
            with self.subTest(address=address, port=port), self.assertRaises(ValueError):
                endpoint.plan(self.connection, SELECTOR, BEFORE, {'address': address, 'port': port})

    def test_incompatible_schema_has_a_non_secret_failure(self):
        connection = sqlite3.connect(':memory:')
        try:
            with self.assertRaisesRegex(ValueError, 'schema'):
                endpoint.plan(connection, SELECTOR, BEFORE, AFTER)
        finally:
            connection.close()


if __name__ == '__main__':
    unittest.main()
