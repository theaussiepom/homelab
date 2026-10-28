"""Registration replacement, with synthetic settings and no credential exports."""
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pgadmin_endpoint as endpoint
from test_pgadmin_endpoint import profile, AFTER, BEFORE

SELECTOR={'server_id':8,'user_id':2}


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.connection=profile();self.addCleanup(self.connection.close)
        self.connection.executescript('''CREATE TABLE query_history(uid INTEGER,sid INTEGER,query_info BLOB);
            INSERT INTO query_history VALUES(1,7,X'102030'),(2,8,X'405060');''')

    def proposal(self):
        return endpoint.replacement_plan(self.connection,SELECTOR,BEFORE,AFTER)

    def test_replace_all_uses_fresh_identity_and_retains_user2_settings(self):
        old=self.connection.execute('SELECT * FROM server WHERE id=8').fetchone()
        users=self.connection.execute('SELECT * FROM user').fetchall()
        plan=self.proposal()
        self.assertEqual(plan['created_server_id'],9)
        endpoint.replacement_apply(self.connection,plan)
        rows=self.connection.execute('SELECT * FROM server').fetchall()
        expected=list(old);expected[0]=9;expected[2]='PostgreSQL';expected[3]=AFTER['address']
        self.assertEqual(rows,[tuple(expected)])
        self.assertEqual(self.connection.execute('SELECT * FROM user').fetchall(),users)
        self.assertEqual(self.connection.execute('SELECT * FROM query_history').fetchall(),[])
        self.assertEqual(self.connection.execute('SELECT value FROM setting').fetchone()[0],'retained')

    def test_added_or_changed_registration_holds_before_any_deletion(self):
        plan=self.proposal()
        self.connection.execute("UPDATE server SET host='changed' WHERE id=7");self.connection.commit()
        before='\n'.join(self.connection.iterdump())
        with self.assertRaises(ValueError): endpoint.replacement_apply(self.connection,plan)
        self.assertEqual('\n'.join(self.connection.iterdump()),before)

    def test_fresh_identity_does_not_reuse_a_previously_deleted_autoincrement_id(self):
        schema=self.connection.execute("SELECT sql FROM sqlite_schema WHERE name='server'").fetchone()[0]
        self.connection.executescript('ALTER TABLE server RENAME TO old_server;'+
            schema.replace('id INTEGER PRIMARY KEY','id INTEGER PRIMARY KEY AUTOINCREMENT')+
            '; INSERT INTO server SELECT * FROM old_server; DROP TABLE old_server;'+
            "UPDATE sqlite_sequence SET seq=20 WHERE name='server';")
        plan=self.proposal()
        self.assertEqual(plan['created_server_id'],21)
        endpoint.replacement_apply(self.connection,plan)
        self.assertEqual(self.connection.execute('SELECT id FROM server').fetchall(),[(21,)])

    def test_owner_auth_source_is_explicit_and_must_remain_oauth2(self):
        plan=self.proposal();self.assertEqual(plan['owner_auth_source'],'oauth2')
        self.connection.execute("UPDATE user SET auth_source='internal' WHERE id=2");self.connection.commit()
        with self.assertRaises(ValueError): endpoint.replacement_apply(self.connection,plan)

    def test_profile_scope_guard_rolls_back_deletes_and_insert(self):
        plan=self.proposal();before='\n'.join(self.connection.iterdump())
        def refuse(connection): raise ValueError('protected profile changed')
        with self.assertRaises(ValueError): endpoint.replacement_apply(self.connection,plan,validate_update=refuse)
        self.assertEqual('\n'.join(self.connection.iterdump()),before)

    def test_replay_cannot_delete_the_replacement(self):
        plan=self.proposal();endpoint.replacement_apply(self.connection,plan)
        before='\n'.join(self.connection.iterdump())
        with self.assertRaises(ValueError): endpoint.replacement_apply(self.connection,plan)
        self.assertEqual('\n'.join(self.connection.iterdump()),before)

    def test_shared_and_other_foreign_key_dependencies_hold(self):
        self.connection.execute('INSERT INTO sharedserver VALUES(1,7,2)');self.connection.commit()
        with self.assertRaises(ValueError): self.proposal()
        self.connection.execute('DELETE FROM sharedserver')
        self.connection.executescript('CREATE TABLE process(server_id INTEGER REFERENCES server(id)); INSERT INTO process VALUES(7);')
        with self.assertRaises(ValueError): self.proposal()

    def test_unknown_fields_and_registration_triggers_hold(self):
        plan=self.proposal();plan['command']='ignored'
        with self.assertRaises(ValueError): endpoint.replacement_apply(self.connection,plan)
        self.connection.executescript('CREATE TRIGGER unexpected AFTER DELETE ON server BEGIN DELETE FROM user; END;')
        with self.assertRaises(ValueError): self.proposal()


if __name__=='__main__': unittest.main()
