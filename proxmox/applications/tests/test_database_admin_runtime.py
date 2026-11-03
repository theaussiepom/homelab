"""Offline helper controls: real private files; no Docker or native SQL calls."""
import base64
import copy
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest.mock import patch

FRAMEWORK = Path(os.environ.get('HOMELAB_FRAMEWORK', Path(__file__).resolve().parents[3]))
SOURCE = Path(os.environ.get('HOMELAB_DATABASE_ADMIN_HELPER', FRAMEWORK / 'proxmox/applications/database-admin-runtime.py'))


class RootStat:
    def __init__(self, value): self.value = value
    @property
    def st_uid(self): return 0
    def __getattr__(self, key): return getattr(self.value, key)


def verifier(password):
    salt = b'synthetic-fixture-salt'
    value = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 4096)
    stored = hashlib.sha256(hmac.digest(value, b'Client Key', 'sha256')).digest()
    server = hmac.digest(value, b'Server Key', 'sha256')
    encode = lambda x: base64.b64encode(x).decode()
    return 'SCRAM-SHA-256$4096:' + encode(salt) + '$' + encode(stored) + ':' + encode(server)


class FakeSQL:
    def __init__(self, helper, value):
        self.m, self.value, self.calls = helper, value, []
        self.row = None
        self.ssl = True
        self.fail_password = False
        self.fail_grant = False
        self.plugin = None
        source = value['account']['owner']['source_address']
        self.hba = [{'type': kind, 'database': ['all', 'replication'], 'user_name': [value['account']['username']], 'address': address, 'netmask': mask, 'method': method, 'options': None, 'error': None} for kind, address, mask, method in [('hostssl', source, '255.255.255.255', 'scram-sha-256'), ('local', None, None, 'reject'), ('host', '0.0.0.0', '0.0.0.0', 'reject'), ('host', '::', '::', 'reject')]]
    def __call__(self, argv, text):
        self.calls.append((list(argv), text))
        user = self.value['account']['username']
        source = self.value['account']['owner']['source_address']
        if 'setsid' in argv:
            if self.fail_password: raise RuntimeError('synthetic password failure')
            password = text.splitlines()
            assert len(password) == 2 and password[0] == password[1]
            self.row['password'] = verifier(password[0]); return ''
        if text == 'SHOW ssl;': return 'on' if self.ssl else 'off'
        if text.startswith('SELECT json_agg') and 'FROM pg_authid' in text: return json.dumps([self.row] if self.row else [])
        if text.startswith('SELECT json_agg') and 'pg_hba_file_rules' in text: return json.dumps(self.hba)
        if text.startswith('CREATE ROLE'):
            self.row = {'name': user, 'login': True, 'super': True, 'createdb': True, 'createrole': True, 'replication': True, 'bypassrls': True, 'password': '', 'connection_limit': -1, 'expires': None, 'memberships': 0}; return ''
        if text.startswith('SHOW GLOBAL VARIABLES'): return 'have_ssl\tYES' if self.ssl else 'have_ssl\tDISABLED'
        if 'FROM information_schema.PLUGINS' in text: return json.dumps(self.plugin) if self.plugin else ''
        if text == "INSTALL SONAME 'auth_parsec';":
            self.plugin={'name':'parsec','status':'ACTIVE','type':'AUTHENTICATION','library':'auth_parsec.so'};return ''
        if text.startswith('SELECT JSON_OBJECT'): return json.dumps(self.row) if self.row else ''
        if text.startswith('CREATE USER'):
            if self.fail_grant: raise RuntimeError('synthetic grant failure')
            stored=re.search(r"IDENTIFIED VIA parsec USING '([^']+)' REQUIRE SSL",text).group(1)
            self.row = {'name': user, 'host': source, 'plugin': 'parsec', 'password': stored, 'ssl': 'ANY'}; return ''
        if text.startswith('SHOW GRANTS'):
            return "GRANT ALL PRIVILEGES ON *.* TO `" + user + "`@`" + source + "` IDENTIFIED BY PASSWORD '<synthetic-verifier>' REQUIRE SSL WITH GRANT OPTION"
        raise AssertionError('Unexpected synthetic SQL boundary: ' + text[:100])
    def writes(self):
        return [(a, t) for a, t in self.calls if 'setsid' in a or t.startswith(('CREATE ROLE', 'CREATE USER', 'INSTALL SONAME'))]


class DatabaseAdminRuntimeTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('database_admin_runtime_fixture', SOURCE)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.m.ROOT = self.root / 'private'
        real_fstat, real_lstat = os.fstat, Path.lstat
        self.enterContext(patch.object(self.m.os, 'geteuid', return_value=0))
        self.enterContext(patch.object(self.m.os, 'fstat', side_effect=lambda fd: RootStat(real_fstat(fd))))
        self.enterContext(patch.object(Path, 'lstat', lambda value: RootStat(real_lstat(value))))
        def openssl(argv, **kwargs):
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            assert argv==['openssl','pkey','-inform','DER','-pubout','-outform','DER']
            data=kwargs['input'];prefix=bytes.fromhex('302e020100300506032b657004220420')
            assert data.startswith(prefix) and len(data)==len(prefix)+32
            key=Ed25519PrivateKey.from_private_bytes(data[len(prefix):]).public_key()
            return types.SimpleNamespace(stdout=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.enterContext(patch.object(self.m.subprocess,'run',side_effect=openssl))
    def value(self, engine='postgresql'):
        own = {'node': 'fixture-node', 'engine': engine, 'database_vmid': 501, 'source_vmid': 502, 'server_address': '198.18.31.23' if engine == 'postgresql' else '198.18.32.24', 'source_address': '198.18.31.32' if engine == 'postgresql' else '198.18.32.32', 'username': 'fixture_admin', 'purpose': 'database-administration'}
        return {'engine': engine, 'account': {'username': own['username'], 'source_guest': 'db-tools', 'credential_id': 'fixture-' + engine, 'credential_file': '/synthetic/managed-fixture-' + engine + '.json', 'access': 'server-administration', 'transport': 'tls', 'owner': own}, 'credential': {'schema': 'homelab-application-account-v1', 'owner': copy.deepcopy(own), 'password': 'ab' * 32}}
    def fake(self, value):
        sql = FakeSQL(self.m, value)
        self.enterContext(patch.object(self.m, 'run', side_effect=sql))
        return sql
    def receipt(self, value): return self.m.ROOT / (value['account']['credential_id'] + '.json')
    def hold(self, value): return self.m.ROOT / (value['account']['credential_id'] + '-HOLD.json')
    def test_pg_apply_preflight_and_idempotency_keep_password_on_stdin(self):
        value = self.value(); sql = self.fake(value)
        self.assertEqual(self.m.preflight(value), {'administrator_preflight': 'verified'})
        self.assertFalse(self.m.ROOT.exists())
        result = self.m.apply(value); before = self.receipt(value).read_bytes(); writes = len(sql.writes())
        self.assertEqual(result, {'administrator': 'verified', 'transport': 'tls', 'source_restricted': True})
        self.assertFalse(self.hold(value).exists())
        self.assertEqual(self.m.ROOT.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.receipt(value).stat().st_mode & 0o777, 0o600)
        self.assertNotIn(value['credential']['password'], before.decode())
        self.m.preflight(value); self.m.apply(value)
        self.assertEqual(before, self.receipt(value).read_bytes())
        self.assertEqual(len(sql.writes()), writes)
        password_calls = [(a, t) for a, t in sql.calls if 'setsid' in a]
        self.assertEqual(len(password_calls), 1)
        self.assertIn('\\password "fixture_admin"', password_calls[0][0])
        self.assertEqual(password_calls[0][1], value['credential']['password'] + '\n' + value['credential']['password'] + '\n')
        for argv, text in sql.calls:
            self.assertNotIn(value['credential']['password'], ' '.join(argv))
            if 'setsid' not in argv: self.assertNotIn(value['credential']['password'], text)
    def test_maria_apply_uses_only_native_verifier_in_sql_and_is_idempotent(self):
        value = self.value('mariadb'); sql = self.fake(value)
        self.m.preflight(value); self.m.apply(value); before = self.receipt(value).read_bytes(); writes = len(sql.writes())
        self.m.apply(value); self.m.preflight(value)
        self.assertEqual(len(sql.writes()), writes)
        self.assertEqual(self.receipt(value).read_bytes(), before)
        create = next(text for _, text in sql.calls if text.startswith('CREATE USER'))
        self.assertIn("'fixture_admin'@'198.18.32.32'", create)
        self.assertIn('REQUIRE SSL', create)
        self.assertIn('IDENTIFIED VIA parsec USING',create)
        self.assertEqual(sql.row['plugin'],'parsec')
        self.assertTrue(sql.row['password'].startswith('P3:'))
        self.assertEqual(sum(text=="INSTALL SONAME 'auth_parsec';" for _,text in sql.calls),1)
        self.assertIn('WITH GRANT OPTION', create)
        self.assertIn(self.m.parsec_verifier(value['credential']['password'], sql.row['password']), create)
        for argv, text in sql.calls:
            self.assertNotIn(value['credential']['password'], ' '.join(argv) + text)
    def test_shape_owner_sql_injection_and_nonprivate_sources_refuse_before_sql(self):
        baseline = self.value(); cases = []
        for key, bad in [('engine', ['postgresql']), ('engine', 'unknown')]:
            value = copy.deepcopy(baseline); value[key] = bad; cases.append(value)
        for key, bad in [('username', 'x";DROP ROLE postgres;--'), ('credential_id', '../wrong'), ('transport', 'plaintext'), ('access', 'owner-only')]:
            value = copy.deepcopy(baseline); value['account'][key] = bad; cases.append(value)
        for key, bad in [('source_address', '8.8.8.8'), ('server_address', '127.0.0.1'), ('source_vmid', True), ('engine', 'mariadb'), ('purpose', 'other')]:
            value = copy.deepcopy(baseline); value['account']['owner'][key] = bad; cases.append(value)
        value = copy.deepcopy(baseline); value['credential']['owner']['username'] = 'foreign'; cases.append(value)
        value = copy.deepcopy(baseline); value['credential']['password'] = 'not-a-declared-password'; cases.append(value)
        sql = self.fake(baseline)
        for value in cases:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                self.m.apply(value)
        self.assertEqual(sql.calls, [])
    def test_foreign_account_is_not_adopted_and_preflight_does_not_write(self):
        value = self.value(); sql = self.fake(value); sql.row = {'name': 'fixture_admin'}
        with self.assertRaises(ValueError): self.m.preflight(value)
        self.assertFalse(self.m.ROOT.exists())
        with self.assertRaises(ValueError): self.m.apply(value)
        self.assertFalse(self.receipt(value).exists())
        self.assertEqual(sql.writes(), [])
    def test_ssl_refusal_precedes_hold_and_account_creation(self):
        for engine in ('postgresql', 'mariadb'):
            value = self.value(engine)
            with patch.object(self.m, 'run', side_effect=FakeSQL(self.m, value)) as unused:
                sql = unused.side_effect; sql.ssl = False
                with self.subTest(engine=engine), self.assertRaises(ValueError): self.m.apply(value)
                self.assertFalse(self.hold(value).exists()); self.assertEqual(sql.writes(), [])
    def test_partial_failure_keeps_hold_and_blocks_retry_without_more_sql(self):
        for engine in ('postgresql', 'mariadb'):
            value = self.value(engine); sql = FakeSQL(self.m, value); sql.fail_password = True; sql.fail_grant = True
            with patch.object(self.m, 'run', side_effect=sql):
                with self.subTest(engine=engine), self.assertRaises(RuntimeError): self.m.apply(value)
                self.assertTrue(self.hold(value).is_file()); self.assertFalse(self.receipt(value).exists())
                before = len(sql.calls)
                with self.assertRaises(ValueError): self.m.preflight(value)
                with self.assertRaises(ValueError): self.m.apply(value)
                self.assertEqual(len(sql.calls), before)
    def test_receipt_drift_mode_symlink_and_hardlink_refuse(self):
        value = self.value(); self.fake(value); self.m.apply(value); receipt = self.receipt(value); original = receipt.read_bytes()
        receipt.chmod(0o644)
        with self.assertRaises(ValueError): self.m.apply(value)
        receipt.chmod(0o600)
        changed = copy.deepcopy(value); changed['credential']['password'] = 'cd' * 32
        with self.assertRaises(ValueError): self.m.apply(changed)
        receipt.unlink(); outside = self.root / 'other.json'; outside.write_bytes(original); outside.chmod(0o600); receipt.symlink_to(outside)
        with self.assertRaises(OSError): self.m.apply(value)
        receipt.unlink(); receipt.write_bytes(original); receipt.chmod(0o600); os.link(receipt, self.root / 'hardlink')
        with self.assertRaises(ValueError): self.m.apply(value)
    def test_hba_replication_source_database_and_row_order_are_strict(self):
        value = self.value(); sql = self.fake(value); self.m.apply(value)
        original = copy.deepcopy(sql.hba)
        variants = []
        for key, bad in [('database', ['all']), ('address', '198.18.31.99'), ('method', 'trust'), ('options', []), ('error', 'parse-error')]:
            rows = copy.deepcopy(original); rows[0][key] = bad; variants.append(rows)
        variants += [original[:-1], list(reversed(original)), original + original[:1]]
        for rows in variants:
            sql.hba = rows
            with self.subTest(rows=rows), self.assertRaises(ValueError): self.m.apply(value)
    def test_password_verifier_and_privilege_drift_are_not_repaired(self):
        value = self.value(); sql = self.fake(value); self.m.apply(value); writes = len(sql.writes())
        for field, bad in [('super', False), ('replication', False), ('memberships', 1), ('expires', 'tomorrow'), ('password', verifier('wrong-password'))]:
            old = sql.row[field]; sql.row[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError): self.m.apply(value)
            sql.row[field] = old
        self.assertEqual(len(sql.writes()), writes)
    def test_scram_bounds_and_both_keys_are_verified(self):
        good = verifier('fixture-password'); self.m.scram('fixture-password', good)
        for bad in [None, 'md5bad', good.replace('$4096:', '$1:'), good.replace('$4096:', '$1000001:'), good[:-1] + '!']:
            with self.subTest(verifier=bad), self.assertRaises((ValueError, TypeError)):
                self.m.scram('fixture-password', bad)
        with self.assertRaises(ValueError): self.m.scram('different-password', good)
    def test_main_bounds_input_and_returns_fixed_safe_failure(self):
        for payload in [b'x' * (1024 * 1024 + 1), b'{not-json', b'{}']:
            with patch('sys.stdin', types.SimpleNamespace(buffer=io.BytesIO(payload))), patch('sys.argv', ['helper']), self.assertRaisesRegex(SystemExit, '^Database administrator deployment held; inspect privately\\.$'):
                self.m.main()

    def test_process_boundary_and_successful_cli_keep_password_off_argv(self):
        with patch.object(self.m.subprocess,'run',return_value=types.SimpleNamespace(stdout=' safe\n')) as process:
            self.assertEqual(self.m.run(['psql','fixture'],'synthetic-secret'),'safe')
        self.assertNotIn('synthetic-secret',repr(process.call_args.args))
        self.assertEqual(process.call_args.kwargs['input'],'synthetic-secret')
        with patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(b'{}'))),patch('sys.argv',['helper','--preflight']), \
                patch.object(self.m,'preflight',return_value={'database_administrator':'preflight'}) as preflight, \
                patch('sys.stdout',new_callable=io.StringIO) as output:
            self.m.main()
        preflight.assert_called_once_with({})
        self.assertEqual(json.loads(output.getvalue()),{'database_administrator':'preflight'})
        import runpy
        with patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(b'{}'))),patch('sys.argv',['helper']),self.assertRaises(SystemExit):
            runpy.run_path(str(SOURCE),run_name='__main__')

    def test_custody_fingerprint_uses_owner_bound_PBKDF2_not_native_authentication(self):
        value=self.value();owner=value['account']['owner'];password=value['credential']['password']
        first=self.m.fingerprint(password,owner)
        self.assertEqual(first,self.m.fingerprint(password,dict(reversed(list(owner.items())))))
        self.assertNotEqual(first,self.m.fingerprint(password,dict(owner,source_vmid=12002)))
        self.assertEqual(len(first),64)
        self.fake(value);self.m.apply(value)
        receipt=self.m.private(self.m.ROOT/(value['account']['credential_id']+'.json'))
        self.assertEqual(receipt['credential_fingerprint'],first)
        self.assertNotIn('password_sha256',receipt)

    def test_parsec_reuses_only_exact_active_vendor_plugin_without_reinstall_or_legacy_fallback(self):
        value=self.value('mariadb');sql=self.fake(value)
        sql.plugin={'name':'parsec','status':'ACTIVE','type':'AUTHENTICATION','library':'auth_parsec.so'}
        self.m.preflight(value);self.m.apply(value)
        self.assertFalse(any(text.startswith('INSTALL')for _,text in sql.calls))
        self.assertTrue(all('mysql_native_password'not in text for _,text in sql.calls))
        before=len(sql.writes())
        for key,bad in [('status','DISABLED'),('type','DAEMON'),('library','foreign.so'),('name','other')]:
            original=sql.plugin[key];sql.plugin[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.m.preflight(value)
            sql.plugin[key]=original
        self.assertEqual(len(sql.writes()),before)

    def test_parsec_format_uses_fresh_salt_exact_native_P3_and_stock_key_stdin(self):
        password='cd'*32;salt=b'fixtureparsecsalt1'
        self.assertEqual(len(salt),18)
        real=self.m.hashlib.pbkdf2_hmac
        with patch.object(self.m.os,'urandom',return_value=salt),patch.object(self.m.hashlib,'pbkdf2_hmac',wraps=real) as kdf:
            stored=self.m.parsec_verifier(password)
        self.assertTrue(stored.startswith('P3:'+base64.b64encode(salt).decode()+':'))
        self.assertEqual(len(stored),71)
        kdf.assert_called_once_with('sha512',password.encode(),salt,8192,dklen=32)
        self.assertEqual(self.m.parsec_verifier(password,stored),stored)
        self.assertNotEqual(self.m.parsec_verifier('ef'*32,stored),stored)
        self.assertNotEqual(self.m.parsec_verifier(password),stored)
        for bad in ('P0'+stored[2:],'P4'+stored[2:],'native-sha1',stored+'=',[],stored[:-1]):
            with self.subTest(stored=bad),self.assertRaises(ValueError):self.m.parsec_verifier(password,bad)
        with patch.object(self.m.subprocess,'run',return_value=types.SimpleNamespace(stdout=b'foreign DER')):
            with self.assertRaises(ValueError):self.m.parsec_verifier(password)


if __name__ == '__main__':
    unittest.main(verbosity=2)
