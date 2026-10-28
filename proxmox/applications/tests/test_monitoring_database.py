import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_database as database


class MonitoringDatabaseTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'listxattr'), 'Native HBA metadata uses Linux xattrs')
    def test_rejected_hba_or_failed_reload_restores_original_and_keeps_hold(self):
        for failure in ('parser', 'reload'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); hba = root / 'pg_hba.conf'; original = b'local all postgres peer\n'; hba.write_bytes(original)
                def query(statement):
                    if 'pg_roles' in statement or 'pg_database' in statement: return '0'
                    if 'pg_hba_file_rules' in statement: return '1' if failure == 'parser' else '0'
                    if 'pg_reload_conf' in statement: return 'f'
                    return ''
                with patch.object(database, 'sql', side_effect=query), patch.object(database.subprocess, 'run', return_value=SimpleNamespace(stdout=b'-- synthetic globals')):
                    with self.assertRaises(ValueError):
                        database.provision(root / 'state', hba, hashlib.sha256(original).hexdigest(), '198.18.30.50', 'a' * 32)
                self.assertEqual(hba.read_bytes(), original)
                self.assertTrue((root / 'state/HOLD.json').exists())
                self.assertTrue((root / 'state/pg_hba.rejected').exists())
                self.assertFalse((root / 'state/READY.json').exists())

    def test_specific_allowance_precedes_role_rejects_and_preserves_original(self):
        original = b'local all postgres peer\nhost all all 198.18.30.0/24 scram-sha-256\n'
        result = database.hba_content(original, '198.18.30.50')
        self.assertTrue(result.endswith(original))
        self.assertLess(result.index(b'host zabbix zabbix'), result.index(b'host all zabbix 0.0.0.0/0 reject'))
        self.assertIn(b'local all zabbix reject', result)
        for address in ['0.0.0.0', '127.0.0.1', '::', 'invalid']:
            with self.subTest(address=address), self.assertRaises(ValueError): database.hba_content(original, address)

    def test_changed_baseline_existing_role_and_hold_prevent_mutation(self):
        for scenario in ['baseline', 'existing', 'held', 'injection']:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); hba = root / 'pg_hba.conf'; hba.write_text('local all postgres peer\n')
                state = root / 'state'; state.mkdir(mode=0o700)
                expected = hashlib.sha256(hba.read_bytes()).hexdigest()
                password = 'a' * 32
                if scenario == 'baseline': expected = '0' * 64
                if scenario == 'held': (state / 'HOLD.json').write_text('{}')
                if scenario == 'injection': password += "';DROP ROLE x;--"
                with patch.object(database, 'sql', return_value='1') as sql:
                    with self.assertRaises(ValueError):
                        database.provision(state, hba, expected, '198.18.30.50', password)
                    self.assertFalse(any('CREATE' in call.args[0] for call in sql.call_args_list))
                self.assertEqual(hba.read_text(), 'local all postgres peer\n')
