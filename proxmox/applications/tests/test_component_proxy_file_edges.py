"""Conditional file capabilities are selected independently, without private reads."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_component_proxy_files import cloud, managed, zabbix, m, monitoring


class ConditionalProxyFileTests(unittest.TestCase):
    def test_postgresql_only_managed_cloud_omits_the_unselected_mariadb_driver(self):
        app=cloud();records=managed(app)
        del app['settings']['managed_connections']['mariadb-admin']
        del app['settings']['mariadb_jdbc'];del records['fixture-mariadb']
        with patch.object(m,'_public_source',return_value='source\n'):
            rows=m.files(app,secrets={'client_secret':b'fixture-oauth-input-for-pg-only'*2},records=records,public_ca=None)
        public=json.loads(next(row['content'] for row in rows if row['path']=='cloudbeaver-public.json'))
        self.assertNotIn('mariadb_jdbc',public)
        self.assertIn('CloudBeaverDatabaseHealth.java',{row['path'] for row in rows})
        native=json.loads(next(row['content'] for row in rows if row['path']=='cloudbeaver-admin-connections.json'))
        self.assertEqual(set(native['connections']),{'postgresql-admin'})

    def test_selected_saml_trust_with_normal_entry_never_loads_the_login_override(self):
        app=zabbix();app['authentication_resolved']={'default_login':'zabbix'}
        ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'
        with patch.object(monitoring,'saml_settings',return_value={}) as validate, \
             patch.object(m,'_public_source',side_effect=AssertionError('unselected public asset')):
            rows=m.files(app,secrets={'database_password':b'fixture\n'},records={},public_ca=ca)
        validate.assert_called_once_with(app['authentication_resolved'])
        self.assertEqual([row['path'] for row in rows],['database-password','proxmox-ca.pem'])


if __name__=='__main__':unittest.main()
