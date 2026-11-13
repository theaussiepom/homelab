"""Management selection owns its own finite schema and secret boundary."""
import copy
from types import SimpleNamespace
import unittest

import component_backup_management as subject
from component_errors import ComponentError


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.value = {'credential': 'pbs-management', 'datastore_path': '/mnt/backup/recovery'}
        self.resolver = SimpleNamespace(site={'secret_sources': {
            'pbs-management': {'type': 'environment', 'name': 'PBS_API_TOKEN'}}})

    def test_environment_reference_is_resolved_without_loading_a_value(self):
        expected = copy.deepcopy(self.value)
        result = subject.bind(self.resolver, self.value)
        self.assertEqual(result['datastore_path'], '/mnt/backup/recovery')
        self.assertEqual(result['credential'], {'type': 'environment', 'name': 'PBS_API_TOKEN'})
        result['credential']['name'] = 'edited'
        self.assertEqual(self.value, expected)
        self.assertEqual(self.resolver.site['secret_sources']['pbs-management']['name'], 'PBS_API_TOKEN')

    def test_wrong_missing_and_unknown_fields_refuse(self):
        for value in (None, [], {}, {'credential': 'pbs-management'},
                dict(self.value, extra=True), dict(self.value, credential='/private/value'),
                dict(self.value, datastore_path='/'), dict(self.value, datastore_path='relative'),
                dict(self.value, datastore_path='/mnt/../other')):
            with self.subTest(value=value), self.assertRaises(ComponentError): subject.source(value)

    def test_only_named_environment_management_credential_is_forwarded(self):
        for value in (None, {}, {'type': 'file', 'path': '/never-read/secret'},
                {'type': 'environment', 'name': 'OTHER'},
                {'type': 'environment', 'name': 'PBS_API_TOKEN', 'workflow_secret': 'OTHER'}):
            self.resolver.site['secret_sources']['pbs-management'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ComponentError, 'backup-management-credential'):
                subject.bind(self.resolver, self.value)
        self.resolver.site['secret_sources'].clear()
        with self.assertRaisesRegex(ComponentError, 'backup-management-credential'):
            subject.bind(self.resolver, self.value)


if __name__ == '__main__': unittest.main()
