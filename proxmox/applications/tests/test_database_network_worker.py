"""Cross-bind runtime changes to the exact saved network operation before stops."""
import copy
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_worker as worker
from test_database_network_server import contract


class Tests(unittest.TestCase):
    def setUp(self):
        self.catalogue = contract()
        self.request = {'engine': 'postgresql', 'phase': 'cutover', 'client_vmids': [211,202],
                        'legacy_server_address': '10.88.30.23'}
        self.context = {'request': self.request, 'catalogue_raw': json.dumps(self.catalogue).encode()}
        self.runtime = {'endpoint': {'address': '10.88.31.23', 'port': 5432},
                        'old_address': '10.88.30.23', 'clients': [dict(c) for c in sorted(
                            self.catalogue['networks']['postgresql']['clients'], key=lambda c:c['vmid'])
                            if c['vmid'] in (211,202)]}

    def bind(self, packet=None):
        worker.bind_runtime('postgresql', packet or self.runtime, self.context, Path('/adapter'), [211,202])

    def test_exact_server_endpoint_and_two_selected_clients_are_accepted(self):
        self.bind()

    def test_future_client_cannot_be_granted_by_a_valid_but_different_saved_plan(self):
        self.request['client_vmids'].append(213)
        with self.assertRaises(ValueError): self.bind()

    def test_wrong_runtime_new_or_old_endpoint_or_future_client_is_refused(self):
        for mutate in (lambda p:p['endpoint'].update(address='10.88.99.23'),
                       lambda p:p.update(old_address='10.88.30.24'),
                       lambda p:p['clients'].append(dict(vmid=213, address='10.88.31.27'))):
            value = copy.deepcopy(self.runtime); mutate(value)
            with self.assertRaises(ValueError): self.bind(value)

    def test_non_cutover_or_other_database_request_is_refused(self):
        for key, value in [('phase','additive'), ('engine','mariadb')]:
            with patch.dict(self.request, {key:value}), self.assertRaises(ValueError): self.bind()

    def test_client_owned_binding_guard_is_required_and_receives_exact_group(self):
        validator = Mock(return_value=True)
        module = types.SimpleNamespace(validate_binding=validator)
        with patch.object(worker.importlib, 'import_module', return_value=module):
            worker.bind_runtime('identity', {'private':'runtime'}, self.context, Path('/adapter'), [211,202])
        validator.assert_called_once_with({'private':'runtime'}, self.catalogue, [202,211], '10.88.30.23')
        validator.return_value = False
        with patch.object(worker.importlib, 'import_module', return_value=module), self.assertRaises(ValueError):
            worker.bind_runtime('identity', {}, self.context, Path('/adapter'), [211,202])


if __name__ == '__main__': unittest.main()
