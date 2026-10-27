"""Only the declared resolver change and its four DNS rules may be applied."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ingress_acme as acme


class AcmeTests(unittest.TestCase):
    def test_candidate_preserves_tokens_provider_routes_and_propagation(self):
        value = {'providers': {'plugin': {'token': 'synthetic-private'}},
                 'certificatesResolvers': {'letsencrypt': {'acme': {
                     'email': 'operator@example.invalid', 'storage': '/private/acme.json',
                     'dnsChallenge': {'provider': 'cloudflare', 'resolvers': ['198.18.40.2:53'],
                                      'propagation': {'disableANSChecks': True, 'requireAllRNS': True}}}}}}
        original = json.dumps(value).encode()
        result = json.loads(acme.candidate(original, ['198.18.40.2:53'], ['1.1.1.1:53', '1.0.0.1:53']))
        expected = copy.deepcopy(value)
        expected['certificatesResolvers']['letsencrypt']['acme']['dnsChallenge']['resolvers'] = ['1.1.1.1:53', '1.0.0.1:53']
        self.assertEqual(result, expected)
        self.assertEqual(json.loads(original), value)
        with self.assertRaises(ValueError):
            acme.candidate(original, ['198.18.40.3:53'], ['1.1.1.1:53'])

    def fixture(self):
        rows = []
        for address, field in acme.RESOURCES.items():
            before = {field: 712, 'node_name': 'test-pve'}
            if address == acme.RULES:
                before['rule'] = [{'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'dport': '22'}]
            after = copy.deepcopy(before)
            if address == acme.RULES:
                after['rule'] += acme.provider_rules(['1.1.1.1:53', '1.0.0.1:53'])
            rows.append({'address': address, 'change': {'actions': ['update'] if before != after else ['no-op'],
                                                       'before': before, 'after': after}})
        return {'resource_changes': rows}

    def test_saved_plan_allows_only_the_declared_dns_egress_append(self):
        value = self.fixture()
        acme.check_plan(value, 'test-pve', 712, ['1.1.1.1:53', '1.0.0.1:53'])
        for mutate in (
            lambda v: v['resource_changes'][0]['change'].update(actions=['update']),
            lambda v: v['resource_changes'][0]['change']['after'].update(protection=False),
            lambda v: v['resource_changes'][-1]['change']['after']['rule'].pop(0),
            lambda v: v['resource_changes'][-1]['change']['after']['rule'][-1].update(dest='0.0.0.0/0'),
            lambda v: v['resource_changes'][-1]['change']['after']['rule'][-1].update(dport='53,8006'),
            lambda v: v['resource_changes'][-1]['change']['after']['rule'][-1].update(iface='eth0'),
            lambda v: v['resource_changes'][-1]['change']['after'].update(container_id=713),
            lambda v: v['resource_changes'][-1]['change'].update(after_unknown={'rule':[{'dest':True}]}),
        ):
            bad = self.fixture(); mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                acme.check_plan(bad, 'test-pve', 712, ['1.1.1.1:53', '1.0.0.1:53'])

    def test_provider_default_fields_do_not_expand_rule_authority(self):
        value = self.fixture()
        for row in value['resource_changes'][-1]['change']['after']['rule'][-4:]:
            row.update(enabled=True, source=None, iface=None, sport=None, log='nolog')
        acme.check_plan(value, 'test-pve', 712, ['1.1.1.1:53', '1.0.0.1:53'])

    def test_completed_operation_requires_a_zero_change_plan(self):
        value = self.fixture()
        with self.assertRaises(ValueError):
            acme.check_plan(value, 'test-pve', 712, ['1.1.1.1:53', '1.0.0.1:53'], True)
        for row in value['resource_changes']:
            row['change']['before'] = copy.deepcopy(row['change']['after'])
            row['change']['actions'] = ['no-op']
        acme.check_plan(value, 'test-pve', 712, ['1.1.1.1:53', '1.0.0.1:53'], True)


if __name__ == '__main__':
    unittest.main()
