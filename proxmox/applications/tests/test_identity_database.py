"""A commissioned Authentik update changes only its two PostgreSQL endpoints."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_database as identity


BEFORE = {'address': '10.88.30.23', 'port': 5432}
AFTER = {'address': '10.88.31.23', 'port': 5432}


def fixture():
    service = {'image': 'example.invalid/authentik@sha256:' + '1' * 64,
               'user': '1000', 'restart': 'unless-stopped',
               'environment': {'AUTHENTIK_POSTGRESQL__HOST': BEFORE['address'],
                   'AUTHENTIK_POSTGRESQL__USER': 'existing-authentik-role',
                   'AUTHENTIK_POSTGRESQL__NAME': 'existing-authentik-db',
                   'AUTHENTIK_POSTGRESQL__PASSWORD': 'file:///run/secrets/postgresql-password',
                   'AUTHENTIK_SECRET_KEY': 'file:///run/secrets/authentik-secret-key',
                   'AUTHENTIK_REDIS__HOST': 'redis',
                   'AUTHENTIK_EMAIL__HOST': 'smtp.example.invalid',
                   'AUTHENTIK_EMAIL__USE_TLS': 'true'},
               'volumes': ['/srv/homelab/data/authentik/media:/media',
                           '/srv/homelab/data/authentik/templates:/templates',
                           {'type': 'bind', 'source': '/opt/homelab-app/runtime/postgresql-password',
                            'target': '/run/secrets/postgresql-password', 'read_only': True}],
               'depends_on': {'redis': {'condition': 'service_healthy'}}}
    server, worker = copy.deepcopy(service), copy.deepcopy(service)
    server.update(command='server', ports=['10.88.30.20:9000:9000'])
    worker.update(command='worker')
    worker['volumes'].append('/srv/homelab/data/authentik/certs:/certs')
    return {'name': 'homelab-identity', 'services': {'server': server, 'worker': worker,
        'redis': {'image': 'example.invalid/redis@sha256:' + '2' * 64,
                  'command': ['--save', '60', '1'], 'restart': 'unless-stopped',
                  'volumes': ['/srv/homelab/data/redis:/data'],
                  'healthcheck': {'test': ['CMD-SHELL', 'redis-cli ping | grep -qx PONG']}}}}


class IdentityDatabaseTests(unittest.TestCase):
    def test_both_modes_change_endpoint_and_every_other_field_is_preserved(self):
        original = fixture()
        encoded = json.dumps(original).encode()
        result = json.loads(identity.candidate(encoded, BEFORE, AFTER))
        expected = copy.deepcopy(original)
        for name in ('server', 'worker'):
            expected['services'][name]['environment'].update(
                AUTHENTIK_POSTGRESQL__HOST=AFTER['address'], AUTHENTIK_POSTGRESQL__PORT=str(AFTER['port']))
        self.assertEqual(result, expected)
        self.assertEqual(json.loads(encoded), original)
        self.assertEqual(result['services']['redis'], original['services']['redis'])
        self.assertEqual(result['services']['server']['ports'], ['10.88.30.20:9000:9000'])

    def test_explicit_original_port_is_bound_before_changing_it(self):
        original = fixture()
        before = dict(BEFORE, port=5544)
        after = dict(AFTER, port=5443)
        for mode in ('server', 'worker'):
            original['services'][mode]['environment']['AUTHENTIK_POSTGRESQL__PORT'] = '5544'
        result = json.loads(identity.candidate(json.dumps(original).encode(), before, after))
        for mode in ('server', 'worker'):
            self.assertEqual(result['services'][mode]['environment']['AUTHENTIK_POSTGRESQL__PORT'], '5443')
        with self.assertRaises(ValueError):
            identity.candidate(json.dumps(fixture()).encode(), before, AFTER)

    def test_partial_or_drifted_endpoint_is_held_before_any_candidate(self):
        for name in ('server', 'worker'):
            for key, value in (('AUTHENTIK_POSTGRESQL__HOST', AFTER['address']),
                               ('AUTHENTIK_POSTGRESQL__PORT', '5544')):
                original = fixture()
                original['services'][name]['environment'][key] = value
                with self.subTest(name=name, key=key), self.assertRaisesRegex(ValueError, 'endpoint differs'):
                    identity.candidate(json.dumps(original).encode(), BEFORE, AFTER)
        updated = identity.candidate(json.dumps(fixture()).encode(), BEFORE, AFTER)
        with self.assertRaises(ValueError):
            identity.candidate(updated, BEFORE, AFTER)

    def test_requires_exact_identity_stack_modes_and_local_redis(self):
        changes = [lambda c: c.update(name='homelab-db-tools'),
                   lambda c: c['services'].update(postgresql={}),
                   lambda c: c['services'].pop('redis'),
                   lambda c: c['services']['server'].update(command='worker'),
                   lambda c: c['services']['worker']['environment'].update(AUTHENTIK_REDIS__HOST='remote'),
                   lambda c: c['services']['server'].update(environment=[])]
        for change in changes:
            original = fixture(); change(original)
            with self.subTest(change=change), self.assertRaises(ValueError):
                identity.candidate(json.dumps(original).encode(), BEFORE, AFTER)

    def test_endpoint_values_are_literal_private_ipv4_and_numeric_ports(self):
        invalid = [None, {}, dict(AFTER, gateway='10.88.31.1'), dict(AFTER, address='postgres.example.invalid'),
                   dict(AFTER, address='0.0.0.0'), dict(AFTER, address='127.0.0.1'),
                   dict(AFTER, address='169.254.1.1'), dict(AFTER, address='8.8.8.8'),
                   dict(AFTER, address='10.88.31.23/24'), dict(AFTER, port='5432'),
                   dict(AFTER, port=True), dict(AFTER, port=0), dict(AFTER, port=65536)]
        original = json.dumps(fixture()).encode()
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                identity.candidate(original, BEFORE, value)
        with self.assertRaises(ValueError):
            identity.candidate(original, BEFORE, BEFORE)

    def test_parse_errors_never_echo_private_compose_content(self):
        private = b'{"synthetic-private-input": invalid}'
        with self.assertRaises(ValueError) as caught:
            identity.candidate(private, BEFORE, AFTER)
        self.assertNotIn('synthetic-private-input', str(caught.exception))


class IdentityDatabaseRulesTests(unittest.TestCase):
    def fixture(self):
        self.old = {'direction': 'out', 'proto': 'tcp', 'port': '5432',
                    'destination': BEFORE['address'] + '/32',
                    'comment': 'Restored Authentik database only'}
        self.new = {'direction': 'out', 'proto': 'tcp', 'port': '5432',
                    'source': '10.88.31.20/32', 'destination': AFTER['address'] + '/32',
                    'comment': 'postgresql approved client authentik'}
        return [{'direction': 'in', 'proto': 'tcp', 'port': '9000',
                 'source': '10.88.30.33/32', 'destination': '10.88.30.20/32',
                 'comment': 'Existing HTTP backend'}, self.old,
                {'direction': 'out', 'proto': 'tcp', 'port': '80,443',
                 'destination': '0.0.0.0/0', 'comment': 'Existing downloads'}]

    def test_exact_sql_allowance_is_replaced_while_http_and_other_rules_remain(self):
        original = self.fixture(); before = copy.deepcopy(original)
        result = identity.rules_candidate(original, BEFORE, self.new)
        self.assertEqual(result, [original[0], self.new, original[2]])
        self.assertEqual(original, before)
        self.assertNotIn(self.old, result)
        result[1]['comment'] = 'edited candidate'
        self.assertEqual(self.new['comment'], 'postgresql approved client authentik')

    def test_missing_duplicate_or_drifted_legacy_rule_is_not_implicitly_repaired(self):
        original = self.fixture()
        variants = [[], original[:1] + original[2:], original + [copy.deepcopy(self.old)],
                    [dict(self.old, comment='unknown existing SQL allowance')],
                    [dict(self.old, source='10.88.30.20/32')]]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                identity.rules_candidate(value, BEFORE, self.new)
        with self.assertRaises(ValueError):
            identity.rules_candidate(identity.rules_candidate(original, BEFORE, self.new), BEFORE, self.new)

    def test_a_second_or_broader_sql_allowance_holds_without_retaining_fallback(self):
        for port in ('5432', '53,5432', '1:65535', '5430-5440', None, '', 'postgresql'):
            original = self.fixture()
            original.append({'direction': 'out', 'proto': 'tcp', 'port': port,
                             'destination': '0.0.0.0/0', 'comment': 'Unmodelled egress'})
            with self.subTest(port=port), self.assertRaises(ValueError):
                identity.rules_candidate(original, BEFORE, self.new)

    def test_unmodelled_direction_or_protocol_cannot_hide_sql_fallback(self):
        for change in ({'proto': None}, {'proto': 'all'}, {'direction': None}):
            original = self.fixture()
            original.append(dict(self.old, **change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                identity.rules_candidate(original, BEFORE, self.new)

    def test_new_rule_requires_one_exact_client_and_server_not_a_subnet(self):
        self.fixture()
        changes = [{'source': '10.88.31.0/24'}, {'destination': '10.88.31.0/24'},
                   {'destination': BEFORE['address'] + '/32'}, {'source': '0.0.0.0/32'},
                   {'port': '5432,5544'}, {'proto': 'udp'}, {'direction': 'in'},
                   {'gateway': '10.88.31.1'}, {'comment': 'different scope'}]
        for change in changes:
            original = self.fixture(); after = dict(self.new, **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                identity.rules_candidate(original, BEFORE, after)


if __name__ == '__main__':
    unittest.main()
