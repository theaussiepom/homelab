"""Exposure API review with conforming endpoint/app collaborators, no compiler/targets."""
import copy
from types import SimpleNamespace
import unittest

from component_errors import ComponentError
from component_exposures import Exposures


def fixture():
    rows = {
        ('web', 'http'): {'app': 'web', 'address': '198.18.40.20', 'protocol': 'http', 'port': 8123},
        ('proxy', 'https'): {'app': 'proxy', 'address': '198.18.40.10', 'protocol': 'https', 'port': 443},
        ('proxy', 'dashboard'): {'app': 'proxy', 'internal': 'dashboard'},
        ('sso', 'auth'): {'app': 'sso', 'address': '198.18.40.11', 'protocol': 'http', 'port': 9000},
        ('external', 'nas'): {'address': '198.18.25.10', 'protocol': 'https', 'port': 5001},
    }
    calls = []

    def endpoint(reference):
        key = ('external', reference['external']) if 'external' in reference else (reference['app'], reference['endpoint'])
        calls.append(copy.deepcopy(reference))
        return copy.deepcopy(rows[key])

    resolver = SimpleNamespace(
        site={'domains': {'web': 'Web.example.invalid', 'alias': 'Other.example.invalid', 'proxy': 'proxy.example.invalid'},
              'exposures': {}, 'networks': {'home': {'cidr': '198.18.40.0/24'}}},
        policy={'tls': {'public': {'type': 'acme', 'resolver': 'dns'}}, 'middlewares': {},
                'transport': {'nas': {'type': 'verified'}}},
        apps={'web': {'id': 'web', 'adapter': 'homeassistant', 'properties': {}},
              'proxy': {'id': 'proxy', 'adapter': 'traefik', 'properties': {'dashboard': True}},
              'dns': {'id': 'dns', 'adapter': 'pihole', 'properties': {}},
              'sso': {'id': 'sso', 'adapter': 'authentik', 'properties': {}}},
        endpoint=endpoint, endpoints=copy.deepcopy(rows), rows=rows, calls=calls)
    return resolver


def http(r, **extra):
    value = {'type': 'http', 'target': {'app': 'web', 'endpoint': 'http'}, 'domain': 'web',
             'ingress': {'app': 'proxy', 'endpoint': 'https'}, 'tls': 'public', **extra}
    r.site['exposures']['web'] = value
    return value


class ExposurePolicyReview(unittest.TestCase):
    def test_http_and_dns_require_target_and_reject_the_old_outer_endpoint(self):
        for kind in ('http', 'dns'):
            for change in ('old-only', 'both', 'missing', 'null', 'wrong-reference'):
                r = fixture()
                value = http(r) if kind == 'http' else {
                    'type': 'dns', 'target': {'app': 'web', 'endpoint': 'http'},
                    'domain': 'web', 'resolver': 'dns'}
                r.site['exposures']['web'] = value
                if change == 'old-only': value['endpoint'] = value.pop('target')
                elif change == 'both': value['endpoint'] = copy.deepcopy(value['target'])
                elif change == 'missing': value.pop('target')
                elif change == 'null': value['target'] = None
                else: value['target'] = {'app': 'web', 'target': 'http'}
                with self.subTest(kind=kind, change=change), self.assertRaisesRegex(
                        ComponentError, ('component.invalid' if change == 'null' else 'component.fields')
                        + ' at exposures.web'):
                    Exposures(r).bind()

    def test_cloudflare_policy_resolves_a_named_internal_allowlist_in_any_order(self):
        r = fixture()
        r.policy['middlewares'] = {
            'public': {'type': 'cloudflare-source', 'local_allowlist': 'local', 'origin_header': 'x-origin-token'},
            'local': {'type': 'ip-allow-list', 'ranges': ['10.20.0.1', '192.168.10.15/24']}}
        api = Exposures(r); api.validate_policies()
        self.assertEqual(api.middlewares['public'], {'type': 'cloudflare-source',
            'ranges': ['10.20.0.1/32', '192.168.10.0/24'], 'origin_header': 'x-origin-token'})
        self.assertIn('local_allowlist', r.policy['middlewares']['public'])

    def test_cloudflare_policy_rejects_public_bypass_unknown_fields_and_unsafe_header(self):
        for change in ('missing', 'wrong-type', 'public', 'all', 'partial', 'benchmark', 'too-many', 'extra', 'header', 'header-case', 'header-real', 'bad-ref'):
            r = fixture()
            r.policy['middlewares'] = {
                'public': {'type': 'cloudflare-source', 'local_allowlist': 'local', 'origin_header': 'x-origin-token'},
                'local': {'type': 'ip-allow-list', 'ranges': ['10.20.0.0/16']}}
            if change == 'missing': r.policy['middlewares'].pop('local')
            elif change == 'wrong-type': r.policy['middlewares']['local'] = {'type': 'default-headers'}
            elif change in ('public', 'all'): r.policy['middlewares']['local']['ranges'] = ['1.1.1.0/24' if change == 'public' else '0.0.0.0/0']
            elif change in ('partial', 'benchmark'): r.policy['middlewares']['local']['ranges'] = ['10.0.0.0/7' if change == 'partial' else '198.18.0.0/15']
            elif change == 'too-many': r.policy['middlewares']['local']['ranges'] = ['10.20.0.1/32'] * 257
            elif change == 'extra': r.policy['middlewares']['public']['raw'] = {}
            elif change == 'bad-ref': r.policy['middlewares']['public']['local_allowlist'] = '../other'
            else: r.policy['middlewares']['public']['origin_header'] = {'header': 'x-forwarded-for', 'header-case': 'X-Origin', 'header-real': 'x-real-ip'}[change]
            with self.subTest(change=change), self.assertRaises(ComponentError): Exposures(r).validate_policies()

    def test_cloudflare_gate_must_be_first_unique_and_without_forward_auth(self):
        for selected in (['headers', 'public'], ['public', 'public'], ['public', 'login']):
            r = fixture()
            r.policy['middlewares'] = {
                'public': {'type': 'cloudflare-source', 'local_allowlist': 'local', 'origin_header': 'x-origin-token'},
                'local': {'type': 'ip-allow-list', 'ranges': ['10.0.0.0/8']},
                'headers': {'type': 'default-headers'},
                'login': {'type': 'forward-auth', 'endpoint': {'app': 'sso', 'endpoint': 'auth'}}}
            http(r, middlewares=selected)
            with self.subTest(selected=selected), self.assertRaises(ComponentError): Exposures(r).bind()
        r = fixture()
        r.policy['middlewares'] = {'public': {'type': 'cloudflare-source', 'local_allowlist': 'local', 'origin_header': 'x-origin-token'},
            'local': {'type': 'ip-allow-list', 'ranges': ['10.0.0.0/8']}}
        http(r, middlewares=['public']); self.assertIn('web', Exposures(r).bind()['routes']['proxy'])

    def test_named_policies_resolve_only_authored_endpoint_network_and_owner(self):
        r = fixture()
        r.policy['middlewares'] = {
            'login': {'type': 'forward-auth', 'endpoint': {'app': 'sso', 'endpoint': 'auth'}},
            'headers': {'type': 'default-headers'},
            'clients': {'type': 'ip-allow-list', 'ranges': [{'network': 'home'}, '198.18.25.10/32']},
            'canonical': {'type': 'canonical-home-redirect', 'app': 'web'},
        }
        original = copy.deepcopy(r.policy)
        api = Exposures(r)
        api.validate_policies()
        self.assertEqual(api.middlewares['clients']['ranges'], ['198.18.40.0/24', '198.18.25.10/32'])
        self.assertEqual(api.middlewares['login']['target'], r.rows[('sso', 'auth')])
        self.assertEqual(r.policy, original)
        self.assertEqual(r.calls, [{'app': 'sso', 'endpoint': 'auth'}])
        self.assertEqual((api.routes, api.records), ({}, {}))

    def test_policy_wrong_shapes_references_protocols_and_unknown_fields_refuse(self):
        policies = [None, {'type': 'unknown'}, {'type': 'default-headers', 'extra': True},
                    {'type': 'ip-allow-list', 'ranges': []}, {'type': 'ip-allow-list', 'ranges': 'all'},
                    {'type': 'ip-allow-list', 'ranges': [{'network': 'missing'}]},
                    {'type': 'ip-allow-list', 'ranges': [{'network': 'home', 'extra': True}]},
                    {'type': 'canonical-home-redirect', 'app': 'missing'}]
        for value in policies:
            r = fixture(); r.policy['middlewares']['invalid'] = value
            with self.subTest(value=value), self.assertRaises(ComponentError): Exposures(r).validate_policies()
        for mutation in ({'protocol': 'tcp'}, {'address': None}):
            r = fixture(); r.policy['middlewares']['login'] = {'type': 'forward-auth', 'endpoint': {'app': 'sso', 'endpoint': 'auth'}}
            if mutation.get('address', 'present') is None: r.rows[('sso', 'auth')].pop('address')
            else: r.rows[('sso', 'auth')].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ComponentError, 'authentication'): Exposures(r).validate_policies()
        for value in ({'type': 'static', 'resolver': 'dns'}, {'type': 'acme', 'resolver': '../bad'}):
            r = fixture(); r.policy['tls']['public'] = value
            with self.subTest(tls=value), self.assertRaises(ComponentError): Exposures(r).validate_policies()


class ExposureBindingReview(unittest.TestCase):
    def test_http_alias_dns_and_origin_bind_without_inventing_readiness(self):
        r = fixture(); http(r, aliases=['alias'], resolver='dns')
        r.rows[('proxy', 'https')]['port'] = 8443
        r.apps['web']['origin'] = {'exposure': 'web', 'domain': 'alias'}
        api = Exposures(r); result = api.bind()
        self.assertEqual(result['dns_records'], {'dns': {'Web.example.invalid': '198.18.40.10', 'Other.example.invalid': '198.18.40.10'}})
        self.assertEqual(result['routes']['proxy']['web']['target']['address'], '198.18.40.20')
        self.assertEqual(r.apps['web']['origin_url'], 'https://Other.example.invalid:8443')
        self.assertEqual(api.hostname({'exposure': 'web'}, {'app': 'web'}), 'Web.example.invalid')
        self.assertEqual(api.hostname({'exposure': 'web', 'domain': 'alias'}, {'app': 'web'}), 'Other.example.invalid')
        self.assertNotIn('readiness', r.apps['web'])

    def test_external_http_and_dns_only_publish_the_declared_address(self):
        r = fixture(); value = http(r, target={'external': 'nas'}, transport='nas')
        api = Exposures(r); result = api.bind()
        self.assertEqual(result['dns_records'], {})
        self.assertEqual(api.hostname({'exposure': 'web'}, {'address': '198.18.25.10'}), 'Web.example.invalid')
        r = fixture(); r.site['exposures']['web'] = {'type': 'dns', 'target': {'app': 'web', 'endpoint': 'http'}, 'domain': 'web', 'resolver': 'dns'}
        api = Exposures(r); result = api.bind()
        self.assertEqual(result['routes'], {})
        self.assertEqual(result['dns_records'], {'dns': {'Web.example.invalid': '198.18.40.20'}})

    def test_names_are_unique_case_insensitively_across_domains_aliases_and_exposures(self):
        for change in ('alias-case', 'repeat-domain', 'other-exposure'):
            r = fixture(); value = http(r)
            if change == 'alias-case': r.site['domains']['alias'] = 'web.EXAMPLE.invalid'; value['aliases'] = ['alias']
            elif change == 'repeat-domain': value['aliases'] = ['web']
            else: r.site['exposures']['again'] = copy.deepcopy(value)
            with self.subTest(change=change), self.assertRaises(ComponentError): Exposures(r).bind()

    def test_dashboard_needs_same_ingress_enabled_property_and_forward_auth(self):
        def selected():
            r = fixture(); http(r, target={'app': 'proxy', 'endpoint': 'dashboard'}, domain='proxy', middlewares=['login'])
            r.policy['middlewares']['login'] = {'type': 'forward-auth', 'endpoint': {'app': 'sso', 'endpoint': 'auth'}}
            return r
        r = selected(); result = Exposures(r).bind()
        self.assertEqual(result['routes']['proxy']['web']['target']['internal'], 'dashboard')
        self.assertIn(('proxy', 'dashboard'), r.endpoints)
        for kind in ('no-auth', 'headers-only', 'disabled', 'wrong-ingress'):
            r = selected()
            if kind == 'no-auth': r.site['exposures']['web']['middlewares'] = []
            elif kind == 'headers-only': r.policy['middlewares']['login'] = {'type': 'default-headers'}
            elif kind == 'disabled': r.apps['proxy']['properties']['dashboard'] = False
            else:
                r.apps['other'] = {'adapter': 'traefik', 'properties': {}}
                r.rows[('proxy', 'https')]['app'] = 'other'
            with self.subTest(kind=kind), self.assertRaisesRegex(ComponentError, 'authentication'): Exposures(r).bind()
        r = fixture(); Exposures(r).bind()
        self.assertNotIn(('proxy', 'dashboard'), r.endpoints)

    def test_ingress_target_resolver_transport_and_origin_refusals_are_closed(self):
        changes = [lambda r, v: v.update(extra=True), lambda r, v: v.update(tls='missing'),
                   lambda r, v: v.update(domain='missing'), lambda r, v: v.update(middlewares=['missing']),
                   lambda r, v: v.update(resolver='web'), lambda r, v: v.update(transport='missing'),
                   lambda r, v: v.update(transport='nas'),
                   lambda r, v: r.rows[('proxy', 'https')].update(protocol='http'),
                   lambda r, v: r.apps['proxy'].update(adapter='unbound'),
                   lambda r, v: r.rows[('web', 'http')].update(address='127.0.0.1'),
                   lambda r, v: r.rows[('web', 'http')].update(address='name.example.invalid'),
                   lambda r, v: r.rows[('web', 'http')].update(protocol='tcp')]
        for number, change in enumerate(changes):
            r = fixture(); value = http(r); change(r, value)
            with self.subTest(number=number), self.assertRaises(ComponentError): Exposures(r).bind()
        for kind in ('internal', 'missing-address', 'non-address'):
            r = fixture(); r.site['exposures']['web'] = {'type': 'dns', 'target': {'app': 'web', 'endpoint': 'http'}, 'domain': 'web', 'resolver': 'dns'}
            if kind == 'internal': r.rows[('web', 'http')]['internal'] = 'dashboard'
            elif kind == 'missing-address': r.rows[('web', 'http')].pop('address')
            else: r.rows[('web', 'http')]['address'] = 'name.example.invalid'
            with self.subTest(dns=kind), self.assertRaises(ComponentError): Exposures(r).bind()
        for reference in ({'exposure': 'missing'}, {'exposure': 'web', 'domain': 'missing'}, {'exposure': 'web', 'extra': True}):
            r = fixture(); http(r); r.apps['web']['origin'] = reference
            with self.subTest(origin=reference), self.assertRaises(ComponentError): Exposures(r).bind()
        r = fixture(); http(r); r.apps['sso']['origin'] = {'exposure': 'web'}
        with self.assertRaisesRegex(ComponentError, 'origin'): Exposures(r).bind()

    def test_hostname_cannot_claim_other_app_external_address_or_unselected_alias(self):
        r = fixture(); http(r); api = Exposures(r); api.bind()
        for reference, owner in [({'exposure': 'missing'}, {'app': 'web'}),
                                 ({'exposure': 'web'}, {'app': 'sso'}),
                                 ({'exposure': 'web'}, {'address': '198.18.25.10'}),
                                 ({'exposure': 'web', 'domain': 'alias'}, {'app': 'web'})]:
            with self.subTest(reference=reference, owner=owner), self.assertRaises(ComponentError): api.hostname(reference, owner)


if __name__ == '__main__':
    unittest.main()
