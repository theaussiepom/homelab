"""Shared route checks: graph composition, TLS client and refusal boundaries."""
import copy
import http.client
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import component_https as graph
import component_types as types
import check_https as runtime


def fixture():
    apps = {'dns': {'guest': 'dns'}, 'ingress': {'guest': 'ingress'},
            'identity': {'guest': 'identity', 'origin_url': 'https://login.example.invalid'},
            'music': {'guest': 'music'}}
    def route(app, hosts):
        return {'type': 'http', 'target': {'app': app, 'guest': apps[app]['guest']},
                'ingress_target': {'app': 'ingress', 'guest': 'ingress', 'port': 443},
                'resolver': 'dns', 'hosts': hosts}
    exposures = {'dns': route('dns', ['dns.example.invalid']),
                 'proxy': route('ingress', ['proxy.example.invalid']),
                 'login': route('identity', ['login.example.invalid']),
                 'music': route('music', ['music.example.invalid', 'alias.example.invalid'])}
    exposures['proxy']['middlewares'] = ['sso']
    exposures['music']['target']['http_check'] = {'path': '/info', 'contains': 'server_version'}
    return {'apps': apps, 'exposures': exposures,
            'middlewares': {'sso': {'type': 'forward-auth', 'target': {'app': 'identity'}}},
            'enabled': ['dns', 'ingress', 'identity', 'music'],
            'guest_dependencies': {'dns': [], 'ingress': ['dns'], 'identity': ['ingress'], 'music': ['dns']}}


def check():
    return graph.checks(fixture(), {}, {})[1]['music'][0]


class GraphTests(unittest.TestCase):
    def test_aliases_automatic_and_foundations_wait_without_cycle_or_final_job(self):
        resolved = fixture(); before = copy.deepcopy(resolved)
        deps, rows = graph.checks(resolved, {}, {})
        self.assertEqual(resolved, before)
        self.assertEqual(deps['dns'], [])
        self.assertEqual(deps['music'], ['dns', 'ingress'])
        self.assertEqual([r['exposure'] for r in rows['ingress']], ['dns'])
        self.assertEqual([r['exposure'] for r in rows['identity']], ['proxy', 'login'])
        self.assertEqual([r['url'] for r in rows['music']],
                         ['https://music.example.invalid/info', 'https://alias.example.invalid/info'])
        self.assertTrue(rows['identity'][0]['require_auth'])
        self.assertEqual(rows['identity'][0]['auth_origins'], ['https://login.example.invalid'])
        self.assertEqual(set(rows), set(resolved['guest_dependencies']))

    def test_external_target_dns_only_disabled_target_and_nonstandard_port(self):
        resolved = fixture()
        resolved['exposures'] = {'external': {'type': 'http', 'target': {'address': '192.0.2.1'},
            'ingress_target': {'guest': 'ingress', 'port': 8443}, 'hosts': ['external.example.invalid']},
            'dns': {'type': 'dns'}, 'off': resolved['exposures']['music']}
        resolved['enabled'].remove('music')
        _, rows = graph.checks(resolved, {}, {})
        self.assertEqual(rows['ingress'][0]['url'], 'https://external.example.invalid:8443/')
        self.assertEqual(rows['music'], [])

    def test_native_auth_and_canonical_alias_use_declared_producers_and_origins(self):
        resolved = fixture()
        resolved['apps']['music']['authentication'] = 'music-auth'
        resolved['identity_providers'] = {'idp': {'origin': 'https://login.example.invalid'}}
        resolved['middlewares']['canonical'] = {'type': 'canonical-home-redirect', 'app': 'music'}
        resolved['middlewares']['headers'] = {'type': 'default-headers'}
        resolved['apps']['music']['origin_url'] = 'https://music.example.invalid'
        resolved['exposures']['music']['middlewares'] = ['canonical', 'headers']
        for library, site in [({'music-auth': {'provider': 'idp'}}, {}),
                              ({}, {'music-auth': {'provider': 'idp'}})]:
            deps, rows = graph.checks(resolved, {'policies': {'authentication': site}},
                                      {'policies': {'authentication': library}})
            self.assertIn('identity', deps['music'])
            self.assertEqual(rows['music'][0]['auth_origins'], ['https://login.example.invalid'])
        resolved['identity_providers']['idp']['origin'] = 'https://external-id.example.invalid'
        deps, rows = graph.checks(resolved, {'policies': {'authentication': site}},
                                  {'policies': {'authentication': library}})
        self.assertNotIn('identity', deps['music'])
        self.assertIn('https://external-id.example.invalid', rows['music'][0]['origins'])

    def test_disabled_producer_and_cycles_refuse(self):
        resolved = fixture(); resolved['enabled'].remove('identity')
        with self.assertRaisesRegex(ValueError, 'https-disabled-dependency'):
            graph.checks(resolved, {}, {})
        resolved = fixture(); resolved['guest_dependencies']['dns'] = ['ingress']
        with self.assertRaisesRegex(ValueError, 'https-dependency-cycle'):
            graph.checks(resolved, {}, {})

    def test_external_forward_auth_requires_declared_origin_and_native_outpost_uses_its_app(self):
        resolved = fixture()
        resolved['apps']['identity']['adapter'] = 'authentik'
        resolved['apps']['music']['resolved_connections'] = {'outpost': {'target': {'app': 'identity'}}}
        deps, rows = graph.checks(resolved, {}, {})
        self.assertIn('identity', deps['music'])
        self.assertEqual(rows['music'][0]['auth_origins'], ['https://login.example.invalid'])
        resolved['middlewares']['sso']['target'] = {'address': '192.0.2.5'}
        with self.assertRaisesRegex(ValueError, 'https-auth-origin'):
            graph.checks(resolved, {}, {})
        resolved['identity_providers'] = {'external': {'origin': 'https://external.example.invalid'},
                                          'certificate-only': {'type': 'saml'}}
        graph.checks(resolved, {}, {})
        resolved['apps']['music']['authentication'] = 'saml'
        _, rows = graph.checks(resolved, {'policies': {'authentication': {'saml': {'provider': 'certificate-only'}}}},
                               {'policies': {'authentication': {}}})
        self.assertIn('https://login.example.invalid', rows['music'][0]['origins'])


class CompilerIntegrationTests(unittest.TestCase):
    def test_real_profile_expectation_reaches_route_and_generated_workflow(self):
        from test_component_explorer_latefiles import source_fixture
        import compile as compiler
        import component_workflows
        from test_component_workflow_generation import WorkflowIntegrationTests, graph as workflow_graph
        library, site = source_fixture()
        endpoint = library['app_profiles']['browser']['endpoints']['web_endpoint']
        endpoint['http_check'] = {'path': '/login', 'contains': 'Sign in'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); stack = root/'stack'; stack.mkdir()
            (stack/'stack.json').write_text(json.dumps(library))
            (stack/'images.json').write_text(json.dumps({name: {'repository': 'example/'+name,
                'tag': None, 'digest': 'sha256:'+'a'*64} for name in ('broker','browser','gateway')}))
            source = root/'site.json'; source.write_text(json.dumps(site))
            plan = compiler.resolve_plan(stack, source)
            rows = component_workflows.model(plan)['guests']['resolver']['https_checks']
            self.assertEqual(rows[0]['contains'], 'Sign in')
            self.assertTrue(rows[0]['url'].endswith('/login'))
            endpoint['protocol'] = 'tcp'
            (stack/'stack.json').write_text(json.dumps(library))
            with self.assertRaises(ValueError):
                compiler.resolve_plan(stack, source)
        case = WorkflowIntegrationTests(); case.setUp()
        try:
            selected = workflow_graph(); selected['guests']['viewer']['https_checks'] = rows
            workflow = case.model(selected)['guest-viewer.yml']['jobs']['deploy']
            step = workflow['steps'][-1]
            self.assertEqual(step['name'], 'HTTPS endpoints')
            self.assertNotIn('secrets', json.dumps(step))
            self.assertIn('--guest viewer', step['run'])
            self.assertEqual(step['timeout-minutes'], 15)
        finally:
            case.doCleanups()


class SchemaTests(unittest.TestCase):
    def test_closed_bounded_optional_http_expectation(self):
        for value in ({'path': '/'}, {'path': '/info', 'contains': 'server_version'}):
            types.http_check(value)
        for value in (None, {}, {'path': None}, {'path': ''}, {'path': '/'*2049},
                      {'path': '//outside'}, {'path': '/a/../b'}, {'path': '/a?b'},
                      {'path': '/a#b'}, {'path': '/a%20b'}, {'path': '/a\\b'},
                      {'path': '/a\nb'}, {'path': '/', 'contains': None},
                      {'path': '/', 'contains': ''}, {'path': '/', 'contains': 'x'*257},
                      {'path': '/', 'contains': '\x7f'}, {'path': '/', 'enabled': False}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                types.http_check(value)


class ProbeTests(unittest.TestCase):
    def test_verified_tls_normal_dns_no_proxy_or_credentials(self):
        conn = Mock(); response = conn.getresponse.return_value
        response.status = 200; response.getheader.return_value = None
        response.read.return_value = b'server_version'
        with patch.object(runtime.ssl, 'create_default_context', return_value='VERIFIED') as context, \
             patch.object(runtime.http.client, 'HTTPSConnection', return_value=conn) as https:
            self.assertEqual(runtime.request('https://music.example.invalid:8443/info?x=1'),
                             (200, None, b'server_version'))
        https.assert_called_once_with('music.example.invalid', 8443, timeout=10, context='VERIFIED')
        self.assertEqual(conn.request.call_args.args, ('GET', '/info?x=1'))
        response.read.assert_called_once_with(runtime.MAX_BODY + 1); conn.close.assert_called_once()
        conn.reset_mock(); conn.request.side_effect = OSError('private error')
        with patch.object(runtime.http.client, 'HTTPSConnection', return_value=conn), self.assertRaises(OSError):
            runtime.request('https://music.example.invalid/info')
        conn.close.assert_called_once()

    def test_success_expected_body_and_alias_redirect(self):
        selected = check()
        with patch.object(runtime, 'request', return_value=(200, None, b'{"server_version":"2"}')):
            runtime.probe(selected)
        with patch.object(runtime, 'request', side_effect=[(302, 'https://alias.example.invalid/info', b''),
                (200, None, b'server_version')]) as request:
            runtime.probe(selected)
        self.assertEqual(request.call_count, 2)

    def test_forward_auth_reaches_declared_login_and_never_requires_app_marker_on_login_page(self):
        selected = check(); selected.update(require_auth=True, auth_origins=['https://login.example.invalid'])
        selected['origins'].append('https://login.example.invalid')
        with patch.object(runtime, 'request', side_effect=[(302, 'https://login.example.invalid/start?next=x', b''),
                (200, None, b'<html>Sign in</html>')]):
            runtime.probe(selected)
        with patch.object(runtime, 'request', return_value=(200, None, b'server_version')), \
             self.assertRaisesRegex(ValueError, 'identity provider'):
            runtime.probe(selected)
        selected.update(contains=None, require_auth=False)
        with patch.object(runtime, 'request', return_value=(200, None, b'page')):
            runtime.probe(selected)

    def test_bad_status_body_marker_and_redirects_refuse(self):
        for response in ((404, None, b'not found'), (500, None, b'error'), (401, None, b'unauthorised'),
                         (200, None, b''), (200, None, b'x'*(runtime.MAX_BODY+1)),
                         (200, None, b'wrong application'), (302, None, b'')):
            with self.subTest(response=response[:2]), patch.object(runtime, 'request', return_value=response), \
                 self.assertRaises(ValueError):
                runtime.probe(check())
        for url in ('http://music.example.invalid/', 'https://evil.example.invalid/',
                    'https://user@music.example.invalid/', 'https://user:pass@music.example.invalid/',
                    'https://music.example.invalid/info', 'https://music.example.invalid/\x01',
                    'https://music.example.invalid/a\\b', 'https://:443/'):
            with self.subTest(url=url), patch.object(runtime, 'request', return_value=(302, url, b'')) as request, \
                 self.assertRaises(ValueError):
                runtime.probe(check())
            self.assertEqual(request.call_count, 1)
        with patch.object(runtime, 'request', side_effect=[(302, '/step'+str(i), b'') for i in range(6)]), \
             self.assertRaisesRegex(ValueError, 'too many'):
            runtime.probe(check())

    def test_finite_retries_preserve_failure_and_hide_response_urls(self):
        selected = check(); second = dict(selected, exposure='alias')
        with patch.object(runtime, 'probe', side_effect=[OSError('private'), None, None]) as probe, \
             patch.object(runtime.time, 'sleep') as sleep:
            runtime.verify([selected, second])
        self.assertEqual(probe.call_count, 3); sleep.assert_called_once_with(5)
        for error in (ValueError('secret URL'), OSError('TLS'), http.client.HTTPException('protocol')):
            with patch.object(runtime, 'probe', side_effect=error) as probe, \
                 patch.object(runtime.time, 'sleep') as sleep, \
                 self.assertRaisesRegex(ValueError, '^HTTPS checks failed for exposures: music$'):
                runtime.verify([selected])
            self.assertEqual(probe.call_count, 6); self.assertEqual(sleep.call_count, 5)
        runtime.verify([])

    def test_cli_uses_admitted_current_plan_and_refuses_disabled_guest(self):
        plan = SimpleNamespace(resolved=fixture(), site={}, library={})
        with patch.object(runtime.compiler, 'site_path', return_value='site'), \
             patch.object(runtime.compiler, 'resolve_plan', return_value=plan) as resolve, \
             patch.object(runtime, 'verify') as verify, patch('sys.stdout', new_callable=io.StringIO) as out, \
             patch.object(sys, 'argv', ['check_https.py', '--stack', '.', '--site-root', '.', '--guest', 'music']):
            runtime.main()
        self.assertTrue(resolve.call_args.kwargs['admit'])
        self.assertEqual(len(verify.call_args.args[0]), 2)
        self.assertEqual(json.loads(out.getvalue()), {'https_checks': 'passed', 'endpoints': 2})
        with patch.object(runtime.compiler, 'site_path', return_value='site'), \
             patch.object(runtime.compiler, 'resolve_plan', return_value=plan), \
             patch.object(sys, 'argv', ['check_https.py', '--stack', '.', '--site-root', '.', '--guest', 'unknown']), \
             self.assertRaisesRegex(ValueError, 'enabled guest'):
            runtime.main()
        # Exercise the actual executable entry without any target access.
        plan.resolved['exposures'] = {}
        with patch.object(runtime.compiler, 'site_path', return_value='site'), \
             patch.object(runtime.compiler, 'resolve_plan', return_value=plan), \
             patch.object(sys, 'argv', ['check_https.py', '--stack', '.', '--site-root', '.', '--guest', 'music']), \
             patch('sys.stdout', new_callable=io.StringIO):
            runpy.run_path(str(Path(runtime.__file__)), run_name='__main__')


if __name__ == '__main__':
    unittest.main()
