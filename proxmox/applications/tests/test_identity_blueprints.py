"""Worker receipts, protected inputs, registration state and sanitized process output."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_blueprints as bp


def fixture():
    document = b'example blueprint'
    spec = dict(slug='console', guest='apps', app='console', app_name='Console',
                admission_group='Operators', provider_name='Console Login', client_id='console',
                authorization_flow='authorize', authentication_flow='login', invalidation_flow='logout',
                signing_key='certificate', launch_url='https://console.example.invalid/',
                callback='https://console.example.invalid/oidc/callback', sha512=hashlib.sha512(document).hexdigest())
    return spec, document


class Missing(Exception):
    pass


def model(**attrs):
    return SimpleNamespace(objects=MagicMock(), **attrs)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.document = fixture()
        self.provider, self.group, self.application, self.binding = (model() for _ in range(4))
        self.instances, self.flows, self.scopes, self.certificate = (model() for _ in range(4))
        self.outpost, self.proxy, self.base_provider = (model() for _ in range(3))
        self.actor = MagicMock()
        self.files = patch.object(Path, 'read_bytes', autospec=True,
            side_effect=lambda path: self.document if path.suffix == '.yaml' else b'synthetic')
        self.files.start()
        self.addCleanup(self.files.stop)
        modules = {'authentik.core.models': dict(Application=self.application, Group=self.group, Provider=self.base_provider),
                   'authentik.outposts.models': dict(Outpost=self.outpost),
                   'authentik.providers.proxy.models': dict(ProxyProvider=self.proxy),
                   'django.db': dict(transaction=SimpleNamespace(atomic=contextlib.nullcontext)),
                   'authentik.policies.models': dict(PolicyBinding=self.binding),
                   'authentik.providers.oauth2.models': dict(OAuth2Provider=self.provider, ScopeMapping=self.scopes),
                   'authentik.blueprints.models': dict(BlueprintInstance=self.instances),
                   'authentik.blueprints.v1.tasks': dict(apply_blueprint=self.actor),
                   'authentik.crypto.models': dict(CertificateKeyPair=self.certificate),
                   'authentik.flows.models': dict(Flow=self.flows),
                   'authentik.lib.config': dict(CONFIG={'blueprints_dir':'/blueprints'}),
                   'django.core.exceptions': dict(ObjectDoesNotExist=Missing)}
        installed = patch.dict(sys.modules, {key:SimpleNamespace(**value) for key,value in modules.items()})
        installed.start()
        self.addCleanup(installed.stop)
        self.instance = SimpleNamespace(pk='stable-id', enabled=True, path='custom/homelab-oidc-console.yaml',
            context={}, content='', last_applied=1, status='successful', last_applied_hash=self.spec['sha512'])
        self.instances.objects.filter.return_value.count.return_value = 1
        self.instances.objects.filter.return_value.exclude.return_value.exists.return_value = False
        self.instances.objects.get_or_create.return_value = self.instance, False

    def test_only_one_effective_strict_authorization_callback_is_admitted(self):
        url = self.spec['callback']
        legacy = {'matching_mode': 'strict', 'url': url}
        explicit = dict(legacy, redirect_uri_type='authorization')
        native = SimpleNamespace(**explicit)
        provider = SimpleNamespace(_redirect_uris=[legacy], redirect_uris=[native])
        self.assertTrue(bp.strict_callback(provider, url))
        native.redirect_uri_type = 'logout'
        self.assertFalse(bp.strict_callback(provider, url))
        native.redirect_uri_type = 'authorization'
        for stored in ([], [legacy, explicit], [dict(explicit, redirect_uri_type='logout')],
                       [dict(legacy, matching_mode='regex')], [dict(legacy, url=url+'/other')],
                       [dict(legacy, unknown=True)]):
            with self.subTest(stored=stored):
                provider._redirect_uris = stored
                self.assertFalse(bp.strict_callback(provider, url))

    def test_adopt_only_the_declared_strict_alias_and_primary_callbacks(self):
        primary = self.spec['callback']
        alias = 'https://alias.example.invalid/auth/strategy/callback/'
        rows = [dict(matching_mode='strict', url=url) for url in (alias, primary)]
        native = [SimpleNamespace(**row, redirect_uri_type='authorization') for row in rows]
        provider = SimpleNamespace(_redirect_uris=rows, redirect_uris=native)
        self.assertTrue(bp.strict_callback(provider, primary, [alias]))
        for stored in (rows[::-1], rows[:1], rows + [rows[0]]):
            with self.subTest(stored=stored):
                provider._redirect_uris = stored
                self.assertFalse(bp.strict_callback(provider, primary, [alias]))
        provider._redirect_uris = rows
        native[0].redirect_uri_type = 'logout'
        self.assertFalse(bp.strict_callback(provider, primary, [alias]))

    def test_refuse_foreign_grants_and_check_native_readback(self):
        query = self.provider.objects.filter.return_value
        query.count.return_value = 1
        query.exclude.return_value.exists.return_value = False
        p = SimpleNamespace(pk=7, _redirect_uris=[{'matching_mode':'strict','redirect_uri_type':'authorization',
            'url':self.spec['callback']}], name='Console Login',client_type='confidential',sub_mode='hashed_user_id',
            issuer_mode='per_provider',include_claims_in_id_token=True,client_secret='synthetic',
            signing_key_id=1,property_mappings=MagicMock())
        p.property_mappings.values_list.return_value = [1,2,3]
        query.first.return_value = p
        apps = self.application.objects.filter.return_value
        a = SimpleNamespace(provider_id=7, name='Console',policy_engine_mode='all',meta_launch_url=self.spec['launch_url'])
        apps.first.return_value = a
        apps.exclude.return_value.exists.return_value = False
        groups = self.group.objects.filter.return_value
        groups.count.return_value = 1
        groups.filter.return_value.exists.return_value = False
        bindings = self.binding.objects.filter.return_value
        bindings.exclude.return_value.exists.return_value = False
        bindings.count.return_value = 1
        refs = dict(foreign={'signing_key':1},scopes={1,2,3})
        self.assertTrue(bp.verify_registration(self.spec, b'synthetic', refs))
        self.assertFalse(bp.verify_registration(self.spec, b'other', refs))
        with self.assertRaises(ValueError):
            bp.verify_registration(self.spec, b'other', refs, adopting=True)
        self.assertTrue(bp.verify_registration(self.spec, b'synthetic', refs, adopting=True))
        a.provider_id = 8
        with self.assertRaises(ValueError):
            bp.verify_registration(self.spec, b'synthetic', refs)
        a.provider_id = 7
        bindings.exclude.return_value.exists.return_value = True
        with self.assertRaises(ValueError):
            bp.verify_registration(self.spec, b'synthetic', refs)
        bindings.exclude.return_value.exists.return_value = False
        a.provider_id = None
        query.first.return_value = None
        with self.assertRaises(ValueError):
            bp.verify_registration(self.spec, b'synthetic', refs, adopting=True)
        apps.first.return_value = None
        with self.assertRaises(ValueError):
            bp.verify_registration(dict(self.spec, retained=True), b'synthetic', refs, adopting=True)
        self.assertFalse(bp.verify_registration(self.spec, b'synthetic', refs))

    def test_successful_hash_repeat_and_native_readback_after_queue(self):
        with patch.object(bp, 'verify_registration', return_value=True):
            self.assertFalse(bp.apply_registration(self.spec, 30))
            self.actor.send_with_options.assert_not_called()
        self.instance.last_applied_hash = 'old'
        def refreshed():
            self.instance.last_applied = 2
            self.instance.last_applied_hash = self.spec['sha512']
        self.instance.refresh_from_db = refreshed
        with patch.object(bp, 'verify_registration', side_effect=[False, True]), patch.object(bp.time,'monotonic',return_value=1):
            self.assertTrue(bp.apply_registration(self.spec, 30))
        self.actor.send_with_options.assert_called_once_with(args=('stable-id',),rel_obj=self.instance)

    def test_worker_rejects_error_stale_success_readback_drift_and_wrong_file(self):
        for state, refreshed_hash, readback, outcome in [
                ('error','other',False,ValueError), ('successful','other',True,TimeoutError),
                ('successful',self.spec['sha512'],False,ValueError), ('waiting','other',True,TimeoutError)]:
            self.instance.last_applied = 1
            def refresh():
                self.instance.last_applied += 1
                self.instance.status = state
                self.instance.last_applied_hash = refreshed_hash
            self.instance.refresh_from_db = refresh
            with self.subTest(state=state), patch.object(bp.time,'sleep'),patch.object(bp.time,'monotonic',side_effect=[1,31]),\
                 patch.object(bp,'verify_registration',side_effect=[False,readback]), self.assertRaises(outcome):
                bp.apply_registration(self.spec,30)
        with self.assertRaises(ValueError):
            bp.apply_registration(dict(self.spec,sha512='wrong'),30)
        self.instance.refresh_from_db = lambda: None
        with patch.object(bp.time,'sleep'),patch.object(bp.time,'monotonic',side_effect=[1,31]),\
             patch.object(bp,'verify_registration',return_value=False),self.assertRaises(TimeoutError):
            bp.apply_registration(self.spec,30)

    def test_initial_dependencies_can_finish_after_service_health(self):
        self.flows.objects.get.side_effect = [Missing(),SimpleNamespace(pk=1),SimpleNamespace(pk=2),SimpleNamespace(pk=3)]
        with patch.object(bp.time,'sleep') as sleep,patch.object(bp.time,'monotonic',return_value=1),\
             patch.object(bp,'verify_registration',return_value=True):
            bp.apply_registration(self.spec,30)
        sleep.assert_called_once_with(2)
        self.flows.objects.get.side_effect = Missing()
        with patch.object(bp.time,'monotonic',return_value=29),self.assertRaises(TimeoutError):
            bp.apply_registration(self.spec,30)

    def test_forward_native_policy_and_exclusive_host_owner(self):
        spec = dict(self.spec, origin='https://console.example.invalid')
        proxy = MagicMock(pk=7, mode='forward_single', external_host=spec['origin'], internal_host='',
                          cookie_domain='', skip_path_regex='', basic_auth_enabled=False, authentication_flow_id=None,
                          intercept_header_auth=True, authorization_flow_id=1, invalidation_flow_id=2)
        proxy.jwt_federation_sources.exists.return_value = proxy.jwt_federation_providers.exists.return_value = False
        proxy.property_mappings.values_list.return_value = [3,4]
        proxy.outpost_set.exclude.return_value.exists.return_value = False
        providers = self.proxy.objects.filter.return_value
        providers.first.return_value = proxy
        providers.__or__.return_value.exclude.return_value.exists.return_value = False
        self.base_provider.objects.filter.return_value.exclude.return_value.exists.return_value = False
        apps = self.application.objects.filter.return_value
        apps.first.return_value = SimpleNamespace(provider_id=7, name=spec['app_name'],
                                                  meta_launch_url=spec['origin']+'/', policy_engine_mode='all')
        apps.exclude.return_value.exists.return_value = False
        bindings = self.binding.objects.filter.return_value
        bindings.count.return_value = bindings.filter.return_value.count.return_value = 1
        bindings.exclude.return_value.exists.return_value = False
        def check(adopting=True):
            return bp.forward_registration(spec, self.group, [1,2], {3,4}, adopting=adopting)
        self.assertTrue(check())
        app = apps.first.return_value
        membership = proxy.outpost_set.filter.return_value.exists
        with patch.dict(spec, retained_application={'name': app.name, 'launch_url': '', 'policy_engine_mode': 'any'}):
            with self.assertRaises(ValueError):
                check()
            with patch.object(app, 'meta_launch_url', ''), patch.object(app, 'policy_engine_mode', 'any'):
                membership.return_value = True
                self.assertTrue(check())
                membership.return_value = False
                with self.assertRaises(ValueError):
                    check()
                membership.return_value = True
                with patch.object(bindings.count, 'return_value', 0), self.assertRaises(ValueError):
                    check(adopting=False)
                with patch.object(apps.first, 'return_value', None), self.assertRaises(ValueError):
                    check()
        proxy.skip_path_regex = '/unexpected'
        with self.assertRaises(ValueError): check()
        self.assertFalse(check(adopting=False))
        proxy.skip_path_regex = ''
        for unexpected in (bindings.exclude.return_value, providers.__or__.return_value.exclude.return_value,
                           self.base_provider.objects.filter.return_value.exclude.return_value, apps.exclude.return_value,
                           proxy.outpost_set.exclude.return_value):
            unexpected.exists.return_value = True
            with self.assertRaises(ValueError): check()
            unexpected.exists.return_value = False
        apps.first.return_value = None
        with self.assertRaises(ValueError): check()
        providers.first.return_value = None
        self.assertFalse(check())

    def test_forward_assignment_repeats_waits_and_rechecks_under_lock(self):
        spec = dict(self.spec, type='forward_single', scope_mappings=['scope'])
        outpost = MagicMock()
        self.outpost.objects.get.return_value = outpost
        self.outpost.objects.select_for_update.return_value.get.return_value = outpost
        proxy = self.proxy.objects.get.return_value
        proxy.outpost_set.exclude.return_value.exists.return_value = False
        exists = outpost.providers.filter.return_value.exists
        def apply_file(spec, deadline, kind, verify):
            self.assertEqual(kind,'forward')
            return not verify()
        with patch.object(bp,'apply_file',side_effect=apply_file), patch.object(bp,'forward_registration',return_value=True):
            self.group.objects.get.side_effect = [Missing(), self.group]
            exists.return_value = True
            with patch.object(bp.time,'sleep') as sleep, patch.object(bp.time,'monotonic',return_value=1):
                self.assertFalse(bp.apply_registration(spec,30))
            sleep.assert_called_once_with(2)
            self.outpost.objects.select_for_update.assert_not_called()
            self.group.objects.get.side_effect = None
            with patch.dict(spec, retained_application={'name': 'Existing radio'}), self.assertRaises(ValueError):
                exists.return_value = False
                bp.apply_registration(spec,30)
            outpost.providers.add.assert_not_called()
            exists.side_effect = [False, True]
            self.assertFalse(bp.apply_registration(spec,30))
            outpost.providers.add.assert_not_called()
            exists.side_effect = [False, False, True]
            self.assertTrue(bp.apply_registration(spec,30))
            outpost.providers.add.assert_called_once_with(proxy)
            self.group.objects.get.side_effect = Missing()
            with patch.object(bp.time,'monotonic',return_value=29), self.assertRaises(TimeoutError):
                bp.apply_registration(spec,30)

    def test_unbound_proxy_pins_the_existing_scope_expression(self):
        spec = dict(self.spec, type='forward_single', admission_group=None, scope_mappings=['stock'],
                    additional_scope_mapping=dict(name='Fixture claim',scope_name='profile',
                        expression_sha256=hashlib.sha256(b'example').hexdigest()))
        extra = SimpleNamespace(pk=2, managed=None, scope_name='profile', expression='example')
        self.scopes.objects.get.side_effect = lambda **query: extra if 'name' in query else SimpleNamespace(pk=1)
        proxy = self.proxy.objects.get.return_value
        self.outpost.objects.get.return_value.providers.filter.return_value.exists.return_value = True
        def apply_file(spec, deadline, kind, verify):
            return verify(adopting=True)
        with patch.object(bp,'apply_file',side_effect=apply_file), patch.object(bp,'forward_registration',return_value=True) as check:
            self.assertTrue(bp.apply_registration(spec,30))
            self.assertIsNone(check.call_args.args[1])
            self.assertEqual(check.call_args.args[3], {1,2})
            extra.expression='drift'
            with self.assertRaises(ValueError): bp.apply_registration(spec,30)
            self.group.objects.get.assert_not_called()

    def test_existing_oidc_provider_keeps_its_secret_and_exact_grant(self):
        spec = dict(self.spec, type='retained_oidc', guard={'application_id':'original','provider_id':3},
                    application_name='Retained', policy_engine_mode='any')
        guard = MagicMock()
        secrets = self.provider.objects.filter.return_value.values_list.return_value.get
        grant = self.binding.objects.get.return_value
        grant.group_id=1
        grant.group.name=spec['admission_group']
        grant.user_id=grant.policy_id=None
        grant.order=0
        grant.enabled=True
        grant.negate=grant.failure_result=False
        def apply_file(spec, deadline, kind, verify):
            self.assertEqual(kind, 'retained_oidc')
            return verify(adopting=True)
        with patch.dict(sys.modules, identity_callbacks=guard), patch.object(bp,'apply_file',side_effect=apply_file):
            secrets.side_effect=['original','original']
            self.assertTrue(bp.apply_registration(spec,30))
            guard.apply_native.assert_called_once_with([spec['guard']],verify_only=True)
            for values in ([''], ['original','changed']):
                secrets.side_effect=values
                with self.assertRaises(ValueError): bp.apply_registration(spec,30)
            secrets.side_effect=['original','original']
            grant.user_id=7
            with self.assertRaises(ValueError): bp.apply_registration(spec,30)

    def test_reconcile_reports_only_app_guest_result_and_hash(self):
        with patch.object(bp,'apply_registration',return_value=True):
            result=bp.reconcile([self.spec])
        self.assertEqual(result['registrations'],[{'guest':'apps','app':'console','sha512':self.spec['sha512'],'changed':True}])
        with patch.object(bp,'apply_registration',side_effect=ValueError('private')):
            self.assertEqual(bp.reconcile([self.spec]),{'failed':{'guest':'apps','app':'console'}})

    def test_host_command_reports_only_admitted_results(self):
        script=Path(bp.__file__)
        data=[self.spec]
        expected={'guest':'apps','app':'console','sha512':self.spec['sha512'],'changed':False}
        for result, code in [({'registrations':[expected]},0),({'failed':{'guest':'apps','app':'console'}},1),
                             ({'failed':{'guest':'private','app':'unknown'}},'Identity blueprint verification failed')]:
            if code == 1:
                data = [dict(self.spec, type='retained_oidc')]
            with patch.object(sys,'argv',[str(script),'/opt/compose.yml','worker','/tmp/manifest']),\
                 patch.object(Path,'read_bytes',return_value=json.dumps(data).encode()),\
                 patch('subprocess.run',return_value=SimpleNamespace(stdout='private\nBLUEPRINT-RESULT '+json.dumps(result))) as run,\
                 contextlib.redirect_stdout(io.StringIO()) as output,contextlib.redirect_stderr(io.StringIO()) as errors,\
                 self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(script),run_name='__main__')
            self.assertEqual(caught.exception.code,code)
            self.assertNotIn('private',output.getvalue()+errors.getvalue())
            self.assertIn('worker',run.call_args.args[0])
            self.assertEqual('callback_guard' in json.loads(run.call_args.kwargs['input']),
                             data[0].get('type') == 'retained_oidc')
