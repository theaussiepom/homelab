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
        self.actor = MagicMock()
        self.files = patch.object(Path, 'read_bytes', autospec=True,
            side_effect=lambda path: self.document if path.suffix == '.yaml' else b'synthetic')
        self.files.start()
        self.addCleanup(self.files.stop)
        modules = {'authentik.core.models': dict(Application=self.application, Group=self.group),
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
            with patch.object(sys,'argv',[str(script),'/opt/compose.yml','worker','/tmp/manifest']),\
                 patch.object(Path,'read_bytes',return_value=json.dumps(data).encode()),\
                 patch('subprocess.run',return_value=SimpleNamespace(stdout='private\nBLUEPRINT-RESULT '+json.dumps(result))) as run,\
                 contextlib.redirect_stdout(io.StringIO()) as output,contextlib.redirect_stderr(io.StringIO()) as errors,\
                 self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(script),run_name='__main__')
            self.assertEqual(caught.exception.code,code)
            self.assertNotIn('private',output.getvalue()+errors.getvalue())
            self.assertIn('worker',run.call_args.args[0])
