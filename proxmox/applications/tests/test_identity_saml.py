"""Native SAML verification uses the pinned public cert and the existing grant."""
import hashlib
from pathlib import Path
import ssl
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_blueprints as bp


class NativeSamlTests(unittest.TestCase):
    def setUp(self):
        self.cert = (Path(__file__).parent / 'monitoring-synthetic-saml-certificate.txt').read_text()
        self.spec = dict(type='saml', slug='monitor', application_name='Monitoring', provider_name='Monitor SAML',
                         signing_key='Monitoring key', admission_group='Operators', policy_engine_mode='any',
                         certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert)).hexdigest(),
                         attributes={'acs_url': 'https://monitor.example.invalid/index_sso.php?acs', 'sign_assertion': True},
                         flows={'authentication_flow': None, 'authorization_flow': 'consent'}, mappings=['stock-username'])
        self.models = {name: MagicMock() for name in ('Application', 'Group', 'Provider', 'CertificateKeyPair',
                                                       'Flow', 'PolicyBinding', 'SAMLPropertyMapping', 'SAMLProvider')}
        def module(*names):
            return SimpleNamespace(**{name: self.models[name] for name in names})
        self.enterContext(patch.dict(sys.modules, {
            'authentik.core.models': module('Application', 'Group', 'Provider'),
            'authentik.crypto.models': module('CertificateKeyPair'), 'authentik.flows.models': module('Flow'),
            'authentik.policies.models': module('PolicyBinding'),
            'authentik.providers.saml.models': module('SAMLPropertyMapping', 'SAMLProvider')}))
        self.app = self.models['Application'].objects.get.return_value
        self.app.configure_mock(pk=1, name='Monitoring', provider_id=2, meta_launch_url='', policy_engine_mode='any')
        self.provider = self.models['SAMLProvider'].objects.get.return_value
        self.provider.configure_mock(pk=2, signing_kp_id=3, is_backchannel=False, backchannel_application_id=None,
            encryption_kp_id=None, verification_kp_id=None, name_id_mapping_id=None, authn_context_class_ref_mapping_id=None,
            authentication_flow_id=None, authorization_flow_id=7, **self.spec['attributes'])
        self.provider.property_mappings.values_list.return_value = [5]
        self.models['SAMLPropertyMapping'].objects.get.return_value.pk = 5
        self.models['Flow'].objects.get.return_value.pk = 7
        self.models['Group'].objects.get.return_value.pk = 4
        self.binding = self.models['PolicyBinding'].objects.get.return_value
        self.binding.configure_mock(group_id=4, policy_id=None, user_id=None, order=0, enabled=True, negate=False, failure_result=False)
        self.models['CertificateKeyPair'].objects.only.return_value.get.return_value = SimpleNamespace(pk=3, certificate_data=self.cert)
        for name in ('Application', 'SAMLProvider', 'Provider'):
            self.models[name].objects.filter.return_value.exclude.return_value.exists.return_value = False

    def verify(self, adopting=True):
        def apply(spec, deadline, kind, verifier):
            self.assertEqual(kind, 'saml')
            return verifier(adopting=adopting)
        with patch.object(bp, 'apply_file', side_effect=apply):
            return bp.apply_registration(self.spec, 30)

    def test_existing_saml_matches_and_later_managed_drift_is_detected(self):
        self.assertTrue(self.verify())
        self.provider.sign_assertion = False
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(self.verify(adopting=False))

    def test_foreign_key_grant_and_missing_native_dependencies_never_schedule_adoption(self):
        for obj, key, value in [(self.binding,'user_id',9),(self.binding,'negate',True),
                                (self.provider,'verification_kp_id',1),(self.app,'provider_id',42),
                                (self.provider,'signing_kp_id',19)]:
            with self.subTest(key=key), patch.object(obj, key, value), self.assertRaises(ValueError):
                self.verify()
        with patch.dict(self.spec, certificate_sha256='0'*64), self.assertRaises(ValueError):
            self.verify()
        self.models['PolicyBinding'].objects.get.side_effect = LookupError('ambiguous binding')
        with self.assertRaises(LookupError):
            self.verify()
