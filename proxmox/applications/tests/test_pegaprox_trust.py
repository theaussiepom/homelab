"""Certificate, file and process boundaries for optional PegaProx provider trust."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import runpy
import ssl
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_trust as trust
import application_contract
import component_runtime
from component_pegaprox_fixture import descriptor, guest


def certificate(name, ca=True):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


class ProviderTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = certificate('Synthetic image root')
        cls.extra = certificate('Synthetic provider root')

    def test_public_ca_bundles_parse_and_private_or_invalid_material_refuses(self):
        for raw in (self.extra, b' \n' + self.extra + b'\n ', self.base + self.extra):
            self.assertIs(trust.certificates(raw, 65536), raw)
        for raw in (None, '', b'', b'x' * 65537, b'prefix' + self.extra,
                    self.extra + b'-----BEGIN PRIVATE KEY-----', self.extra + b'\x00',
                    b'-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n',
                    certificate('Synthetic leaf', ca=False)):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):
                trust.certificates(raw, 65536)

    def test_bundle_preserves_both_roots_repeats_and_never_follows_destination_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, extra, bundle, victim = [root / name for name in ('base', 'extra', 'bundle', 'victim')]
            base.write_bytes(self.base); extra.write_bytes(self.extra); victim.write_bytes(b'preserved')
            bundle.symlink_to(victim)
            for _ in range(2):
                self.assertEqual(trust.prepare_bundle(base, extra, bundle), str(bundle))
                self.assertEqual(victim.read_bytes(), b'preserved')
                self.assertFalse(bundle.is_symlink())
                self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o600)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cafile=bundle)
                self.assertEqual(len(context.get_ca_certs()), 2)
            self.assertEqual(base.read_bytes(), self.base)
            self.assertEqual(extra.read_bytes(), self.extra)
            self.assertFalse(list(root.glob('.pegaprox-ca-*')))
            with patch.object(trust.os, 'replace', side_effect=OSError('synthetic failure')):
                with self.assertRaises(OSError): trust.prepare_bundle(base, extra, bundle)
            self.assertFalse(list(root.glob('.pegaprox-ca-*')))
            extra.write_bytes(b'invalid')
            with self.assertRaises(ValueError): trust.prepare_bundle(base, extra, bundle)

    def test_selected_renderer_keeps_the_stock_image_and_security_boundary(self):
        original = descriptor()
        expected = component_runtime._pegaprox(original, guest())['pegaprox']
        selected = descriptor()
        selected['settings']['proxmox_ca_source'] = '/declared/context-ca.pem'
        rendered = component_runtime._pegaprox(selected, guest())['pegaprox']
        self.assertEqual(rendered.pop('entrypoint'), ['python3', '/run/homelab/pegaprox-trust.py'])
        extra = rendered['volumes'][-2:]
        self.assertEqual([row['target'] for row in extra],
                         ['/run/homelab/proxmox-ca.pem', '/run/homelab/pegaprox-trust.py'])
        self.assertTrue(all(row['read_only'] and not row['bind']['create_host_path'] for row in extra))
        del rendered['volumes'][-2:]
        self.assertEqual(rendered, expected)
        self.assertEqual(application_contract.runtime_files(selected) - application_contract.runtime_files(original),
                         {'pegaprox-proxmox-ca.pem', 'pegaprox-trust.py'})
        launcher = Path(trust.__file__).read_bytes()
        rows = trust.files(self.extra, launcher)
        self.assertEqual({row['path'] for row in rows}, {'pegaprox-proxmox-ca.pem', 'pegaprox-trust.py'})
        self.assertTrue(all(row['uid'] == 999 and row['gid'] == 999 and row['mode'] == '0400' for row in rows))
        self.assertEqual(rows[0]['content'], self.extra)
        self.assertEqual(rows[1]['content'], launcher)
        for value in (None, '', b'', b'x' * 65537):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                trust.files(self.extra, value)

    def test_launcher_keeps_process_arguments_and_sets_both_tls_clients(self):
        with patch.object(trust, 'prepare_bundle', return_value='/tmp/owned-bundle'), \
             patch.object(trust.os, 'execv') as execute, patch.object(sys, 'argv', ['launcher', '--help']), \
             patch.dict(os.environ, {'PRESERVED': 'yes'}):
            trust.main()
            execute.assert_called_once_with(sys.executable,
                                           [sys.executable, '/app/pegaprox_multi_cluster.py', '--help'])
            self.assertEqual(os.environ['SSL_CERT_FILE'], '/tmp/owned-bundle')
            self.assertEqual(os.environ['REQUESTS_CA_BUNDLE'], '/tmp/owned-bundle')
            self.assertEqual(os.environ['PRESERVED'], 'yes')

    def test_script_entrypoint_builds_before_executing_and_invalid_input_never_executes(self):
        script = Path(trust.__file__)
        with tempfile.TemporaryDirectory() as directory:
            source = script.read_bytes()
            def read(path):
                return source if path == script else self.extra
            descriptor_, temporary = tempfile.mkstemp(dir=directory)
            with patch.object(Path, 'read_bytes', read), \
                 patch('tempfile.mkstemp', return_value=(descriptor_, temporary)), \
                 patch('os.replace') as replace, patch('os.execv') as execute, \
                 patch.object(sys, 'argv', ['launcher']), patch.dict(os.environ):
                runpy.run_path(str(script), run_name='__main__')
                replace.assert_called_once_with(temporary, trust.BUNDLE)
                execute.assert_called_once_with(sys.executable, [sys.executable, trust.APPLICATION])
            with patch.object(Path, 'read_bytes', return_value=b'invalid'), patch('os.execv') as execute:
                with self.assertRaises(ValueError): trust.main()
                execute.assert_not_called()
