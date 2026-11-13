"""Recovery-key parsing uses disposable synthetic keys, never a real key store."""
import hashlib
from pathlib import Path
import sys
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_recovery


class RecoveryKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def test_native_public_pair_identifier_preserves_exact_source_bytes(self):
        result = backup_recovery.public_key(self.public)
        der = self.key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(result, {'pem': self.public.decode(),
            'sha256': hashlib.sha256(self.public).hexdigest(),
            'fingerprint': hashlib.sha256(der).hexdigest()})
        self.assertEqual(backup_recovery.public_key(self.public+b'\n')['fingerprint'], result['fingerprint'])
        self.assertNotEqual(backup_recovery.public_key(self.public+b'\n')['sha256'], result['sha256'])

    def test_private_material_duplicate_keys_trailing_content_and_wrong_sizes_refuse(self):
        private = self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        for raw in (private, b'', None, self.public.decode(), b'x'*4097,
                    self.public+self.public, self.public+b'-----END PUBLIC KEY-----\n', self.public+b'foreign', b'garbage',
                    b'-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n'):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError) as error:
                backup_recovery.public_key(raw)
            self.assertNotIn('MII', str(error.exception))
        for key in (rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key(),
                    ed25519.Ed25519PrivateKey.generate().public_key()):
            raw = key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
            with self.assertRaisesRegex(ValueError, 'RSA-4096'): backup_recovery.public_key(raw)


if __name__ == '__main__': unittest.main()
