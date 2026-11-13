"""Validate public PBS recovery material without reading or generating private keys."""
import hashlib
from private_io import require

MAX_PUBLIC_PEM = 4096


def public_key(raw):
    """Accept one RSA-4096 SubjectPublicKeyInfo PEM and retain its exact bytes."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_PUBLIC_PEM,
            'Use one bounded recovery public PEM')
    require(raw.startswith(b'-----BEGIN PUBLIC KEY-----\n')
            and raw.rstrip().endswith(b'-----END PUBLIC KEY-----')
            and raw.count(b'-----BEGIN ') == 1 and b'PRIVATE' not in raw,
            'Use only a recovery public key, never private material')
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError:
        raise ValueError('Invalid recovery public key') from None
    require(isinstance(key, RSAPublicKey) and key.key_size == 4096,
            'Use the native RSA-4096 recovery public key')
    canonical = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(raw.replace(b'\r\n', b'\n').rstrip()+b'\n' == canonical,
            'Use one complete canonical public PEM without trailing objects')
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {'pem': raw.decode('ascii'), 'sha256': hashlib.sha256(raw).hexdigest(),
            'fingerprint': hashlib.sha256(der).hexdigest()}
