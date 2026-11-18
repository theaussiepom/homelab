"""Add the selected Proxmox CA to the stock image roots before starting PegaProx."""
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile

BASE = Path('/etc/ssl/certs/ca-certificates.crt')
EXTRA = Path('/run/homelab/proxmox-ca.pem')
BUNDLE = Path('/tmp/homelab-pegaprox-ca.pem')
APPLICATION = '/app/pegaprox_multi_cluster.py'
PEM = rb'(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+'


def certificates(raw, limit):
    """Accept bounded public certificate bundles, never private keys or other PEM."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit or not re.fullmatch(PEM, raw.strip()):
        raise ValueError('Use a bounded public CA certificate bundle')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=raw.decode('ascii'))
    except (UnicodeError, ssl.SSLError):
        raise ValueError('Invalid CA certificate bundle') from None
    if not context.get_ca_certs():
        raise ValueError('The certificate bundle contains no certificate authority')
    return raw


def files(public_ca, launcher):
    """Pure runtime rows; the caller supplies the sealed framework launcher bytes."""
    certificates(public_ca, 65536)
    if not isinstance(launcher, bytes) or not 0 < len(launcher) <= 65536:
        raise ValueError('Use the fixed PegaProx trust launcher')
    return [{'path': name, 'content': raw, 'uid': 999, 'gid': 999, 'mode': '0400'}
            for name, raw in [('pegaprox-proxmox-ca.pem', public_ca),
                              ('pegaprox-trust.py', launcher)]]


def prepare_bundle(base=BASE, extra=EXTRA, destination=BUNDLE):
    """Keep every image root and append the declared CA in the existing private tmpfs."""
    roots = certificates(base.read_bytes(), 1024 * 1024)
    added = certificates(extra.read_bytes(), 65536)
    descriptor, temporary = tempfile.mkstemp(prefix='.pegaprox-ca-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(roots.rstrip() + b'\n' + added.rstrip() + b'\n')
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return str(destination)


def main():
    bundle = prepare_bundle()
    os.environ.update(SSL_CERT_FILE=bundle, REQUESTS_CA_BUNDLE=bundle)
    # Preserve the official image's Python process and any operator-supplied args.
    os.execv(sys.executable, [sys.executable, APPLICATION, *sys.argv[1:]])


if __name__ == '__main__':
    main()
