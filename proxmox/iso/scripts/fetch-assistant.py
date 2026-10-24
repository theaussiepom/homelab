#!/usr/bin/env python3
"""Fetch the pinned helper through the vendor's signed public APT repository.

The public APT endpoint uses HTTP. The independently pinned release fingerprint,
verified InRelease signature, Packages digest and package digest authenticate it.
This never disables TLS verification on an HTTPS request.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path('/work/build')
REPO = 'http://download.proxmox.com/debian/pve/'
FINGERPRINT = '24B30F06ECC1836A4E5EFECBA7BCD1420BFE778E'
ASSISTANT_SHA256 = '19c786bf633e9c10631932cc8bcf1920153776995a25002c5c2fa818e405183e'


def fetch(url, output):
    if output.exists():
        return output.read_bytes()  # All cached bytes are verified below before use.
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(16 * 1024**2)
        assert not response.read(1), 'oversized vendor file'
    output.write_bytes(data)
    return data


ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
gpg_home = Path(os.environ.setdefault('GNUPGHOME', str(ROOT / 'gnupg')))
gpg_home.mkdir(mode=0o700, parents=True, exist_ok=True)
key = ROOT / 'proxmox-release-trixie.gpg'
fetch('https://enterprise.proxmox.com/debian/proxmox-release-trixie.gpg', key)
shown = subprocess.run(['gpg', '--batch', '--show-keys', '--with-colons', str(key)], check=True, capture_output=True, text=True)
assert FINGERPRINT in [r.split(':')[9] for r in shown.stdout.splitlines() if r.startswith('fpr:')], 'unexpected release key'
release = ROOT / 'InRelease'
fetch(REPO + 'dists/trixie/InRelease', release)
sig = subprocess.run(['gpg', '--batch', '--no-default-keyring', '--keyring', str(key), '--status-fd=1', '--verify', str(release)], check=True, capture_output=True, text=True)
assert '[GNUPG:] VALIDSIG ' + FINGERPRINT + ' ' in sig.stdout, 'wrong signing key'
package_path = 'pve-no-subscription/binary-amd64/Packages.gz'
lines = release.read_text().split('SHA256:\n', 1)[1].splitlines()
expected = next(line.split() for line in lines if len(line.split()) == 3 and line.split()[2] == package_path)
compressed = fetch(REPO + 'dists/trixie/' + package_path, ROOT / 'Packages.gz')
assert len(compressed) == int(expected[1]) and hashlib.sha256(compressed).hexdigest() == expected[0], 'package index hash mismatch'
blocks = [dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' ')) for block in gzip.decompress(compressed).decode().split('\n\n')]
matches = [b for b in blocks if b.get('Package') == 'proxmox-auto-install-assistant' and b.get('Version') == '9.2.8']
assert len(matches) == 1, 'pinned assistant unavailable or ambiguous'
package = matches[0]
deb_path = ROOT / 'assistant-9.2.8.deb'
deb = fetch(REPO + package['Filename'], deb_path)
assert len(deb) == int(package['Size']) and hashlib.sha256(deb).hexdigest() == package['SHA256'], 'package hash mismatch'
subprocess.run(['dpkg-deb', '--extract', str(deb_path), str(ROOT / 'assistant-root')], check=True)
binary = ROOT / 'assistant-root/usr/bin/proxmox-auto-install-assistant'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == ASSISTANT_SHA256, 'helper binary differs from reviewed pin'
reported = subprocess.run([str(binary), '--version'], check=True, capture_output=True, text=True)
version = (reported.stdout + reported.stderr).strip()
assert version.endswith('v9.2.8'), 'unexpected helper version report'
receipt = {'version': version, 'binary_sha256': ASSISTANT_SHA256, 'release_fingerprint': FINGERPRINT, 'inrelease_signature_verified': True, 'package': package, 'host_packages_installed': False}
(ROOT / 'assistant-verification.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'assistant_verified': True, 'version': version, 'sha256': ASSISTANT_SHA256}))
