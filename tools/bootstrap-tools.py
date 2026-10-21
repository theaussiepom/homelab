#!/usr/bin/env python3
"""Fetch a pinned OpenTofu binary into an explicitly selected local directory."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('--directory', type=Path, required=True)
a = p.parse_args()
pins = json.loads((Path(__file__).resolve().parents[1] / 'releases/toolchain.json').read_text())
target = {('Darwin','arm64'):'darwin_arm64', ('Linux','x86_64'):'linux_amd64'}.get((platform.system(),platform.machine()))
if target is None:
    raise SystemExit('Unsupported local platform; add and verify its exact release artifact first.')
version = pins['opentofu']['version']
asset = pins['opentofu']['artifacts'][f'tofu_{version}_{target}.tar.gz']
if not asset['url'].startswith('https://github.com/opentofu/opentofu/releases/download/'):
    raise SystemExit('Unqualified download origin')
with urllib.request.urlopen(asset['url'], timeout=90) as response:
    content = response.read(64 * 1024 * 1024 + 1)
if len(content) > 64 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != asset['sha256']:
    raise SystemExit('Artifact size/checksum refused')
a.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
out = a.directory / 'tofu'
if out.exists() or out.is_symlink():
    raise SystemExit('Preserve existing tool directory; select a new one')
with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
    member = archive.getmember('tofu')
    if not member.isfile():
        raise SystemExit('Unexpected archive member')
    with out.open('xb') as stream:
        stream.write(archive.extractfile(member).read())
out.chmod(0o755)
print(json.dumps({'version':version,'artifact_sha256':asset['sha256'],'signature_verified':False,'system_install':False}))
