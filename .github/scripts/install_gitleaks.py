#!/usr/bin/env python3
"""Install an integrity-pinned official scanner into a caller-selected tool directory."""
import hashlib
import io
from pathlib import Path
import platform
import sys
import tarfile
import urllib.request

PINS = {
    ('Linux', 'x86_64'): ('linux_x64', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
    ('Darwin', 'arm64'): ('darwin_arm64', 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'),
}

def install(directory):
    asset, digest = PINS[(platform.system(), platform.machine())]
    url = f'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_{asset}.tar.gz'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Scanner archive checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.getmember('gitleaks')
        if not member.isfile() or member.size > 64 * 1024 * 1024:
            raise ValueError('Unexpected scanner archive entry')
        binary = archive.extractfile(member).read()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / 'gitleaks'
    target.write_bytes(binary)
    target.chmod(0o755)
    print(target)

if __name__ == '__main__':
    install(Path(sys.argv[1]).resolve())
