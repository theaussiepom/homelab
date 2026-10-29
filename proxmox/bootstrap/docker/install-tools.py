"""Install the already selected OpenTofu release inside the test image only."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request


def install(pin, target):
    with urllib.request.urlopen(pin["url"], timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if (
        len(data) > 64 * 1024 * 1024
        or hashlib.sha256(data).hexdigest() != pin["sha256"]
    ):
        raise SystemExit("OpenTofu download checksum refused")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("tofu")
        if not member.isfile() or member.size > 256 * 1024 * 1024:
            raise SystemExit("Unexpected tool archive")
        target.parent.mkdir()
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(0o755)


if __name__ == "__main__":
    install(
        json.loads(Path("/opt/tools.json").read_text())["opentofu"],
        Path("/opt/bin/tofu"),
    )
