"""Vendor archive trust and password hashing run with synthetic external adapters."""

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "scripts" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "scenario",
    ["fresh", "cached", "key", "signature", "index", "package", "binary", "version"],
)
def test_assistant_fetch_binds_signing_key_index_package_and_extracted_binary(
    tmp_path, scenario
):
    module = load("fetch-assistant.py")
    binary = b"fixture helper"
    deb = b"fixture deb"
    fingerprint = module.FINGERPRINT
    compressed = gzip.compress(
        (
            "Package: proxmox-auto-install-assistant\nVersion: 9.2.8\nFilename: pool/assistant.deb\nSize: "
            + str(len(deb))
            + "\nSHA256: "
            + ("0" * 64 if scenario == "package" else hashlib.sha256(deb).hexdigest())
            + "\n"
        ).encode()
    )
    release = (
        "SHA256:\n "
        + ("0" * 64 if scenario == "index" else hashlib.sha256(compressed).hexdigest())
        + " "
        + str(len(compressed))
        + " pve-no-subscription/binary-amd64/Packages.gz\n"
    ).encode()
    assets = {
        "proxmox-release-trixie.gpg": b"public key",
        "InRelease": release,
        "Packages.gz": compressed,
        "assistant.deb": deb,
    }

    def network(url, **kwargs):
        return io.BytesIO(assets[url.rsplit("/", 1)[-1]])

    def execute(argv, **kwargs):
        if argv[0] == "gpg":
            stdout = (
                "fpr:::::::::"
                + ("0" * 40 if scenario == "key" else fingerprint)
                + ":\n"
                if "--show-keys" in argv
                else "[GNUPG:] VALIDSIG "
                + ("0" * 40 if scenario == "signature" else fingerprint)
                + " fixture\n"
            )
        elif argv[0] == "dpkg-deb":
            output = tmp_path / "assistant-root/usr/bin/proxmox-auto-install-assistant"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"changed" if scenario == "binary" else binary)
            stdout = ""
        else:
            stdout = "helper v0.0.0" if scenario == "version" else "helper v9.2.8"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    if scenario == "cached":
        for name, data in assets.items():
            (
                tmp_path / ("assistant-9.2.8.deb" if name == "assistant.deb" else name)
            ).write_bytes(data)
    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(module, "ASSISTANT_SHA256", hashlib.sha256(binary).hexdigest()),
        patch.dict(module.os.environ, {"GNUPGHOME": str(tmp_path / "gnupg")}),
        patch.object(module.urllib.request, "urlopen", side_effect=network) as fetch,
        patch.object(module.subprocess, "run", side_effect=execute),
    ):
        if scenario in ("fresh", "cached"):
            module.main()
            assert (
                json.loads((tmp_path / "assistant-verification.json").read_text())[
                    "host_packages_installed"
                ]
                is False
            )
        else:
            with pytest.raises(RuntimeError, match="vendor verification failed"):
                module.main()
        if scenario == "cached":
            fetch.assert_not_called()


@pytest.mark.parametrize("scenario", ["success", "exists", "short", "mismatch"])
def test_password_prompt_never_exports_plaintext_or_overwrites_existing_hash(
    tmp_path, scenario, capsys
):
    module = load("password-hash.py")
    target = tmp_path / "hash"
    first = "synthetic password of enough length"
    if scenario == "exists":
        target.write_bytes(b"existing")
    with (
        patch.object(
            module.getpass,
            "getpass",
            side_effect=[
                "short" if scenario == "short" else first,
                "different" if scenario == "mismatch" else first,
            ],
        ),
        patch.object(
            module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, b"$6$synthetic-hash\n", b""
            ),
        ) as process,
    ):
        if scenario == "success":
            module.save_hash(target)
            assert target.read_bytes() == b"$6$synthetic-hash\n"
            assert target.stat().st_mode & 0o777 == 0o600
            assert process.call_args.kwargs["input"] == first.encode() + b"\n"
            assert first not in " ".join(process.call_args.args[0])
        else:
            with pytest.raises(SystemExit):
                module.save_hash(target)
            process.assert_not_called()
    assert first not in capsys.readouterr().out
    if scenario == "exists":
        assert target.read_bytes() == b"existing"
