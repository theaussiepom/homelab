"""Archive integrity and extraction stay local under synthetic download adapters."""

import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
from unittest.mock import patch, Mock
import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(path):
    spec = importlib.util.spec_from_file_location(
        "download_" + path.stem.replace("-", "_"), path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(name, kind=tarfile.REGTYPE, size=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as target:
        item = tarfile.TarInfo(name)
        item.type = kind
        content = b"synthetic executable"
        item.size = len(content) if size is None else size
        target.addfile(item, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


def test_collection_import_has_no_download_or_install_side_effects():
    with patch("urllib.request.urlopen") as network, patch("subprocess.run") as process:
        module = load(ROOT / "proxmox/applications/monitoring/install-collections.py")
    assert callable(module.install)
    network.assert_not_called()
    process.assert_not_called()


@pytest.mark.parametrize("cached", [False, True])
def test_collection_install_verifies_new_and_cached_content(tmp_path, cached):
    module = load(ROOT / "proxmox/applications/monitoring/install-collections.py")
    content = b"collection bytes"
    lock = {"fixture.tar.gz": hashlib.sha256(content).hexdigest()}
    if cached:
        (tmp_path / "fixture.tar.gz").write_bytes(content)
    with (
        patch.object(module, "urlopen", return_value=io.BytesIO(content)) as network,
        patch.object(module.subprocess, "run") as process,
    ):
        module.install(tmp_path, lock)
    assert network.call_count == (0 if cached else 1)
    assert process.call_args.args[0][-1] == str(tmp_path / "fixture.tar.gz")
    assert "--no-deps" in process.call_args.args[0]
    assert (tmp_path / "fixture.tar.gz").read_bytes() == content


@pytest.mark.parametrize("cached", [False, True])
def test_collection_digest_drift_blocks_ansible(tmp_path, cached):
    module = load(ROOT / "proxmox/applications/monitoring/install-collections.py")
    if cached:
        (tmp_path / "fixture").write_bytes(b"changed")
    with (
        patch.object(module, "urlopen", return_value=io.BytesIO(b"changed")),
        patch.object(module.subprocess, "run") as process,
        pytest.raises(SystemExit, match="pinned digest"),
    ):
        module.install(tmp_path, {"fixture": "0" * 64})
    process.assert_not_called()


def test_scanner_extracts_only_bounded_verified_binary(tmp_path):
    module = load(ROOT / ".github/scripts/install_gitleaks.py")
    data = archive("gitleaks")
    with (
        patch.object(module.platform, "system", return_value="fixture"),
        patch.object(module.platform, "machine", return_value="fixture"),
        patch.dict(
            module.PINS,
            {("fixture", "fixture"): ("fixture", hashlib.sha256(data).hexdigest())},
        ),
        patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(data)),
    ):
        module.install(tmp_path)
    assert (tmp_path / "gitleaks").read_bytes() == b"synthetic executable"
    assert (tmp_path / "gitleaks").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("scenario", ["digest", "directory", "oversize-entry"])
def test_scanner_refuses_archive_failures(tmp_path, scenario):
    module = load(ROOT / ".github/scripts/install_gitleaks.py")
    data = (
        archive("gitleaks", tarfile.DIRTYPE)
        if scenario == "directory"
        else archive("gitleaks")
    )
    digest = "0" * 64 if scenario == "digest" else hashlib.sha256(data).hexdigest()
    with (
        patch.object(module.platform, "system", return_value="fixture"),
        patch.object(module.platform, "machine", return_value="fixture"),
        patch.dict(module.PINS, {("fixture", "fixture"): ("fixture", digest)}),
        patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(data)),
    ):
        if scenario == "oversize-entry":
            member = Mock()
            member.isfile.return_value = True
            member.size = 64 * 1024 * 1024 + 1
            with (
                patch.object(module.tarfile.TarFile, "getmember", return_value=member),
                pytest.raises(ValueError),
            ):
                module.install(tmp_path)
        else:
            with pytest.raises(ValueError):
                module.install(tmp_path)
    assert not (tmp_path / "gitleaks").exists()


@pytest.mark.parametrize("scenario", ["valid", "digest", "directory", "size"])
def test_docker_tofu_tool_checks_archive_before_writing(tmp_path, scenario):
    module = load(ROOT / "proxmox/bootstrap/docker/install-tools.py")
    data = archive(
        "tofu", tarfile.DIRTYPE if scenario == "directory" else tarfile.REGTYPE
    )
    pin = {
        "url": "https://example.invalid/fixture",
        "sha256": (
            "0" * 64 if scenario == "digest" else hashlib.sha256(data).hexdigest()
        ),
    }
    target = tmp_path / "bin/tofu"
    with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(data)):
        if scenario == "size":
            member = Mock()
            member.isfile.return_value = True
            member.size = 256 * 1024 * 1024 + 1
            with (
                patch.object(module.tarfile.TarFile, "getmember", return_value=member),
                pytest.raises(SystemExit),
            ):
                module.install(pin, target)
        elif scenario == "valid":
            module.install(pin, target)
            assert target.read_bytes() == b"synthetic executable"
        else:
            with pytest.raises(SystemExit):
                module.install(pin, target)
