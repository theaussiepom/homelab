"""Regressions for public-output boundaries and malformed operator inputs."""
import importlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from homelab import cli, core

renderer = importlib.import_module("homelab.render")


@pytest.fixture
def catalog():
    return core.read_json(core.ROOT / "examples/site/catalog/site.json")


@pytest.mark.parametrize("hardware_field", ["management_mac", "spare_mac", "installer_mac"])
def test_guest_cannot_reuse_hardware_mac(catalog, hardware_field):
    catalog["guests"][0]["interfaces"][0]["mac"] = catalog["hardware"][hardware_field]
    with pytest.raises(core.Refusal, match="duplicate interface mac"):
        core.validate_catalog(catalog)


def test_installer_requires_nonempty_dns(catalog):
    catalog["hardware"]["installer_dns"] = []
    with pytest.raises(core.Refusal, match="schema"):
        core.validate_catalog(catalog)


def test_production_render_refuses_symlink_into_public_root(catalog, tmp_path, monkeypatch):
    catalog["site"]["environment"] = "production"
    public = tmp_path / "public"
    public.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(public, target_is_directory=True)
    monkeypatch.setattr(renderer, "ROOT", public)
    with pytest.raises(core.Refusal, match="public implementation tree"):
        renderer.render(catalog, alias / "output")
    assert not (public / "output").exists()


@pytest.mark.parametrize("alias", [False, True])
def test_installer_hash_never_written_into_public_root(catalog, tmp_path, monkeypatch, capsys, alias):
    public = tmp_path / "public"
    public.mkdir()
    target = public
    if alias:
        target = tmp_path / "alias"
        target.symlink_to(public, target_is_directory=True)
    source = tmp_path / "catalog.json"
    source.write_text(json.dumps(catalog))
    root_hash = tmp_path / "root-hash"
    root_hash.write_text("$6$synthetic-only-test-value")
    root_hash.chmod(0o600)
    # The renderer has its real schema root; the CLI boundary is a disposable public tree.
    monkeypatch.setattr(cli.core, "ROOT", public)
    monkeypatch.setattr(cli, "installer_answer", lambda *_: "synthetic answer")
    monkeypatch.setattr(sys, "argv", ["homelab", "installer-answer", "--catalog", str(source),
        "--root-password-hash-file", str(root_hash), "--out", str(target / "answer.toml")])
    assert cli.main() == 3
    assert json.loads(capsys.readouterr().err)["refused"]
    assert not (public / "answer.toml").exists()


@pytest.mark.parametrize("value", [[], 42, None, "synthetic"])
def test_malformed_plan_has_structured_refusal(tmp_path, monkeypatch, capsys, value):
    source = tmp_path / "plan.json"
    source.write_text(json.dumps(value))
    monkeypatch.setattr(sys, "argv", ["homelab", "guard-plan", "--input", str(source)])
    assert cli.main() == 3
    result = capsys.readouterr()
    assert json.loads(result.err)["refused"]
    assert "Traceback" not in result.err


@pytest.mark.parametrize("value", [[], 42, None, "synthetic", {"payload": []}])
def test_malformed_approval_is_explicitly_refused(value):
    with pytest.raises(core.Refusal):
        core.check_approval(value, {}, b"synthetic-only-fixture")


@pytest.mark.parametrize("slot", ["", "scsi0", "mp0", "scsi", "scsi-1"])
def test_vm_data_disk_slot_refuses_invalid_or_root(catalog, slot):
    vm = next(guest for guest in catalog["guests"] if guest["runtime"] == "vm")
    vm["mounts"][0]["slot"] = slot
    with pytest.raises(core.Refusal):
        core.validate_catalog(catalog)
