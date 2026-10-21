from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from homelab import core
from homelab.render import installer_answer, render


@pytest.fixture
def catalog():
    return core.read_json(core.ROOT / "examples/site/catalog/site.json")


def test_example_has_complete_synthetic_inputs_and_deploy(catalog):
    result = core.validate_catalog(catalog)
    assert result["unresolved_fields"] == []
    assert sum(g["runtime"] == "vm" for g in catalog["guests"]) == 1
    assert sum(g["runtime"] == "unprivileged_lxc" for g in catalog["guests"]) == 14
    assert next(g for g in catalog["guests"] if g["key"] == "deploy")["state_root"] == "critical"


@pytest.mark.parametrize("field,value", [
    ("cpu", True), ("vmid", True), ("vmid", 0), ("memory_mib", -1),
    ("started", True), ("on_boot", True), ("protection", False),
    ("runtime", "privileged_lxc"), ("swap_mib", 8192),
])
def test_reject_unsafe_or_mistyped_guest_input(catalog, field, value):
    catalog["guests"][0][field] = value
    with pytest.raises(core.Refusal):
        core.validate_catalog(catalog)


def test_unknown_schema_field_is_not_silently_ignored(catalog):
    catalog["guests"][0]["start_immediately"] = True
    with pytest.raises(core.Refusal, match="schema"):
        core.validate_catalog(catalog)


@pytest.mark.parametrize("key", ["vmid", "key"])
def test_duplicate_guest_identity(catalog, key):
    catalog["guests"][1][key] = catalog["guests"][0][key]
    with pytest.raises(core.Refusal, match="duplicate"):
        core.validate_catalog(catalog)


@pytest.mark.parametrize("key", ["ipv4", "mac"])
def test_duplicate_network_identity(catalog, key):
    catalog["guests"][1]["interfaces"][0][key] = catalog["guests"][0]["interfaces"][0][key]
    with pytest.raises(core.Refusal, match="duplicate"):
        core.validate_catalog(catalog)


def test_backend_default_route_refuses(catalog):
    catalog["guests"][0]["interfaces"][0]["main_default"] = False
    next(i for i in catalog["guests"][0]["interfaces"] if i["vlan"] == 30)["main_default"] = True
    with pytest.raises(core.Refusal, match="backend"):
        core.validate_catalog(catalog)


def test_identity_preservation_is_mandatory(catalog):
    catalog["policy"]["preserve_existing_uid_gid"] = False
    with pytest.raises(core.Refusal):
        core.validate_catalog(catalog)


def test_backup_volume_exclusion_refuses(catalog):
    catalog["guests"][0]["mounts"][0]["backup"] = False
    with pytest.raises(core.Refusal):
        core.validate_catalog(catalog)


def test_duplicate_json_key_refuses(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"vmid":900,"vmid":901}')
    with pytest.raises(core.Refusal, match="duplicate"):
        core.read_json(p)


def test_nan_refuses(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"cpu":NaN}')
    with pytest.raises(core.Refusal):
        core.read_json(p)


def test_synthetic_full_roundtrip_and_noop(catalog, tmp_path):
    assert core.synthetic_plan(catalog, tmp_path)["changes"] == 18
    core.synthetic_approve(catalog, tmp_path)
    assert core.synthetic_apply(catalog, tmp_path)["changed"]
    assert core.synthetic_verify(catalog, tmp_path)["verified"]
    assert core.synthetic_plan(catalog, tmp_path)["changes"] == 0
    core.synthetic_approve(catalog, tmp_path)
    assert core.synthetic_apply(catalog, tmp_path) == {"target": "synthetic", "changed": False, "serial": 1}
    assert len(list((tmp_path / "history").glob("*-receipt.json"))) == 1


def test_apply_without_approval_writes_no_state(catalog, tmp_path):
    core.synthetic_plan(catalog, tmp_path)
    with pytest.raises(FileNotFoundError):
        core.synthetic_apply(catalog, tmp_path)
    assert not (tmp_path / "synthetic-state.json").exists()


def test_changed_catalog_refuses_saved_plan(catalog, tmp_path):
    core.synthetic_plan(catalog, tmp_path)
    core.synthetic_approve(catalog, tmp_path)
    catalog["guests"][0]["cpu"] += 1
    with pytest.raises(core.Refusal, match="catalog changed"):
        core.synthetic_apply(catalog, tmp_path)
    assert not (tmp_path / "synthetic-state.json").exists()


def test_stale_state_refuses(catalog, tmp_path):
    core.synthetic_plan(catalog, tmp_path)
    core.synthetic_approve(catalog, tmp_path)
    core.write_json(tmp_path / "synthetic-state.json", {"serial": 42, "objects": {}})
    with pytest.raises(core.Refusal, match="state changed"):
        core.synthetic_apply(catalog, tmp_path)


@pytest.mark.parametrize("case", ["expiry", "signature", "target", "plan", "catalog"])
def test_approval_binding_and_expiry(catalog, tmp_path, case):
    core.synthetic_plan(catalog, tmp_path)
    plan = core.read_json(tmp_path / "plan.json")
    key = b"synthetic-only-test-key"
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()
    approval = core.sign_approval(plan, key, expires=expiry)
    if case == "expiry":
        approval = core.sign_approval(plan, key, expires="2000-01-01T00:00:00+00:00")
    elif case == "signature":
        approval["signature"] = "0" * 64
    else:
        approval["payload"][{"target":"target", "plan":"plan_sha256", "catalog":"catalog_sha256"}[case]] = "wrong"
    with pytest.raises(core.Refusal):
        core.check_approval(approval, plan, key)


def test_protected_nested_update_refuses(catalog, tmp_path):
    core.synthetic_plan(catalog, tmp_path); core.synthetic_approve(catalog, tmp_path)
    core.synthetic_apply(catalog, tmp_path)
    catalog["guests"][0]["mounts"][0]["size_gib"] -= 1
    with pytest.raises(core.Refusal, match="protected"):
        core.synthetic_plan(catalog, tmp_path)


def test_local_execution_lock_does_not_get_stolen(tmp_path):
    with core.execution_lock(tmp_path):
        with pytest.raises(core.Refusal, match="lock occupied"):
            with core.execution_lock(tmp_path):
                raise AssertionError("second owner acquired lock")


def test_replaced_lock_is_preserved(tmp_path):
    with pytest.raises(core.Refusal, match="lock replaced"):
        with core.execution_lock(tmp_path):
            p = tmp_path / "execution.lock"
            p.rename(tmp_path / "old-lock")
            p.write_text("different owner")
    assert (tmp_path / "execution.lock").read_text() == "different owner"


def test_production_input_never_uses_synthetic_executor(catalog, tmp_path):
    catalog["site"]["environment"] = "production"
    with pytest.raises(core.Refusal, match="PVE adapter held"):
        core.synthetic_plan(catalog, tmp_path)


def test_synthetic_input_does_not_point_at_actual_management(catalog, tmp_path):
    catalog["guests"][0]["interfaces"][0]["ipv4"] = "10.0.25.20"
    with pytest.raises(core.Refusal, match="outside"):
        core.synthetic_plan(catalog, tmp_path)


def test_render_preserves_existing_directory(catalog, tmp_path):
    p = tmp_path / "rendered"
    p.mkdir(); (p / "keep").write_text("operator edit")
    with pytest.raises(core.Refusal, match="must be new"):
        render(catalog, p)
    assert (p / "keep").read_text() == "operator edit"


def test_render_contains_all_four_roots_and_deploy(catalog, tmp_path):
    p = tmp_path / "new-render"
    result = render(catalog, p)
    assert result["deploy_included"] and result["unresolved_field_count"] == 0
    for root in ("foundation", "critical", "application-guests", "security-vm"):
        values = core.read_json(p / "proxmox" / root / "site.auto.tfvars.json")
        assert "deploy" in values["guests"]
        assert values["guests"]["deploy"]["started"] is False


def test_installer_answer_is_parseable_and_nonwildcard(catalog):
    value = tomllib.loads(installer_answer(catalog, "$6$example$synthetic-only-hash"))
    assert value["disk-setup"]["filter"]["ID_SERIAL_SHORT"] == "EXAMPLE-SERIAL"
    assert value["network"]["source"] == "from-answer"
    assert value["first-boot"]["ordering"] == "before-network"
    assert "root-password" not in value["global"]


@pytest.mark.parametrize("case", ["serial", "size_bytes", "by_id", "duplicate", "read_only", "wildcard"])
def test_wrong_or_ambiguous_install_disk_refuses(case):
    expected = {"by_id":"/dev/disk/by-id/example", "serial":"EXAMPLE", "size_bytes":1000}
    observed = [expected | {"read_only":False}]
    if case == "duplicate":
        observed.append(copy.deepcopy(observed[0]))
    elif case == "wildcard":
        expected["serial"] = "EX*"
    else:
        observed[0][case] = {"serial":"OTHER", "size_bytes":999, "by_id":"/dev/wrong", "read_only":True}[case]
    with pytest.raises(core.Refusal):
        core.disk_preflight(expected, observed)


def test_disk_identity_pass_never_grants_erase():
    expected = {"by_id":"/dev/disk/by-id/example", "serial":"EXAMPLE", "size_bytes":1000}
    assert core.disk_preflight(expected, [expected | {"read_only":False}]) == {"identity_matched":True, "erase_authorized":False}


@pytest.mark.parametrize("case", ["missing", "size", "hash", "traversal", "symlink", "empty"])
def test_recovery_file_refusals(tmp_path, case):
    p = tmp_path / "capture"
    p.write_bytes(b"synthetic native export fixture")
    item = {"path":"capture", "size_bytes":p.stat().st_size, "sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
    if case == "missing": p.unlink()
    elif case == "size": item["size_bytes"] += 1
    elif case == "hash": item["sha256"] = "0" * 64
    elif case == "traversal": item["path"] = "../capture"
    elif case == "symlink":
        p.rename(tmp_path / "original"); p.symlink_to(tmp_path / "original")
    else: p.write_bytes(b""); item["size_bytes"] = 0
    with pytest.raises(core.Refusal):
        core.verify_recovery_files({"format":"homelab-recovery-files-v1", "files":[item]}, tmp_path)


def plan_change(before, after, actions=None, unknown=None, kind="proxmox_virtual_environment_container"):
    return {"format_version":"1.2", "resource_changes":[{"type":kind, "change":{"before":before, "after":after, "actions":actions or ["update"], "after_unknown":unknown or {}}}]}


@pytest.mark.parametrize("key,value", [
    ("disk", [{"size":1}]), ("network_interface", [{"mac_address":"02:aa:00:00:00:ff"}]),
    ("unprivileged",False), ("protection",False), ("idmap",[{"host_id":0}]),
    ("started",True), ("start_on_boot",True), ("mount_point",[]),
])
def test_actual_plan_nested_protected_field_guard(key, value):
    before = {key:"original", "cpu":[{"cores":2}], "memory":[{"dedicated":512}]}
    after = copy.deepcopy(before); after[key] = value
    with pytest.raises(core.Refusal): core.guard_tofu_plan(plan_change(before,after))


def test_actual_plan_cpu_adjustment_is_bounded():
    before = {"cpu":[{"cores":2,"units":100}], "memory":[{"dedicated":512}]}
    after = copy.deepcopy(before); after["cpu"][0]["cores"] = 3
    assert core.guard_tofu_plan(plan_change(before,after))["guard_passed"]
    after["cpu"][0]["units"] = 999
    with pytest.raises(core.Refusal): core.guard_tofu_plan(plan_change(before,after))


@pytest.mark.parametrize("actions", [["delete"],["delete","create"],["create","delete"],["forget"]])
def test_delete_replacement_and_forget_refuse(actions):
    with pytest.raises(core.Refusal): core.guard_tofu_plan(plan_change({}, {}, actions))


def test_unknown_nested_plan_value_refuses():
    with pytest.raises(core.Refusal): core.guard_tofu_plan(plan_change({}, {}, unknown={"mount_point":[{"volume":True}]}))


def test_documented_cli_is_same_code_and_refuses_pve(catalog, tmp_path):
    command=[sys.executable,str(core.ROOT/'bin/homelab')]
    path=core.ROOT/'examples/site/catalog/site.json'
    p=subprocess.run(command+['validate','--catalog',str(path)],capture_output=True,text=True)
    assert p.returncode==0 and json.loads(p.stdout)['valid']
    p=subprocess.run(command+['plan','--catalog',str(path),'--workspace',str(tmp_path),'--target','pve'],capture_output=True,text=True)
    assert p.returncode==3 and 'PVE execution held' in json.loads(p.stderr)['reason']
