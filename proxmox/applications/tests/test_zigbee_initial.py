"""Closed Zigbee initial receipt admission using local synthetic custody only."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import coordinated_generation as generation
import deployment_inputs
import initial_ordinary as initial
import private_io as io
from custody_fixtures import save, backend, legacy_canonical, legacy_immutable

SCHEMA = "homelab-zigbee-initial-ordinary-v1"


class ZigbeeInitialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve(); self.root.chmod(0o700)
        self.work = self.root / "state/209"; self.work.parent.mkdir(mode=0o700); self.work.mkdir(mode=0o700)
        self.serial = {"path": "/dev/serial/by-id/usb-fixture"}
        self.cfg = {"guest": {"vmid": 209, "hostname": "fixture-radio", "serial_device": self.serial},
            "app": {"kind": "zigbee2mqtt", "vmid": 209, "mac": "02:00:00:00:00:09", "stack_config": str(self.root / "current-stack.json")},
            "site": {"node": "fixture-pve"}, "paths": {"state_root": str(self.work.parent),
                "backup_mount": str(self.root / "backup"), "backup_directory": str(self.root / "backup/states"),
                "backup_source": "fixture:/backup", "ca_file": str(self.root / "ca"),
                "host_device_key": str(self.root / "helper-key"), "host_known_hosts": str(self.root / "helper-hosts")}}
        save(self.root / "ca", b"fixture public CA\n")
        save(self.root / "helper-key", b"synthetic registered helper key\n")
        save(self.root / "helper-hosts", b"fixture host trust\n")
        save(self.root / "current-stack.json", {"kind": "zigbee2mqtt", "zigbee": {"serial_device": self.serial["path"]}})
        self.installed = self.root / "installed-zigbee.json"
        self.old_cfg = copy.deepcopy(self.cfg)
        # The original producer did not select or hash the newer helper inputs.
        for name in ("host_device_key", "host_known_hosts"): self.old_cfg["paths"].pop(name)
        self.old_cfg["app"]["stack_config"] = str(self.root / "old-stack.json")
        save(self.root / "old-stack.json", {"kind": "zigbee2mqtt", "zigbee": {"serial_device": self.serial["path"]}})
        state = save(self.work / "terraform.tfstate", backend(209))
        self.old = {"status": "passed", "binding": {"vmid": 209, "source_sha256": "a" * 64,
            "site_sha256": save(self.installed, self.old_cfg), "input_hashes": {
                str(self.root / "ca"): io.sha(self.root / "ca"),
                str(self.root / "old-stack.json"): io.sha(self.root / "old-stack.json")}},
            "state_sha256": state, "result": {"status": "passed", "changed": False}}
        self.copy = self.work / "ordinary-100-3/complete.json"
        self.canonical = self.work / "ordinary-complete.json"
        selected = {"schema": SCHEMA, "vmid": 209, "node": "fixture-pve",
            "incomplete_operations": ["ordinary-100-2"],
            "installed_site": str(self.installed), "installed_site_sha256": self.old["binding"]["site_sha256"],
            "initial_state_sha256": state, "receipt": {"operation": "ordinary-100-3",
                "sha256": save(self.canonical, legacy_canonical(self.old)),
                "immutable_sha256": save(self.copy, legacy_immutable(self.old)), "source_sha256": "a" * 64}}
        self.cfg["initial_ordinary"] = selected
        save(self.work / "ssh-trust.json", {"address": "198.18.25.9", "keys": [["ssh-ed25519", "fixture"]]})
        save(self.work / "ordinary-100-2/failure.log", b"retained earlier incomplete attempt\n")

    def attempt(self, cfg=None):
        cfg = self.cfg if cfg is None else cfg
        attempt = SimpleNamespace(work=self.work, operation=self.work / "ordinary-777-1",
            hold=self.work / "ORDINARY-HOLD.json", receipt=self.canonical, initial_ordinary=None,
            binding={"vmid": 209, initial.BINDING: initial.selection_digest(cfg)},
            workflow=["example/private-site", "example/private-site/.github/workflows/deploy.yml"], marker={})
        attempt._select_run = lambda: None
        return attempt

    def test_exact_zigbee_selection_reads_original_proofs_without_rewriting_them(self):
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        proofs, member, raw = initial.inspect(self.cfg)
        self.assertEqual(member["vmid"], 209)
        self.assertEqual(raw, self.copy.read_bytes()); self.assertNotEqual(raw, self.canonical.read_bytes())
        self.assertIn(str(self.installed), proofs); self.assertIn(str(self.copy), proofs)
        self.assertNotIn(str(self.canonical), proofs); self.assertNotIn(str(self.work / "terraform.tfstate"), proofs)
        self.assertNotIn("workflow", json.loads(raw))
        for p, body in before.items(): self.assertEqual(p.read_bytes(), body)

    def test_selected_kind_and_pins_are_closed_and_other_schemas_keep_their_shape(self):
        for kind in ("automation", "influxdb", "mariadb"):
            cfg = copy.deepcopy(self.cfg); cfg["app"]["kind"] = kind
            with self.subTest(kind=kind), self.assertRaises(ValueError): initial.selection(cfg)
        for mutate in (
            lambda s: s.update(waiver=True), lambda s: s.pop("installed_site_sha256"),
            lambda s: s["receipt"].update(sha256="invalid"), lambda s: s.pop("incomplete_operations"),
        ):
            cfg = copy.deepcopy(self.cfg); mutate(cfg["initial_ordinary"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): initial.selection(cfg)
        for schema, kind in ((initial.SCHEMA, "influxdb"), (initial.AUTOMATION_SCHEMA, "automation")):
            cfg = copy.deepcopy(self.cfg); cfg["app"]["kind"] = kind; cfg["initial_ordinary"]["schema"] = schema
            if kind == "automation": cfg["initial_ordinary"]["incomplete_operations"] = []
            else: cfg["initial_ordinary"].pop("incomplete_operations")
            raw = io.encoded(cfg["initial_ordinary"])
            expected = dict(vmid=209, node="fixture-pve", initial_state_sha256=self.old["state_sha256"],
                            initial_ordinary=cfg["initial_ordinary"]["receipt"])
            if kind == "automation": expected["incomplete_operations"] = []
            self.assertEqual(initial.selection(cfg), expected)
            self.assertEqual(initial.selection_digest(cfg), io.digest(raw))
            self.assertEqual(io.encoded(cfg["initial_ordinary"]), raw)

    def test_changed_or_missing_original_coordinator_refuses_even_with_new_raw_pins(self):
        original = copy.deepcopy(self.old_cfg)
        for serial in (None, "invalid", {"path": "/dev/serial/by-id/usb-other"}, {}):
            old_cfg = copy.deepcopy(original)
            if serial is None: old_cfg["guest"].pop("serial_device")
            else: old_cfg["guest"]["serial_device"] = serial
            site_hash = save(self.installed, old_cfg)
            self.cfg["initial_ordinary"]["installed_site_sha256"] = site_hash
            old = copy.deepcopy(self.old); old["binding"]["site_sha256"] = site_hash
            self.cfg["initial_ordinary"]["receipt"]["immutable_sha256"] = save(self.copy, legacy_immutable(old))
            with self.subTest(serial=serial), self.assertRaisesRegex(ValueError, "coordinator"):
                initial.inspect(self.cfg)

    def test_new_helper_inputs_are_hashed_without_inventing_old_hashes(self):
        hashes = deployment_inputs.input_hashes(self.cfg)
        for name in ("host_device_key", "host_known_hosts"):
            path = self.cfg["paths"][name]
            self.assertNotIn(path, self.old["binding"]["input_hashes"])
            self.assertEqual(hashes[path], io.sha(Path(path)))
        key = Path(self.cfg["paths"]["host_device_key"]); key.unlink()
        with self.assertRaises(FileNotFoundError): deployment_inputs.input_hashes(self.cfg)

    def test_first_anchor_later_success_and_rollback_use_existing_readonly_classifier(self):
        _, member, raw = initial.inspect(self.cfg)
        _, identity = generation.backend(self.work, member)
        attempt = self.attempt()
        self.assertEqual(generation.classify(attempt, member, identity["lineage"], raw, binding_key=initial.BINDING), identity)
        self.assertEqual(attempt.initial_ordinary, self.canonical.read_bytes())
        original = self.canonical.read_bytes()
        operation = self.work / "ordinary-778-1"
        modern = dict(status="passed", binding=attempt.binding, state_sha256=io.sha(self.work / "terraform.tfstate"),
            state_identity=identity, result={}, workflow=attempt.workflow, run_number=778,
            site_revision="b" * 40, operation=str(operation))
        save(operation / "complete.json", modern); save(self.canonical, modern)
        self.assertEqual(generation.classify(self.attempt(), member, identity["lineage"], raw, binding_key=initial.BINDING), identity)
        save(self.canonical, original)
        with self.assertRaisesRegex(ValueError, "latest ordinary success"):
            generation.classify(self.attempt(), member, identity["lineage"], raw, binding_key=initial.BINDING)
        self.assertEqual(self.copy.read_bytes(), raw)

    def test_unknown_incomplete_and_pending_history_never_becomes_an_exception(self):
        _, member, raw = initial.inspect(self.cfg); _, identity = generation.backend(self.work, member)
        for name in ("ordinary-90-1", "ordinary-100-4", "ordinary-999-1"):
            path = self.work / name; path.mkdir(mode=0o700)
            with self.subTest(name=name), self.assertRaises(FileNotFoundError):
                generation.classify(self.attempt(), member, identity["lineage"], raw, binding_key=initial.BINDING)
            path.rmdir()
        for directory in (self.copy.parent, self.work / "ordinary-100-2"):
            path = directory / "complete.json.pending"; save(path, {})
            with self.subTest(directory=directory), self.assertRaises(ValueError):
                generation.classify(self.attempt(), member, identity["lineage"], raw, binding_key=initial.BINDING)
            path.unlink()

    def test_incomplete_list_orders_numeric_run_and_attempt_without_changing_automation(self):
        for operations in (None, [{}], ["ordinary-100-2"] * 2, ["ordinary-100-3"],
                           ["ordinary-100-4"], ["ordinary-101-1"], ["ordinary-0-1"],
                           ["ordinary-100-0"], ["ordinary-" + str(n) + "-1" for n in range(1, 18)]):
            cfg = copy.deepcopy(self.cfg); cfg["initial_ordinary"]["incomplete_operations"] = operations
            with self.subTest(operations=operations), self.assertRaises(ValueError): initial.selection(cfg)
        for name in ("ordinary-99-99", "ordinary-100-1", "ordinary-100-2"):
            cfg = copy.deepcopy(self.cfg); cfg["initial_ordinary"]["incomplete_operations"] = [name]
            self.assertEqual(initial.selection(cfg)["incomplete_operations"], [name])
        cfg = copy.deepcopy(self.cfg); cfg["initial_ordinary"]["receipt"]["operation"] = "ordinary-100-10"
        cfg["initial_ordinary"]["incomplete_operations"] = ["ordinary-100-2"]
        self.assertEqual(initial.selection(cfg)["incomplete_operations"], ["ordinary-100-2"])
        cfg["initial_ordinary"]["incomplete_operations"] = ["ordinary-100-11"]
        with self.assertRaises(ValueError): initial.selection(cfg)
        cfg = copy.deepcopy(self.cfg); cfg["app"]["kind"] = "automation"
        cfg["initial_ordinary"]["schema"] = initial.AUTOMATION_SCHEMA
        with self.assertRaises(ValueError): initial.selection(cfg)
        cfg["initial_ordinary"]["incomplete_operations"] = ["ordinary-99-99"]
        self.assertEqual(initial.selection(cfg)["incomplete_operations"], ["ordinary-99-99"])

    def test_selected_incompletion_holds_completion_replay_and_missing_history_refuse(self):
        history = self.work / "ordinary-100-2"
        before = (history / "failure.log").read_bytes()
        for name in ("HOLD.json", ".ORDINARY-HOLD.json", "SERVICE-VERIFYING.json", "complete.json.pending", "complete.json"):
            path = history / name; save(path, {})
            with self.subTest(name=name), self.assertRaises(ValueError): initial.inspect(self.cfg)
            path.unlink()
        complete = history / "complete.json"; complete.symlink_to("absent")
        with self.assertRaises(ValueError): initial.inspect(self.cfg)
        complete.unlink()
        _, member, raw = initial.inspect(self.cfg); _, identity = generation.backend(self.work, member)
        active = self.attempt(); active.operation = history
        with self.assertRaisesRegex(ValueError, "no replay"):
            generation.classify(active, member, identity["lineage"], raw, binding_key=initial.BINDING)
        history.chmod(0o755)
        with self.assertRaises(ValueError): initial.inspect(self.cfg)
        history.chmod(0o700)
        cfg = copy.deepcopy(self.cfg); cfg["initial_ordinary"]["incomplete_operations"] = ["ordinary-100-1"]
        with self.assertRaises(FileNotFoundError): initial.inspect(cfg)
        cfg["initial_ordinary"]["incomplete_operations"] = []
        with self.assertRaises(FileNotFoundError):
            generation.classify(self.attempt(), initial.selection(cfg), identity["lineage"], raw, binding_key=initial.BINDING)
        self.assertEqual((history / "failure.log").read_bytes(), before)
        self.assertFalse(complete.exists())

    def test_changed_exact_pins_current_coordinator_and_existing_trust_refuse(self):
        original_ca = (self.root / "ca").read_bytes()
        original_trust = (self.work / "ssh-trust.json").read_bytes()
        original_copy = self.copy.read_bytes()
        for variant in ("canonical", "immutable", "source", "site", "state", "CA", "guest-trust", "coordinator"):
            cfg = copy.deepcopy(self.cfg); selected = cfg["initial_ordinary"]
            if variant in {"canonical", "immutable", "source"}:
                key = {"canonical": "sha256", "immutable": "immutable_sha256", "source": "source_sha256"}[variant]
                selected["receipt"][key] = "d" * 64
            if variant == "site": selected["installed_site_sha256"] = "d" * 64
            if variant == "state": selected["initial_state_sha256"] = "d" * 64
            if variant == "CA": save(self.root / "ca", b"changed CA")
            if variant == "guest-trust": (self.work / "ssh-trust.json").unlink()
            if variant == "coordinator": cfg["guest"]["serial_device"] = {"path": "/dev/serial/by-id/usb-other"}
            try:
                with self.subTest(variant=variant), self.assertRaises((ValueError, OSError)):
                    _, member, raw = initial.inspect(cfg)
                    _, identity = generation.backend(self.work, member)
                    generation.classify(self.attempt(cfg), member, identity["lineage"], raw, binding_key=initial.BINDING)
            finally:
                save(self.root / "ca", original_ca)
                save(self.work / "ssh-trust.json", original_trust)
            self.assertEqual(self.copy.read_bytes(), original_copy)
