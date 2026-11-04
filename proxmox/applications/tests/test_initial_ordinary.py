"""Explicit standalone Influx first-anchor transition, using synthetic local files."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import commands
import coordinated_generation as generation
import component_guest
import component_inputs
from current_initial_fixtures import CurrentInitialCase
import initial_ordinary as initial
import private_io as io
from custody_fixtures import save, backend, legacy_canonical, legacy_immutable


class InitialOrdinaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.current=CurrentInitialCase(self,self.root,getattr(self,'role','influxdb'))
        self.cfg=self.current.cfg;self.work=self.current.work
        self.installed=self.current.installed;self.immutable=self.current.immutable
        self.canonical=self.current.canonical;self.old=self.current.old
        self.site=self.current.h.packet;self.revisions=self.current.h.revisions
        self.ca_raw=self.current.ca_raw

    def binding(self):return self.current.binding()

    def attempt(self,binding=None):return self.current.attempt(binding)

    def runtime(self):return self.current.h.native,self.current.apps

    def all_phases(self):return self.current.all_phases()

    def phase(self,phase):return self.current.phase(phase)

    def publish(self):self.current.publish()

    def test_first_anchor_and_later_generations_keep_all_original_bytes(self):
        self.assertEqual(component_guest.validate(self.cfg), 808)
        proofs, member, raw = initial.inspect(self.cfg)
        self.assertEqual(raw, self.immutable.read_bytes())
        self.assertNotEqual(raw, self.canonical.read_bytes())
        self.assertIn(str(self.installed), proofs)
        self.assertNotIn(str(self.canonical), proofs)
        self.assertNotIn(str(self.work / "terraform.tfstate"), proofs)
        self.assertEqual(member["vmid"], 808)
        with self.attempt() as attempt:
            self.assertFalse(attempt.completed(commands.is_ancestor))
        original = {p: p.read_bytes() for p in self.work.rglob("*.json") if p != self.canonical and p.name != "terraform.tfstate"}
        installed = self.installed.read_bytes()
        infra, apps = self.runtime()
        for number, revision in ((777, self.revisions[0]), (778, self.revisions[1]), (779, self.revisions[1])):
            with patch.dict(os.environ, {"GITHUB_RUN_ID": str(number), "GITHUB_RUN_NUMBER": str(number), "GITHUB_SHA": revision}):
                self.all_phases()
                current = json.loads(self.canonical.read_bytes())
                self.assertEqual(current["run_number"], number)
                self.assertEqual(current["site_revision"], revision)
                self.assertEqual(set(current), {"status", "binding", "state_sha256", "state_identity", "result", "workflow", "run_number", "site_revision", "operation", "schema", "phase_inputs"})
                self.assertEqual(current["binding"][initial.BINDING], initial.selection_digest(self.cfg))
                self.assertEqual((Path(current["operation"]) / "complete.json").read_bytes(), self.canonical.read_bytes())
                self.assertFalse(self.phase("infrastructure")["target_contacted"])
        self.assertEqual(infra.call_count, 3)
        self.assertEqual(apps.call_count, 6)
        self.assertEqual(installed, self.installed.read_bytes())
        for path, raw in original.items(): self.assertEqual(path.read_bytes(), raw)

    def test_real_packet_compilation_and_preparation_bind_the_explicit_selection(self):
        import component_packet
        import test_component_packet as packets
        fixture=packets.PacketIntegrationTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.native('influxdb');fixture.site['apps'].pop('recursive_a')
        guest=fixture.site['guests']['resolver'];guest['lifecycle']='retained'
        guest['identity']={'vmid':808,'hostname':self.cfg['guest']['hostname']}
        context=fixture.site['contexts']['lab'];context['node']=self.cfg['site']['node']
        context['paths']=copy.deepcopy({key:self.cfg['paths'][key] for key in
            ('state_root','backup_directory','backup_mount','backup_source')})
        context['trust']={'ca_file':self.cfg['paths']['ca_file'],'known_hosts':self.cfg['paths']['known_hosts']}
        fixture.site['apps']['influxdb'].update(lifecycle='retained',identity={'phase':'influxdb','runtime_id':'owned-influx'})
        fixture.site['evidence']={'initial':{'type':'initial-ordinary','document':copy.deepcopy(self.cfg['initial_ordinary'])}}
        guest['admission']={'initial_ordinary':{'evidence':'initial'}}
        packet=component_packet.lower_plan(fixture.resolve(),inputs=self.root/'real-inputs')['resolver']
        source=self.root/'real-packet.json';save(source,packet)
        observed,site=component_inputs.prepare(source,self.root/'real-inputs',create=True)
        self.assertEqual(observed,json.loads(packet['files']['site.json']))
        self.assertEqual(observed['initial_ordinary'],self.cfg['initial_ordinary'])
        binding=component_inputs.binding(observed,site)
        self.assertEqual(binding[initial.BINDING],initial.selection_digest(observed))
        self.assertIn(str(self.immutable),binding['input_hashes'])
        self.assertNotIn(str(self.canonical),binding['input_hashes'])
        self.assertNotIn('workflow',json.loads(self.immutable.read_bytes()))

    def test_exact_closed_pins_and_standalone_kind_are_required(self):
        changes = [
            lambda c: c["initial_ordinary"].update(schema="other"),
            lambda c: c["initial_ordinary"].update(waiver=True),
            lambda c: c["initial_ordinary"].pop("initial_state_sha256"),
            lambda c: c["app"].update(kind="mariadb"),
            lambda c: c.update(coordinated_custody={}),
            lambda c: c["paths"].update(coordinated_custody_inputs="/elsewhere"),
            lambda c: c["initial_ordinary"].update(vmid=True),
            lambda c: c["initial_ordinary"].update(vmid=900),
            lambda c: c["initial_ordinary"].update(vmid=809),
            lambda c: c["initial_ordinary"].update(node="other"),
            lambda c: c["initial_ordinary"].update(installed_site="/a/../b"),
            lambda c: c["initial_ordinary"].update(installed_site_sha256="x"),
            lambda c: c["initial_ordinary"]["receipt"].pop("immutable_sha256"),
            lambda c: c["initial_ordinary"]["receipt"].update(operation="ordinary-0-1"),
            lambda c: c["initial_ordinary"]["receipt"].update(sha256="x"),
        ]
        for mutate in changes:
            cfg = copy.deepcopy(self.cfg); mutate(cfg)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): initial.selection(cfg)
        cfg = copy.deepcopy(self.cfg); cfg.pop("initial_ordinary")
        self.assertIsNone(initial.selection(cfg))
        self.assertEqual(initial.inspect(cfg), ({}, None, None))

    def test_no_selection_and_older_copy_never_adopt_the_initial_receipt(self):
        selected = self.cfg.pop("initial_ordinary")
        with self.attempt() as attempt, self.assertRaisesRegex(ValueError, "workflow runs"):
            attempt.completed(commands.is_ancestor)
        self.cfg["initial_ordinary"] = selected
        selected["receipt"]["operation"] = "ordinary-90-1"
        selected["receipt"]["immutable_sha256"] = io.sha(self.work / "ordinary-90-1/complete.json")
        with self.assertRaisesRegex(ValueError, "qualified initial"):
            self.binding()

    def test_immutable_site_source_and_trust_proofs_fail_closed(self):
        old_installed = self.installed.read_bytes()
        old_copy = self.immutable.read_bytes()
        for variant in ("site", "copy", "source", "site-binding", "kind", "paths", "CA", "inputs", "trust", "mode", "symlink"):
            with self.subTest(variant=variant):
                cfg = copy.deepcopy(self.cfg)
                if variant == "site": save(self.installed, old_installed + b" ")
                if variant == "copy": save(self.immutable, old_copy + b" ")
                if variant == "source": cfg["initial_ordinary"]["receipt"]["source_sha256"] = "c" * 64
                if variant == "site-binding": cfg["initial_ordinary"]["installed_site_sha256"] = "c" * 64
                if variant in ("kind", "paths"):
                    value = json.loads(old_installed)
                    if variant == "kind": value["app"]["kind"] = "mariadb"
                    else: value["paths"]["state_root"] = "/foreign"
                    site_hash = save(self.installed, value)
                    cfg["initial_ordinary"]["installed_site_sha256"] = site_hash
                    receipt = copy.deepcopy(self.old); receipt["binding"]["site_sha256"] = site_hash
                    cfg["initial_ordinary"]["receipt"]["immutable_sha256"] = save(self.immutable, legacy_immutable(receipt))
                if variant == "CA": save(self.root / "ca", b"changed CA")
                if variant == "inputs":
                    receipt = copy.deepcopy(self.old); receipt["binding"]["input_hashes"] = None
                    cfg["initial_ordinary"]["receipt"]["immutable_sha256"] = save(self.immutable, legacy_immutable(receipt))
                if variant == "trust": (self.work / "ssh-trust.json").unlink()
                if variant == "mode": self.installed.chmod(0o644)
                if variant == "symlink":
                    link = self.root / "link"; link.symlink_to(self.installed); cfg["initial_ordinary"]["installed_site"] = str(link)
                with self.assertRaises((ValueError, OSError)): initial.inspect(cfg)
                save(self.installed, old_installed); save(self.immutable, old_copy)
                save(self.root / "ca", self.ca_raw)
                save(self.work / "ssh-trust.json", {"address": self.cfg["app"]["address"], "keys": [["ssh-ed25519", "fixture"]]})

    def test_canonical_backend_and_bound_evidence_changes_refuse_before_targets(self):
        infra, apps = self.runtime()
        canonical = self.canonical.read_bytes(); state_raw = (self.work / "terraform.tfstate").read_bytes()
        expected = self.binding()
        bad = copy.deepcopy(expected); bad["input_hashes"][str(self.immutable)] = "0" * 64
        with self.assertRaisesRegex(ValueError, "immutable evidence"):
            with self.attempt(bad): pass
        for variant in ("missing", "changed", "typed", "state", "backend-id", "known-hosts"):
            selected = copy.deepcopy(self.cfg["initial_ordinary"])
            if variant == "missing": self.canonical.unlink()
            if variant == "changed": save(self.canonical, canonical + b" ")
            if variant == "typed":
                old = copy.deepcopy(self.old); old["result"]["rows"][1] = 1
                self.cfg["initial_ordinary"]["receipt"]["sha256"] = save(self.canonical, legacy_canonical(old))
            if variant == "state": save(self.work / "terraform.tfstate", backend(808, 99))
            if variant == "backend-id":
                value = backend(808); value["resources"][0]["instances"][0]["attributes"]["id"] = "foreign"
                save(self.work / "terraform.tfstate", value)
            if variant == "known-hosts": save(self.root / "hosts", b"unrelated ssh-ed25519 fixture\n")
            with self.subTest(variant=variant), self.assertRaises((ValueError, OSError)):
                self.phase("infrastructure")
            save(self.canonical, canonical); save(self.work / "terraform.tfstate", state_raw)
            save(self.root / "hosts", b"198.18.25.8 ssh-ed25519 fixture\n")
            self.cfg["initial_ordinary"] = selected
        infra.assert_not_called(); apps.assert_not_called()
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_holds_and_existing_group_ownership_are_not_exempted(self):
        for name in ("HOLD.json", ".ORDINARY-HOLD.json.pending", "SERVICE-VERIFYING.json"):
            path = self.work / name; save(path, {})
            with self.subTest(name=name), self.assertRaises(ValueError):
                with self.attempt(): pass
            path.unlink()
        for prefix in ("database-network-cutover-", "database-server-cutover-"):
            folder = self.work.parent / (prefix + "influxdb-fixture")
            save(folder / "request.json", {"schema": "homelab-database-server-cutover-v1", "members": {"influxdb": {"vmid": 808}}})
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, "coordinated maintenance"):
                with self.attempt(): pass
            (folder / "request.json").unlink(); folder.rmdir()

    def test_selected_or_other_ordinary_pending_markers_and_unknown_binding_refuse(self):
        for folder in (self.immutable.parent, self.work / "ordinary-90-1"):
            path = folder / "complete.json.pending"
            save(path, {})
            with self.subTest(folder=folder), self.assertRaises(ValueError):
                with self.attempt(): pass
            path.unlink()
        with self.attempt() as attempt, self.assertRaisesRegex(ValueError, "closed ordinary"):
            generation.classify(attempt, initial.selection(self.cfg), "fixture-808", self.immutable.read_bytes(), binding_key="arbitrary")

    def test_failed_infrastructure_hold_is_retained_without_replay(self):
        infra, apps = self.runtime()
        infra.side_effect = subprocess.CalledProcessError(7, ["fixture"])
        with self.assertRaises(subprocess.CalledProcessError): self.phase("infrastructure")
        hold = self.work / "ORDINARY-HOLD.json"; original = hold.read_bytes()
        with self.assertRaises((ValueError, OSError)): self.phase("infrastructure")
        self.assertEqual(hold.read_bytes(), original)
        infra.assert_called_once(); apps.assert_not_called()

    def test_later_success_outvotes_anchor_and_cannot_drop_selection_or_binding(self):
        anchor = self.canonical.read_bytes()
        infra, _ = self.runtime(); self.all_phases()
        receipt = self.canonical.read_bytes()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778", "GITHUB_SHA": self.revisions[1]}):
            for variant in ("anchor", "missing", "no-workflow", "no-binding", "malformed-binding", "legacy-downgrade"):
                current = self.work / "ordinary-777-1/complete.json"
                original = current.read_bytes()
                if variant == "anchor": save(self.canonical, anchor)
                if variant == "missing": self.canonical.unlink()
                if variant in ("no-workflow", "no-binding", "malformed-binding", "legacy-downgrade"):
                    value = json.loads(receipt)
                    if variant == "no-workflow": value.pop("workflow")
                    elif variant == "no-binding": value["binding"].pop(initial.BINDING)
                    elif variant == "malformed-binding": value["binding"] = None
                    else: value = {k: value[k] for k in ("status", "binding", "state_sha256", "result")}; value["binding"].pop(initial.BINDING)
                    save(current, value)
                with self.subTest(variant=variant), self.assertRaises((ValueError, OSError)):
                    self.phase("infrastructure")
                save(current, original); save(self.canonical, receipt)
        self.cfg.pop("initial_ordinary")
        with self.assertRaisesRegex(ValueError, "Keep the selected"):
            self.phase("infrastructure")
        self.assertEqual(infra.call_count, 1)

    def test_new_profile_retains_ordinary_workflow_sequence_and_source_ancestry(self):
        infra, _ = self.runtime(); self.all_phases()
        for environment in (
            {"GITHUB_RUN_NUMBER": "776", "GITHUB_RUN_ID": "776"},
            {"GITHUB_RUN_ATTEMPT": "2"},
            {"GITHUB_SHA": self.revisions[1]},
            {"GITHUB_REPOSITORY": "example/other", "HOMELAB_DEPLOYMENT_WORKFLOW": "example/other/.github/workflows/deploy.yml@refs/heads/main"},
        ):
            with patch.dict(os.environ, environment), self.assertRaises(ValueError): self.phase("infrastructure")
        with patch.object(commands, "is_ancestor", return_value=False), self.assertRaises(ValueError):
            self.phase("infrastructure")
        self.assertEqual(infra.call_count, 1)

    def test_unselected_malformed_old_binding_keeps_ordinary_provenance_refusal(self):
        self.cfg.pop("initial_ordinary")
        value = copy.deepcopy(self.old); value["binding"] = None
        save(self.canonical, value)
        with self.attempt() as attempt, self.assertRaisesRegex(ValueError, "workflow runs"):
            attempt.completed(commands.is_ancestor)
