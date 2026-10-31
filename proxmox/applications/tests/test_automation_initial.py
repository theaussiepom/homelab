"""Closed Automation anchor with explicitly qualified earlier incomplete history."""

import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy
import guest_contract
import initial_ordinary as initial
import private_io as io
import test_initial_ordinary as original_cases
from custody_fixtures import save, legacy_canonical, legacy_immutable
from test_render import fixture as stack_fixture


class AutomationInitialTests(unittest.TestCase):
    def setUp(self):
        case = original_cases.InitialOrdinaryTests(); case.setUp()
        self.addCleanup(case.doCleanups); self.case = case
        self.cfg, self.work = case.cfg, case.work
        selected = self.cfg.pop("initial_ordinary")
        self.cfg["guest"]["memory_mib"] = self.cfg["app"]["memory_mib"] = 4096
        self.cfg["deployment"]["capabilities"] = ["linux", "docker"]
        self.cfg["app"].pop("database")
        self.cfg["app"].update(kind="automation", node_red_authentication="authentik-oidc",
            exclusive_writer_confirmed=True, required_paths=guest_contract.BLUEPRINTS["automation"]["required_paths"],
            service_health_checks={name: [{"name": name, "argv": ["true"]}] for name in ("mqtt", "homeassistant", "node_red")})
        self.stack = stack_fixture("automation")
        self.stack["services"]["homeassistant"]["environment"].pop("HOMELAB_HA_IPV4", None)
        stack_path = case.root / "stack.json"; save(stack_path, self.stack)
        self.cfg["app"]["stack_config"] = str(stack_path)
        site_hash = save(case.installed, self.cfg)
        old = copy.deepcopy(case.old)
        old["binding"]["site_sha256"] = site_hash
        old["binding"]["input_hashes"][str(stack_path)] = io.sha(stack_path)
        selected.update(schema=initial.AUTOMATION_SCHEMA, installed_site_sha256=site_hash,
                        incomplete_operations=["ordinary-70-1", "ordinary-80-1", "ordinary-90-1"])
        selected["receipt"]["immutable_sha256"] = save(case.immutable, legacy_immutable(old))
        selected["receipt"]["sha256"] = save(case.canonical, legacy_canonical(old))
        self.cfg["initial_ordinary"] = selected
        (self.work / "ordinary-90-1/complete.json").unlink()
        for name in selected["incomplete_operations"]:
            save(self.work / name / "failure.log", b"retained failed attempt evidence\n")
        # Cached source is not an operation-control marker scope or an executor.
        save(self.work / "ordinary-80-1/cache/tests/HOLD.json", b"cached test fixture, not a live hold")
        save(self.work / "ordinary-80-1/cache/never-run.py", b"raise AssertionError('never execute cached controllers')")
        save(case.site, self.cfg)

    def test_explicit_failed_history_stays_incomplete_through_modern_generations(self):
        self.assertEqual(guest_contract.validate(self.cfg, self.stack), 808)
        original = {p: p.read_bytes() for name in self.cfg["initial_ordinary"]["incomplete_operations"]
                    for p in (self.work / name).rglob("*") if p.is_file()}
        infra, apps = self.case.runtime()
        for number in (777, 778):
            with patch.dict(os.environ, {"GITHUB_RUN_ID": str(number), "GITHUB_RUN_NUMBER": str(number),
                                       "GITHUB_SHA": self.case.revisions[number - 777]}):
                self.case.all_phases()
                value = json.loads(self.case.canonical.read_bytes())
                self.assertEqual(value["run_number"], number)
                self.assertEqual(value["binding"][initial.BINDING], initial.selection_digest(self.cfg))
        self.assertEqual(infra.call_count, 2); self.assertEqual(apps.call_count, 8)
        for path, raw in original.items(): self.assertEqual(path.read_bytes(), raw)
        for name in self.cfg["initial_ordinary"]["incomplete_operations"]:
            self.assertFalse((self.work / name / "complete.json").exists())

    def test_selection_is_closed_and_never_guesses_missing_history(self):
        changes = [
            lambda c: c["initial_ordinary"].pop("incomplete_operations"),
            lambda c: c["initial_ordinary"].update(incomplete_operations=None),
            lambda c: c["initial_ordinary"].update(incomplete_operations=[{}]),
            lambda c: c["initial_ordinary"].update(incomplete_operations=["ordinary-70-1"] * 2),
            lambda c: c["initial_ordinary"].update(incomplete_operations=["ordinary-0-1"]),
            lambda c: c["initial_ordinary"].update(incomplete_operations=["ordinary-100-1"]),
            lambda c: c["initial_ordinary"].update(incomplete_operations=["ordinary-101-1"]),
            lambda c: c["initial_ordinary"].update(incomplete_operations=["ordinary-" + str(n) + "-1" for n in range(1, 18)]),
            lambda c: c["app"].update(kind="influxdb"),
        ]
        for mutate in changes:
            cfg = copy.deepcopy(self.cfg); mutate(cfg)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): initial.selection(cfg)
        selected = self.cfg["initial_ordinary"]["incomplete_operations"]
        self.cfg["initial_ordinary"]["incomplete_operations"] = []
        with self.assertRaises((ValueError, OSError)):
            with self.case.attempt(): pass
        self.cfg["initial_ordinary"]["incomplete_operations"] = selected

    def test_any_actual_immediate_marker_or_new_completion_refuses_the_exception(self):
        for name in self.cfg["initial_ordinary"]["incomplete_operations"]:
            for leaf in ("HOLD.json", ".ORDINARY-HOLD.json", "SERVICE-VERIFYING.json", "complete.json.pending", "complete.json"):
                path = self.work / name / leaf; save(path, {})
                with self.subTest(operation=name, leaf=leaf), self.assertRaises(ValueError):
                    with self.case.attempt(): pass
                path.unlink()
            complete = self.work / name / "complete.json"; complete.symlink_to("absent")
            with self.assertRaises(ValueError): initial.inspect(self.cfg)
            complete.unlink()

    def test_unknown_older_and_later_incomplete_operations_are_never_skipped(self):
        infra, apps = self.case.runtime()
        for name in ("ordinary-60-1", "ordinary-999-1"):
            path = self.work / name; path.mkdir(mode=0o700)
            with self.subTest(operation=name), self.assertRaises((ValueError, OSError)):
                deploy.run("infrastructure", self.case.site)
            path.rmdir()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "70"}), self.assertRaises(ValueError):
            deploy.run("infrastructure", self.case.site)
        infra.assert_not_called(); apps.assert_not_called()

    def test_missing_or_symlinked_selected_history_is_not_silently_accepted(self):
        history = self.cfg["initial_ordinary"]["incomplete_operations"]
        original = list(history)
        history[0] = "ordinary-50-1"
        with self.assertRaises((ValueError, OSError)): initial.inspect(self.cfg)
        link = self.work / "ordinary-50-1"; link.symlink_to(self.work / "ordinary-70-1")
        with self.assertRaises(ValueError): initial.inspect(self.cfg)
        link.unlink(); history[:] = original

    def test_influx_contract_bytes_digest_and_no_history_exception_remain_unchanged(self):
        case = original_cases.InitialOrdinaryTests(); case.setUp(); self.addCleanup(case.doCleanups)
        raw = io.encoded(case.cfg["initial_ordinary"])
        expected = io.digest(raw)
        self.assertNotIn("incomplete_operations", initial.selection(case.cfg))
        self.assertEqual(initial.selection_digest(case.cfg), expected)
        self.assertEqual(io.encoded(case.cfg["initial_ordinary"]), raw)
        case.cfg["initial_ordinary"]["incomplete_operations"] = []
        with self.assertRaises(ValueError): initial.selection(case.cfg)
