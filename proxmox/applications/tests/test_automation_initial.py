"""Closed Automation anchor with explicitly qualified earlier incomplete history."""

import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_guest
import initial_ordinary as initial
import private_io as io
import test_initial_ordinary as original_cases
from custody_fixtures import save, legacy_canonical, legacy_immutable


class AutomationInitialTests(unittest.TestCase):
    def setUp(self):
        case=original_cases.InitialOrdinaryTests();case.role='automation';case.setUp()
        self.addCleanup(case.doCleanups);self.case=case
        self.cfg,self.work=case.cfg,case.work

    def test_explicit_failed_history_stays_incomplete_through_modern_generations(self):
        self.assertEqual(component_guest.validate(self.cfg), 808)
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

    def test_exact_reviewed_modern_failure_preserves_anchor_and_rejoins_normal_deployment(self):
        initial_bytes = io.encoded(self.cfg["initial_ordinary"])
        infra, apps = self.case.runtime()
        self.case.all_phases()
        previous = self.case.canonical.read_bytes()
        original_infrastructure = infra.side_effect
        # Reproduce the actual no-change infrastructure followed by an app failure.
        infra.side_effect = lambda *a, **k: {
            "changed": False, "created": False, "state_sha256": io.sha(self.work / "terraform.tfstate")}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778",
                                     "GITHUB_SHA": self.case.revisions[1]}):
            for phase in ("infrastructure", "preparation", "mqtt"):
                self.case.phase(phase)
            apps.side_effect = RuntimeError("synthetic localhost readiness refusal")
            with self.assertRaises(RuntimeError):
                self.case.phase("homeassistant")
            apps.side_effect = None
        operation = self.work / "ordinary-778-1"
        hold = (self.work / "ORDINARY-HOLD.json").read_bytes()
        log = operation / "homeassistant/application.log"
        save(log, b"synthetic application probe failed; original failure remains\n")
        row = {"operation": operation.name, "phase": "homeassistant", "hold_sha256": io.digest(hold),
               "infrastructure_sha256": io.sha(operation / "infrastructure-complete.json"),
               "log_sha256": io.sha(log), "previous_ordinary_sha256": io.digest(previous),
               "state_sha256": io.sha(self.work / "terraform.tfstate")}
        self.assertEqual(json.loads(previous)["state_sha256"], row["state_sha256"])
        self.cfg["reviewed_ordinary_failures"] = [row]
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "779", "GITHUB_RUN_NUMBER": "779",
                                     "GITHUB_SHA": self.case.revisions[1]}):
            with self.assertRaises((ValueError, OSError)):
                self.case.phase("infrastructure")
            # Only the separately reviewed operator preserves the active hold.
            (self.work / "ORDINARY-HOLD.json").rename(operation / "preserved-failed-hold.json")
            originals = {p: p.read_bytes() for p in (operation / "preserved-failed-hold.json",
                         operation / "homeassistant-started.json", operation / "infrastructure-complete.json", log)}
            original_row = copy.deepcopy(row)
            for change in ("unselected", "log", "previous", "namespace", "complete", "pending"):
                if change == "unselected":
                    self.cfg.pop("reviewed_ordinary_failures")
                if change == "log":
                    save(log, originals[log] + b"changed")
                if change == "previous":
                    row["previous_ordinary_sha256"] = "f" * 64
                if change == "namespace":
                    changed = json.loads(hold)
                    changed["binding"][initial.BINDING] = "f" * 64
                    new = io.encoded(changed)
                    save(operation / "preserved-failed-hold.json", new)
                    save(operation / "homeassistant-started.json", new)
                    row["hold_sha256"] = io.digest(new)
                if change == "complete":
                    save(operation / "complete.json", {})
                if change == "pending":
                    save(log.parent / ".pending-HOLD.json", {})
                before = infra.call_count
                with self.subTest(change=change), self.assertRaises((ValueError, OSError)):
                    self.case.phase("infrastructure")
                self.assertEqual(infra.call_count, before)
                self.assertFalse((self.work / "ordinary-779-1").exists())
                for path, raw in originals.items():
                    save(path, raw)
                row.clear(); row.update(original_row)
                self.cfg["reviewed_ordinary_failures"] = [row]
                (operation / "complete.json").unlink(missing_ok=True)
                (log.parent / ".pending-HOLD.json").unlink(missing_ok=True)
            infra.side_effect = original_infrastructure
            self.case.all_phases()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "780", "GITHUB_RUN_NUMBER": "780",
                                     "GITHUB_SHA": self.case.revisions[1]}):
            self.case.all_phases()
        self.assertEqual(infra.call_count, 4)
        self.assertEqual(self.case.canonical.read_bytes(), (self.work / "ordinary-780-1/complete.json").read_bytes())
        self.assertEqual(io.encoded(self.cfg["initial_ordinary"]), initial_bytes)
        self.assertEqual((operation / "preserved-failed-hold.json").read_bytes(), hold)
        self.assertFalse((operation / "homeassistant-complete.json").exists())
        self.assertFalse((operation / "complete.json").exists())

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
                self.case.phase("infrastructure")
            path.rmdir()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "70"}), self.assertRaises(ValueError):
            self.case.phase("infrastructure")
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
