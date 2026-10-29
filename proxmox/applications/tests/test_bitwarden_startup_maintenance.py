"""A policy correction cannot change the migrated vault or consume failure holds."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden_startup as startup
import foundation_cd as fc
import foundation_maintenance as maintenance


class StartupMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.work = self.state / "715"
        self.inputs = self.root / "inputs/bitwarden"
        self.nas = self.root / "nas/715"
        for path in (self.work, self.inputs, self.nas):
            path.mkdir(parents=True, mode=0o700)
        self.site = self.inputs / "site.json"
        self.cfg = {
            "guest": {"vmid": 715},
            "app": {
                "vmid": 715,
                "kind": "bitwarden",
                "stack_config": str(self.inputs / "stack.json"),
                "bitwarden": {"public_origin": "https://retained.example.invalid"},
            },
            "paths": {"state_root": str(self.state)},
        }
        fc.write_new(self.site, fc.encoded(self.cfg))
        self.stack = {
            "services": {
                "bitwarden": {
                    "restart": "no",
                    "image": "ghcr.io/bitwarden/lite:latest",
                    "environment": {
                        "BW_DOMAIN": "retained.example.invalid",
                        "BW_DB_PASSWORD": "synthetic-secret",
                    },
                }
            }
        }
        fc.write_new(self.inputs / "stack.json", fc.encoded(self.stack))
        fc.write_new(self.inputs / "prepared.json", b"original prepared")
        self.plan = {
            "plan_sha256": "a" * 64,
            "site_sha256": fc.digest(self.site.read_bytes()),
            "source_sha256": "b" * 64,
            "input_hashes": {"stack": "c" * 64},
        }
        for name in ("plan.json", "applied.json", "started.json"):
            fc.write_new(self.work / name, fc.encoded(self.plan))
        for name in ("ssh-trust.json", "terraform.tfstate", "rollout-complete.json"):
            fc.write_new(self.work / name, ("original " + name).encode())
        (self.work / "rendered").mkdir(mode=0o700)
        query = b"original database query"
        fc.write_new(self.work / "rendered/bitwarden-database-query.json", query)
        fc.write_new(self.nas / "bitwarden-database-query.json", query)
        receipt = {
            "status": "passed",
            "binding": {
                "prepared_sha256": fc.digest(
                    (self.inputs / "prepared.json").read_bytes()
                ),
                "source_sha256": "b" * 64,
                "input_hashes": self.plan["input_hashes"],
                "vmid": 715,
            },
            "plan_sha256": "a" * 64,
            "state_sha256": fc.digest((self.work / "terraform.tfstate").read_bytes()),
            "rollout_sha256": fc.digest(
                (self.work / "rollout-complete.json").read_bytes()
            ),
            "database_query_sha256": fc.digest(query),
        }
        for path in (self.work, self.nas):
            fc.write_new(path / "bitwarden-complete.json", fc.encoded(receipt))
        self.selected = {
            "schema": startup.SCHEMA,
            "revision": "d" * 40,
            "source_revision": "e" * 40,
            "vmid": 715,
            "plan_sha256": "a" * 64,
            "bitwarden_complete_sha256": fc.digest(fc.encoded(receipt)),
            "public_origin": self.cfg["app"]["bitwarden"]["public_origin"],
            "container": {
                "id": "f" * 64,
                "name": "homelab-bitwarden-bitwarden-1",
                "image": "sha256:" + "1" * 64,
                "fingerprint_sha256": "2" * 64,
            },
        }
        clean_stack = copy.deepcopy(self.stack)
        clean_stack["services"]["bitwarden"]["environment"] = {}
        self.config = self.root / "deployment.json"
        fc.write_new(
            self.config,
            fc.encoded(
                {
                    "schema": "homelab-bitwarden-deployment-v1",
                    "enabled": True,
                    "site": self.cfg,
                    "stack": clean_stack,
                    "approved_plan_sha256": "a" * 64,
                }
            ),
        )
        self.deployment = Mock()
        self.deployment.sha.side_effect = lambda path: fc.digest(path.read_bytes())
        self.deployment.source_hash.return_value = "b" * 64
        self.deployment.input_hashes.return_value = self.plan["input_hashes"]
        self.execute = Mock(
            side_effect=lambda *args, observe: (
                self.current()
                if observe
                else {"status": "passed", "changed": True, "container": self.current()}
            )
        )
        self.nas_root = Mock(return_value=self.nas)
        self.original = {
            p: p.read_bytes()
            for directory in (self.inputs, self.work, self.nas)
            for p in directory.rglob("*")
            if p.is_file()
        }
        patcher = patch.object(maintenance, "STATE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def current(self):
        return {
            **self.selected["container"],
            "restart": "unless-stopped",
            "running": True,
        }

    def run_startup(self):
        return startup.run(
            self.deployment,
            fc,
            self.cfg,
            self.site,
            self.root / "helper",
            self.selected,
            self.state,
            self.nas_root,
            maintenance.expected,
            self.config,
            self.execute,
        )

    def assert_no_target(self):
        self.execute.assert_not_called()
        self.deployment.execute.assert_not_called()

    def test_policy_overlay_preserves_originals_domain_and_second_push_is_observe_only(
        self,
    ):
        first = self.run_startup()
        self.assertTrue(first["changed"])
        self.assertEqual(first["public_origin"], "https://retained.example.invalid")
        self.assertFalse(first["client_acceptance_verified"])
        self.assertFalse(self.run_startup()["changed"])
        self.assertEqual(
            [call.kwargs["observe"] for call in self.execute.call_args_list],
            [False, True],
        )
        self.deployment.execute.assert_not_called()
        self.nas_root.assert_called_with(self.cfg)
        for path, data in self.original.items():
            self.assertEqual(path.read_bytes(), data)
        for name in ("claim", "complete", "result"):
            file = "bitwarden-startup-" + name + ".json"
            self.assertEqual(
                (self.work / file).read_bytes(), (self.nas / file).read_bytes()
            )
        self.assertFalse((self.work / "CONTINUATION-HOLD.json").exists())
        self.assertNotIn("synthetic-secret", json.dumps(first))

    def test_existing_verification_hold_is_never_cleared_or_consumed(self):
        hold = self.work / "BITWARDEN-CD-HOLD.json"
        fc.write_new(hold, b"original failed verification")
        with self.assertRaises(ValueError):
            self.run_startup()
        self.assertEqual(hold.read_bytes(), b"original failed verification")
        self.assert_no_target()
        self.assertFalse((self.work / "bitwarden-startup-claim.json").exists())

    def test_failed_policy_operation_cannot_replay_under_another_source_revision(self):
        self.execute.side_effect = RuntimeError("synthetic policy failure")
        with self.assertRaises(RuntimeError):
            self.run_startup()
        self.selected["revision"] = "3" * 40
        with self.assertRaises(ValueError):
            self.run_startup()
        self.execute.assert_called_once()
        self.assertTrue((self.work / "CONTINUATION-HOLD.json").is_file())
        self.assertFalse((self.work / "bitwarden-startup-complete.json").exists())

    def test_partial_claim_and_missing_nas_stop_before_target(self):
        fc.write_new(self.work / "bitwarden-startup-claim.json", b"previous attempt")
        with self.assertRaises(FileExistsError):
            self.run_startup()
        self.assert_no_target()
        (self.work / "bitwarden-startup-claim.json").unlink()
        self.nas_root.side_effect = ValueError("NAS unavailable")
        with self.assertRaises(ValueError):
            self.run_startup()
        self.assert_no_target()

    def test_source_completion_state_query_trust_and_domain_drift_stop_before_target(
        self,
    ):
        for kind in (
            "source",
            "completion",
            "state",
            "query",
            "trust",
            "domain",
            "tracked-domain",
        ):
            with self.subTest(kind=kind):
                change = None
                if kind == "source":
                    self.deployment.source_hash.return_value = "4" * 64
                elif kind == "domain":
                    self.selected["public_origin"] = "https://new.example.invalid"
                else:
                    change = {
                        "completion": self.work / "bitwarden-complete.json",
                        "state": self.work / "terraform.tfstate",
                        "query": self.nas / "bitwarden-database-query.json",
                        "trust": self.work / "ssh-trust.json",
                        "tracked-domain": self.config,
                    }[kind]
                    original = change.read_bytes()
                    if kind == "trust":
                        change.unlink()
                    else:
                        change.write_bytes(b"drift")
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.run_startup()
                self.assert_no_target()
                if change is not None:
                    change.write_bytes(original)
                    change.chmod(0o600)
                self.deployment.source_hash.return_value = "b" * 64
                self.selected["public_origin"] = self.cfg["app"]["bitwarden"][
                    "public_origin"
                ]

    def test_completed_identity_drift_holds_future_push_without_mutation(self):
        self.run_startup()
        self.execute.side_effect = lambda *args, **kwargs: {
            **self.current(),
            "image": "sha256:" + "9" * 64,
        }
        with self.assertRaises(ValueError):
            self.run_startup()
        self.assertTrue(self.execute.call_args.kwargs["observe"])
        self.assertTrue((self.work / "CONTINUATION-HOLD.json").exists())

    def test_packet_rejects_unbounded_operations_and_nonexact_identities(self):
        self.assertEqual(maintenance.packet(self.selected), self.selected)
        for change in (
            {"start": True},
            {"vmid": 900},
            {"revision": "main"},
            {"source_revision": "main"},
            {"container": {**self.selected["container"], "id": "short"}},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                maintenance.packet({**self.selected, **change})


if __name__ == "__main__":
    unittest.main()
