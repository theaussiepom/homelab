"""Current deployment safety without PVE, SSH, NAS or application contact."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy
import deployment_inputs as inputs
import deployment_state as state
import guest_contract as contract
import private_io as io
import proxmox_guest as pve
import plan_policy
from fixtures import guest, github_source
from test_plan import fixture as plan_fixture


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = guest(self.root)
        self.packet = self.root / "packet.json"
        self.value = {
            "schema": contract.SCHEMA,
            "enabled": True,
            "kind": "mariadb",
            "identity": "a" * 64,
            "files": {
                "site.json": json.dumps(self.cfg),
                "homelab.cnf": "retained listener\n",
            },
        }

    def save(self):
        self.packet.write_text(json.dumps(self.value))

    def test_previous_schema_and_disabled_selection_refuse_before_materialization(self):
        for change in [
            {"schema": "homelab-ordinary-deployment-v1"},
            {"enabled": False},
        ]:
            value = copy.deepcopy(self.value)
            value.update(change)
            self.packet.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                inputs.prepare(self.packet, self.root / "inputs")
            self.assertFalse((self.root / "inputs").exists())

    def test_current_definition_does_not_require_or_accept_installer_flags(self):
        self.assertEqual(contract.validate(self.cfg), 808)
        for key in [
            "new_target",
            "capture",
            "ha_http",
            "clean_install_confirmed",
            "installation",
        ]:
            value = copy.deepcopy(self.cfg)
            value["app"][key] = True
            with self.assertRaises(ValueError):
                contract.validate(value)

    def test_exact_private_preparation_repeats_and_incomplete_inputs_are_not_adopted(
        self,
    ):
        self.save()
        _, path = inputs.prepare(self.packet, self.root / "inputs")
        before = {p.name: p.read_bytes() for p in path.parent.iterdir()}
        inputs.prepare(self.packet, self.root / "inputs")
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in path.parent.iterdir()}
        )
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        (path.parent / "prepared.json").unlink()
        with self.assertRaises(ValueError):
            inputs.prepare(self.packet, self.root / "inputs")
        self.assertFalse((path.parent / "prepared.json").exists())

    def test_path_traversal_duplicate_json_and_symlink_inputs_are_refused(self):
        self.value["files"]["../escape"] = "invalid"
        self.save()
        with self.assertRaises(ValueError):
            inputs.prepare(self.packet, self.root / "inputs")
        self.packet.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            inputs.prepare(self.packet, self.root / "inputs")
        self.save()
        link = self.root / "link"
        link.symlink_to(self.packet)
        with self.assertRaises((ValueError, OSError)):
            inputs.prepare(link, self.root / "inputs")

    def test_target_identity_protected_guests_and_capability_drift_refuse(self):
        variants = [
            lambda c: c["app"].update(vmid=809),
            lambda c: c["guest"].update(vmid=900),
            lambda c: c["app"].update(address="198.18.25.9"),
            lambda c: c["deployment"].update(capabilities=["linux", "docker"]),
            lambda c: c["paths"].update(known_hosts=c["paths"]["api_token"]),
        ]
        for change in variants:
            value = copy.deepcopy(self.cfg)
            change(value)
            with self.assertRaises(ValueError):
                contract.validate(value)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.cfg = guest(self.root)
        self.cfg["paths"]["state_root"] = str(self.root)
        self.work = self.root / "808"
        self.work.mkdir(mode=0o700)
        (self.work / "terraform.tfstate").write_text("authoritative state")
        self.site = self.root / "site.json"
        self.site.write_text("{}")
        self.expected = {"vmid": 808, "site_sha256": "a" * 64}
        self.source, self.revisions = github_source(self.root)
        context = patch.dict(
            os.environ,
            {"GITHUB_SHA": self.revisions[0], "GITHUB_WORKSPACE": str(self.source)},
        )
        context.start()
        self.addCleanup(context.stop)
        for name, value in [
            ("prepare", (self.cfg, self.site)),
            ("binding", self.expected),
        ]:
            p = patch.object(inputs, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(
            os.environ,
            {
                "GITHUB_RUN_ID": "777",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_RUN_NUMBER": "777",
                "GITHUB_REPOSITORY": "example/private-site",
                "HOMELAB_DEPLOYMENT_WORKFLOW": "example/private-site/.github/workflows/deploy.yml@refs/heads/main",
            },
        )
        p.start()
        self.addCleanup(p.stop)
        self.infrastructure = patch.object(
            pve,
            "infrastructure",
            side_effect=lambda *args: {
                "changed": False,
                "created": False,
                "state_sha256": io.sha(self.work / "terraform.tfstate"),
            },
        )
        self.infra = self.infrastructure.start()
        self.addCleanup(self.infrastructure.stop)
        p = patch.object(
            deploy.ansible_guest,
            "run_phase",
            return_value={"status": "passed", "changed": False},
        )
        self.app = p.start()
        self.addCleanup(p.stop)

    def run_all(self):
        for phase in ["infrastructure", *contract.phases(self.cfg)]:
            deploy.run(phase, self.site)

    def test_preparation_precedes_app_and_unchanged_repeat_contacts_no_target(self):
        deploy.run("infrastructure", self.site)
        with self.assertRaises((ValueError, FileNotFoundError)):
            deploy.run("mariadb", self.site)
        self.app.assert_not_called()
        deploy.run("preparation", self.site)
        deploy.run("mariadb", self.site)
        for phase in ["infrastructure", "preparation", "mariadb"]:
            self.assertFalse(deploy.run(phase, self.site)["target_contacted"])
        self.assertEqual(self.infra.call_count, 1)
        self.assertEqual(self.app.call_count, 2)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_automation_and_dns_order_have_no_arbitrary_dag_or_bundled_phase(self):
        for name, phases in [
            ("automation", ["mqtt", "homeassistant", "node_red"]),
            ("dns", ["unbound", "pihole"]),
        ]:
            self.cfg["app"]["kind"] = name
            self.cfg["deployment"]["capabilities"] = ["linux", "docker"]
            # Reset only this test-owned completed attempt for an independent guest case.
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                root.chmod(0o700)
                self.cfg["paths"]["state_root"] = str(root)
                self.work = root / "808"
                self.work.mkdir(mode=0o700)
                (self.work / "terraform.tfstate").write_text("state")
                deploy.run("infrastructure", self.site)
                deploy.run("preparation", self.site)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    deploy.run(phases[-1], self.site)
                for phase in phases:
                    deploy.run(phase, self.site)
                self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_infrastructure_and_preparation_failures_hold_and_never_replay(self):
        self.infra.side_effect = ValueError("native failure")
        with self.assertRaises(ValueError):
            deploy.run("infrastructure", self.site)
        with self.assertRaises(ValueError):
            deploy.run("infrastructure", self.site)
        self.assertEqual(self.infra.call_count, 1)
        self.app.assert_not_called()

    def test_interrupted_application_is_durable_even_for_same_run(self):
        deploy.run("infrastructure", self.site)
        self.app.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            deploy.run("preparation", self.site)
        with self.assertRaises(ValueError):
            deploy.run("preparation", self.site)
        with self.assertRaises((ValueError, FileNotFoundError)):
            deploy.run("mariadb", self.site)
        self.assertEqual(self.app.call_count, 1)
        self.assertTrue((self.work / "ORDINARY-HOLD.json").exists())

    def test_another_run_and_input_state_drift_cannot_advance_an_attempt(self):
        deploy.run("infrastructure", self.site)
        held = (self.work / "ORDINARY-HOLD.json").read_bytes()
        with (
            patch.dict(
                os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
            ),
            self.assertRaises(ValueError),
        ):
            deploy.run("preparation", self.site)
        self.expected["site_sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            deploy.run("preparation", self.site)
        self.expected["site_sha256"] = "a" * 64
        (self.work / "terraform.tfstate").write_text("changed state")
        with self.assertRaises(ValueError):
            deploy.run("preparation", self.site)
        self.assertEqual((self.work / "ORDINARY-HOLD.json").read_bytes(), held)
        self.app.assert_not_called()

    def test_existing_and_group_holds_include_dangling_symlinks(self):
        for folder, name in [
            (self.work, "FOUNDATION-HOLD.json"),
            (self.root / "database-network-cutover-held", "HOLD.json"),
        ]:
            folder.mkdir(mode=0o700, exist_ok=True)
            hold = folder / name
            hold.symlink_to(folder / "absent")
            with self.assertRaises(ValueError):
                deploy.run("infrastructure", self.site)
            self.infra.assert_not_called()
            hold.unlink()

    def test_state_change_during_phase_preserves_the_hold_and_unfinished_phase(self):
        deploy.run("infrastructure", self.site)

        def change(*args):
            (self.work / "terraform.tfstate").write_text(
                "external change during application"
            )
            return {"status": "passed", "changed": False}

        self.app.side_effect = change
        with self.assertRaises(ValueError):
            deploy.run("preparation", self.site)
        self.assertTrue((self.work / "ORDINARY-HOLD.json").exists())
        self.assertFalse(
            (self.work / "ordinary-777-1/preparation-complete.json").exists()
        )

    def test_missing_backend_with_completed_custody_cannot_recreate_on_new_inputs(self):
        self.run_all()
        (self.work / "terraform.tfstate").unlink()
        self.expected["site_sha256"] = "b" * 64
        self.infra.side_effect = None
        self.infra.return_value = {
            "created": True,
            "changed": True,
            "state_sha256": "unwanted new backend",
        }
        with (
            patch.dict(
                os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
            ),
            self.assertRaises(ValueError),
        ):
            deploy.run("infrastructure", self.site)
        self.assertEqual(self.infra.call_count, 1)
        self.assertFalse((self.work / "ordinary-778-1").exists())

    def test_symlinked_backend_is_not_an_authoritative_state_file(self):
        (self.work / "terraform.tfstate").unlink()
        target = self.root / "other-state"
        target.write_text("unrelated backend")
        (self.work / "terraform.tfstate").symlink_to(target)
        with self.assertRaises(ValueError):
            deploy.run("infrastructure", self.site)
        self.infra.assert_not_called()
        self.assertEqual(target.read_text(), "unrelated backend")

    def test_missing_backend_preserves_each_kind_of_prior_custody(self):
        (self.work / "terraform.tfstate").unlink()
        for name in [
            "ordinary-complete.json",
            "ordinary-776-1",
            "ssh-trust.json",
            "host-key-evidence.json",
            "plan.json",
            "applied.json",
            "started.json",
            "rollout-complete.json",
            "foundation-complete.json",
            "terraform.tfstate.backup",
        ]:
            with self.subTest(name=name):
                evidence = self.work / name
                evidence.symlink_to(self.work / "absent")
                with self.assertRaises(ValueError):
                    with state.DeploymentAttempt(self.cfg, self.expected, []):
                        pass
                self.assertTrue(evidence.is_symlink())
                evidence.unlink()
        self.infra.assert_not_called()

    def test_empty_guest_custody_allows_first_creation_but_directory_backend_refuses(
        self,
    ):
        backend = self.work / "terraform.tfstate"
        backend.unlink()
        with state.DeploymentAttempt(self.cfg, self.expected, []):
            pass
        backend.mkdir()
        with self.assertRaises(ValueError):
            deploy.run("infrastructure", self.site)
        self.infra.assert_not_called()
        self.assertTrue(backend.is_dir())

    def test_locks_are_exclusive_and_released_after_exception(self):
        with state.DeploymentAttempt(
            self.cfg, self.expected, ["preparation", "mariadb"]
        ):
            with self.assertRaises(BlockingIOError):
                with state.DeploymentAttempt(
                    self.cfg, self.expected, ["preparation", "mariadb"]
                ):
                    pass
        with state.DeploymentAttempt(
            self.cfg, self.expected, ["preparation", "mariadb"]
        ):
            pass

    def test_changed_state_invalidates_a_completed_noop_and_retains_old_install_records(
        self,
    ):
        install = self.work / "rollout-complete.json"
        install.write_text("original installation evidence")
        self.run_all()
        (self.work / "terraform.tfstate").write_text("changed state")
        with patch.dict(
            os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
        ):
            deploy.run("infrastructure", self.site)
        self.assertEqual(self.infra.call_count, 2)
        self.assertEqual(install.read_text(), "original installation evidence")

    def test_new_merges_reconcile_and_older_or_replayed_runs_cannot_roll_back(self):
        self.run_all()
        old = (self.work / "ordinary-777-1/complete.json").read_bytes()
        with patch.dict(
            os.environ,
            {
                "GITHUB_RUN_ID": "778",
                "GITHUB_RUN_NUMBER": "778",
                "GITHUB_SHA": self.revisions[1],
            },
        ):
            self.run_all()
        self.assertEqual(self.infra.call_count, 2)
        self.assertEqual(self.app.call_count, 4)
        self.assertEqual((self.work / "ordinary-777-1/complete.json").read_bytes(), old)
        receipt = (self.work / "ordinary-complete.json").read_bytes()
        for metadata in (
            {"GITHUB_RUN_ID": "776", "GITHUB_RUN_NUMBER": "776"},
            {
                "GITHUB_RUN_ID": "778",
                "GITHUB_RUN_NUMBER": "778",
                "GITHUB_RUN_ATTEMPT": "2",
            },
            {
                "GITHUB_RUN_ID": "780",
                "GITHUB_RUN_NUMBER": "780",
                "GITHUB_SHA": self.revisions[0],
            },
            {
                "GITHUB_RUN_ID": "779",
                "GITHUB_RUN_NUMBER": "779",
                "HOMELAB_DEPLOYMENT_WORKFLOW": "other/site/.github/workflows/deploy.yml@refs/heads/main",
            },
        ):
            with patch.dict(os.environ, metadata), self.assertRaises(ValueError):
                deploy.run("infrastructure", self.site)
        self.assertEqual((self.work / "ordinary-complete.json").read_bytes(), receipt)
        self.assertEqual(self.infra.call_count, 2)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_missing_workflow_sequence_cannot_select_an_attempt(self):
        for metadata in (
            {"GITHUB_RUN_NUMBER": ""},
            {"GITHUB_SHA": ""},
            {"GITHUB_WORKSPACE": ""},
            {"GITHUB_REPOSITORY": ""},
            {"HOMELAB_DEPLOYMENT_WORKFLOW": ""},
        ):
            with patch.dict(os.environ, metadata), self.assertRaises(ValueError):
                deploy.run("infrastructure", self.site)
        self.infra.assert_not_called()
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_changed_backend_cannot_replay_a_completed_run(self):
        self.run_all()
        (self.work / "terraform.tfstate").write_bytes(b"changed outside this run")
        with self.assertRaisesRegex(ValueError, "existing attempt"):
            deploy.run("infrastructure", self.site)
        self.assertEqual(self.infra.call_count, 1)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())


class PlanTests(unittest.TestCase):
    def test_safe_updates_preserve_data_and_reject_drift_import_replacement_or_volume_changes(
        self,
    ):
        cfg = {"guest": {"vmid": 6100}, "site": {"node": "pve-lab"}}
        value = plan_fixture()
        for row in value["resource_changes"]:
            row["change"].update(
                actions=["no-op"], before=copy.deepcopy(row["change"]["after"])
            )
        plan_policy.check_plan(
            value, cfg["site"]["node"], cfg["guest"]["vmid"], existing=True
        )
        for mutate in [
            lambda v: v.update(resource_drift=[{}]),
            lambda v: v["resource_changes"][0]["change"].update(
                importing={"id": "6100"}
            ),
            lambda v: v["resource_changes"][0]["change"].update(
                actions=["delete", "create"]
            ),
            lambda v: v["resource_changes"][0]["change"]["after"].update(
                disk=[{"size": 999}]
            ),
        ]:
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaises(ValueError):
                plan_policy.check_plan(
                    changed, cfg["site"]["node"], cfg["guest"]["vmid"], existing=True
                )

    def test_fresh_creation_has_an_apply_window_before_trusted_identity_pinning(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                cfg["guest"]["vmid"] = cfg["app"]["vmid"] = 6100
                cfg["site"]["node"] = "pve-lab"
                work = root / "work"
                work.mkdir()
                operation = root / "attempt"
                operation.mkdir()
                (root / "api").write_text("fixture@pve!deploy=synthetic")
                (root / "api").chmod(0o600)

                def command(argv, env, log):
                    if "plan" in argv:
                        (operation / "guest.tfplan").write_bytes(b"saved-plan")
                    if "apply" in argv:
                        window = json.loads((operation / "apply-window.json").read_text())
                        self.assertEqual(window["plan_sha256"], io.sha(operation / "guest.tfplan"))
                        self.assertNotIn("finished_at_ns", window)
                        if failed:
                            raise ValueError("synthetic apply failure")
                        (work / "terraform.tfstate").write_text("created")

                def pin(cfg, directory, *args):
                    self.assertEqual(directory, operation)
                    window = json.loads((directory / "apply-window.json").read_text())
                    self.assertEqual(
                        window["plan_sha256"], io.sha(directory / "guest.tfplan")
                    )
                    self.assertLessEqual(window["started_at_ns"], window["finished_at_ns"])

                with (
                    patch.object(inputs, "binding", return_value={"approved": True}),
                    patch.object(pve, "backup"),
                    patch.object(pve, "quiet", side_effect=command),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value=json.dumps(plan_fixture()).encode(),
                    ),
                    patch.object(pve.guest_identity, "pin", side_effect=pin) as identity,
                ):
                    if failed:
                        with self.assertRaisesRegex(ValueError, "synthetic apply failure"):
                            pve.infrastructure(cfg, root / "site", work, operation, {"approved": True})
                        identity.assert_not_called()
                        window = json.loads((operation / "apply-window.json").read_text())
                        self.assertNotIn("finished_at_ns", window)
                        self.assertTrue((operation / "plan.json").is_file())
                    else:
                        self.assertTrue(
                            pve.infrastructure(
                                cfg, root / "site", work, operation, {"approved": True}
                            )["created"]
                        )
                        identity.assert_called_once()

    def test_radio_capability_brackets_api_reconciliation_without_api_device_ownership(
        self,
    ):
        for attached in (False, True):
            with self.subTest(attached=attached), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                cfg["guest"].update(
                    vmid=6100, serial_device={"path": "/dev/serial/by-id/usb-fixture"}
                )
                cfg["app"]["vmid"] = 6100
                cfg["site"]["node"] = "pve-lab"
                work, operation = root / "work", root / "attempt"
                work.mkdir()
                operation.mkdir()
                (work / "terraform.tfstate").write_bytes(b"existing backend")
                io.write_new(root / "api", b"fixture@pve!deploy=synthetic")
                value = plan_fixture()
                for row in value["resource_changes"]:
                    row["change"].update(
                        actions=["no-op"], before=copy.deepcopy(row["change"]["after"])
                    )
                events = []

                def command(argv, env, log):
                    events.append("plan" if "plan" in argv else "init")
                    self.assertNotIn("apply", argv)
                    variables = json.loads(
                        (operation / "tofu/site.auto.tfvars.json").read_text()
                    )
                    self.assertNotIn("serial_device", variables["guest"])
                    if "plan" in argv:
                        (operation / "guest.tfplan").write_bytes(b"saved plan")

                with (
                    patch.object(inputs, "binding", return_value={}),
                    patch.object(
                        pve.host_devices,
                        "check",
                        side_effect=lambda *_: events.append("check"),
                    ),
                    patch.object(
                        pve.host_devices,
                        "attach",
                        side_effect=lambda *_: (events.append("attach"), attached)[1],
                    ),
                    patch.object(
                        pve,
                        "backup",
                        side_effect=lambda _c, _s, label: events.append(label),
                    ),
                    patch.object(pve, "quiet", side_effect=command),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value=json.dumps(value).encode(),
                    ),
                ):
                    result = pve.infrastructure(cfg, root / "site", work, operation, {})
                self.assertEqual(
                    result,
                    {
                        "changed": attached,
                        "created": False,
                        "state_sha256": io.sha(work / "terraform.tfstate"),
                    },
                )
                self.assertEqual(
                    events,
                    [
                        "check",
                        "before-ordinary",
                        "init",
                        "plan",
                        "attach",
                        "after-ordinary",
                    ],
                )
                blocked = root / "blocked"
                blocked.mkdir()
                with (
                    patch.object(
                        pve.host_devices,
                        "check",
                        side_effect=ValueError("capability unavailable"),
                    ),
                    patch.object(pve, "backup") as backup,
                    patch.object(pve, "quiet") as run,
                    self.assertRaisesRegex(ValueError, "capability unavailable"),
                ):
                    pve.infrastructure(cfg, root / "site", work, blocked, {})
                backup.assert_not_called()
                run.assert_not_called()
                self.assertEqual(list(blocked.iterdir()), [])


class SecretMaterializationTests(unittest.TestCase):
    def test_effective_ca_and_database_configuration_changes_invalidate_the_binding(
        self,
    ):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            ca = root / "ca"
            ca.write_text("trusted fixture CA")
            configuration = root / "database.cnf"
            configuration.write_text("retained listener")
            cfg["app"]["database"]["config_files"] = [{"source": str(configuration)}]
            before = inputs.input_hashes(cfg)
            configuration.write_text("changed listener")
            self.assertNotEqual(inputs.input_hashes(cfg), before)
            configuration.write_text("retained listener")
            ca.write_text("changed trust")
            self.assertNotEqual(inputs.input_hashes(cfg), before)

    def test_runtime_token_remains_private_and_changed_token_cannot_replace_prepared_inputs(
        self,
    ):
        from test_render import fixture

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            kind = "automation"
            cfg["app"].pop("database")
            cfg["guest"]["memory_mib"] = cfg["app"]["memory_mib"] = 4096
            cfg["app"].update(
                kind=kind,
                node_red_authentication="authentik-oidc",
                exclusive_writer_confirmed=True,
                service_health_checks={
                    p: [{"name": p, "argv": ["true"]}]
                    for p in ["mqtt", "homeassistant", "node_red"]
                },
                required_paths=contract.BLUEPRINTS[kind]["required_paths"],
            )
            cfg["deployment"]["capabilities"] = ["linux", "docker"]
            destination = root / "inputs" / kind / ("a" * 64)
            cfg["app"]["stack_config"] = str(destination / "stack.json")
            packet = root / "packet.json"
            value = {
                "schema": contract.SCHEMA,
                "enabled": True,
                "kind": kind,
                "identity": "a" * 64,
                "files": {
                    "site.json": json.dumps(cfg),
                    "stack.json": json.dumps(fixture(kind)),
                },
            }
            packet.write_text(json.dumps(value))
            env = {"NODE_RED_API_TOKEN": "synthetic-runtime-token"}
            _, site = inputs.prepare(packet, root / "inputs", env)
            raw = (site.parent / "stack.json").read_bytes()
            self.assertIn(b"synthetic-runtime-token", raw)
            self.assertNotIn("synthetic-runtime-token", packet.read_text())
            inputs.prepare(packet, root / "inputs", env)
            with self.assertRaises(ValueError):
                inputs.prepare(
                    packet, root / "inputs", {"NODE_RED_API_TOKEN": "changed"}
                )
            self.assertEqual((site.parent / "stack.json").read_bytes(), raw)

    def test_evidence_log_drift_is_refused_before_subprocess(self):
        import commands

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "log"
            path.write_bytes(b"original evidence")
            path.chmod(0o644)
            with (
                patch.object(commands.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                commands.quiet(["fixture"], {}, path)
            self.assertEqual(path.read_bytes(), b"original evidence")
            run.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            link = Path(td) / "link"
            link.symlink_to(path)
            with (
                patch.object(commands.subprocess, "run") as run,
                self.assertRaises(OSError),
            ):
                commands.quiet(["fixture"], {}, link)
            run.assert_not_called()


class BackendBoundaryTests(unittest.TestCase):
    def test_recovery_refuses_a_symlinked_mount_and_another_filesystem(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"synthetic backend")
            actual_mount = root / "actual-nas"
            actual_mount.mkdir()
            mount = root / "nas"
            mount.symlink_to(actual_mount, target_is_directory=True)
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                self.assertRaises((ValueError, OSError)),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertEqual(list(actual_mount.iterdir()), [])
            mount.unlink()
            mount.mkdir()
            (mount / "backups").mkdir()
            original_fstat = pve.os.fstat
            calls = 0

            def filesystem_drift(fd):
                nonlocal calls
                info = original_fstat(fd)
                calls += 1
                if calls == 2:
                    values = list(info)
                    values[2] = info.st_dev + 1
                    return os.stat_result(values)
                return info

            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
                patch.object(pve.os, "fstat", side_effect=filesystem_drift),
                self.assertRaisesRegex(ValueError, "recovery filesystem"),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertFalse((mount / "backups/808").exists())

    def test_recovery_path_changes_cannot_redirect_writes_or_report_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"synthetic backend")
            destination = root / "nas/backups/808"
            destination.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            moved = destination.with_name("preserved")

            def changed_path(name, **options):
                destination.rename(moved)
                destination.symlink_to(outside, target_is_directory=True)
                return io.private_writer(name, **options)

            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
                patch.object(pve, "private_writer", side_effect=changed_path),
                self.assertRaises((ValueError, OSError)),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual(
                next(moved.glob("*.tfstate")).read_bytes(), b"synthetic backend"
            )

    def test_descriptor_relative_private_writes_refuse_path_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for path in ("../outside", str(root / "absolute"), "subdir/nested"):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        io.write_new(path, b"must not be written", dir_fd=descriptor)
                io.write_new("receipt", b"private evidence", dir_fd=descriptor)
                self.assertEqual(
                    io.sha("receipt", dir_fd=descriptor), io.digest(b"private evidence")
                )
                self.assertEqual({path.name for path in root.iterdir()}, {"receipt"})
            finally:
                os.close(descriptor)

    def test_recovery_refuses_destination_symlinks_before_writing(self):
        for selected in ("backups", "backups/808"):
            with self.subTest(path=selected), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                mount = root / "nas"
                mount.mkdir()
                outside = root / "outside"
                outside.mkdir()
                link = mount / selected
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside, target_is_directory=True)
                source = root / "terraform.tfstate"
                source.write_bytes(b"synthetic backend")
                with (
                    patch.object(pve.os.path, "ismount", return_value=True),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                    ),
                    self.assertRaises((ValueError, OSError)),
                ):
                    pve.backup(cfg, source, "fixture")
                self.assertEqual(list(outside.iterdir()), [])
                self.assertTrue(link.is_symlink())

    def test_token_bearing_api_requests_never_follow_redirects(self):
        with self.assertRaises(pve.InputNeeded):
            pve.RefuseRedirects().redirect_request(
                None, None, 302, "redirect", {}, "https://other.invalid"
            )

    def test_state_recovery_requires_the_selected_nas_and_proves_readback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"retained backend bytes")
            with (
                patch.object(pve.os.path, "ismount", return_value=False),
                self.assertRaises(ValueError),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertFalse((root / "nas").exists())
            (root / "nas").mkdir()
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess, "check_output", return_value="nfs4 wrong:/source\n"
                ),
                self.assertRaises(ValueError),
            ):
                pve.backup(cfg, source, "fixture")
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
            ):
                pve.backup(cfg, source, "fixture")
            copied = list((root / "nas/backups/808").glob("*.tfstate"))
            self.assertEqual(len(copied), 1)
            self.assertEqual(copied[0].read_bytes(), source.read_bytes())
            self.assertEqual(copied[0].stat().st_mode & 0o777, 0o600)

    def test_per_guest_ssh_trust_cannot_change_or_normalize_permission_drift(self):
        from test_guest_identity import public_key
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            Path(cfg["paths"]["known_hosts"]).touch(mode=0o600)

            def result(byte):
                return subprocess.CompletedProcess(
                    [],
                    0,
                    cfg["app"]["address"] + " ssh-ed25519 " + public_key(byte) + "\n",
                    "",
                )

            with patch.object(pve.subprocess, "run", return_value=result(1)):
                pve.guest_trust(cfg, root)
                pve.guest_trust(cfg, root)
            record = root / "ssh-trust.json"
            original = record.read_bytes()
            with (
                patch.object(pve.subprocess, "run", return_value=result(2)),
                self.assertRaises(ValueError),
            ):
                pve.guest_trust(cfg, root)
            self.assertEqual(record.read_bytes(), original)
            record.chmod(0o644)
            with (
                patch.object(pve.subprocess, "run", return_value=result(1)),
                self.assertRaises(ValueError),
            ):
                pve.guest_trust(cfg, root)
            self.assertEqual(record.stat().st_mode & 0o777, 0o644)
