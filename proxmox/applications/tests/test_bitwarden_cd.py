"""Synthetic actual-CD admission: same image/credentials, separate DB restore, no replay."""

import copy, hashlib, json, os
from pathlib import Path
import sys, tempfile, unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden_cd, bitwarden_migration, deploy, render
from test_deploy import fixture as site_fixture


def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def setup(root):
    destination = root / "inputs" / "bitwarden"
    destination.parent.mkdir(mode=0o700)
    source = {
        "PUID": "1000",
        "PGID": "1000",
        "BW_DOMAIN": "vault.example.invalid",
        "BW_DB_PROVIDER": "mysql",
        "BW_DB_SERVER": "old-db",
        "BW_DB_DATABASE": "bitwarden_vault",
        "BW_DB_USERNAME": "synthetic-user",
        "BW_DB_PASSWORD": "synthetic-$-quote-\"-apostrophe-'-backslash-\\",
        "BW_INSTALLATION_ID": "00000000-0000-4000-8000-000000000001",
        "BW_INSTALLATION_KEY": "synthetic-installation-key",
        "globalSettings__identityServer__certificatePassword": "synthetic-certificate-password",
        "globalSettings__mail__smtp__host": "smtp.example.invalid",
        "globalSettings__mail__smtp__password": "",
    }
    envhash = bitwarden_migration.environment_hash(source)
    cfg = site_fixture(root)
    cfg["guest"]["interfaces"][0]["ipv4"] = "10.88.100.20/24"
    cfg["app"]["address"] = "10.88.100.20"
    cfg["app"].update(
        kind="bitwarden",
        packages=["mariadb-client-core=1:11.8.6-0+deb13u1"],
        stack_config=str(destination / "stack.json"),
        exclusive_writer_confirmed=True,
        capture={
            "path": str(root / "capture.tar"),
            "sha256": "c" * 64,
            "coherent": True,
        },
    )
    private(root / "ca", b"synthetic public CA")
    cfg["app"]["bitwarden"] = {
        "schema": "homelab-bitwarden-admission-v1",
        "public_origin": "https://vault.example.invalid",
        "issuer": "http://localhost",
        "source_environment_sha256": envhash,
        "source_backup_sha256": "b" * 64,
        "database_guest": 206,
        "restore_receipt": {"path": str(root / "restore.json"), "sha256": None},
        "prerequisites_receipt": {
            "path": str(root / "prerequisites.json"),
            "sha256": None,
        },
    }
    cfg["app"]["discovery_routes"] = [
        {
            "name": "bitwarden",
            "host": "vault.example.invalid",
            "url": "http://10.88.100.20:8080",
        }
    ]
    cfg["app"]["health_checks"] = [
        {
            "name": "Bitwarden alive/config/identity",
            "argv": [
                "python3",
                "/opt/homelab-app/bitwarden.py",
                "--origin",
                "http://10.88.100.20:8080",
                "--issuer",
                "http://localhost",
                "--backend",
            ],
            "expect": '"status": "passed"',
        }
    ]
    stack = {
        "kind": "bitwarden",
        "guest_memory_mib": 4096,
        "timezone": "Etc/UTC",
        "bitwarden": {
            "schema": "homelab-bitwarden-migration-v1",
            "bind_address": "10.88.100.20",
            "source_image_id": "sha256:" + "a" * 64,
            "source_database_server": "old-db",
            "database_server": "10.88.100.24",
            "database_provider": "mysql",
            "database_name": "bitwarden_vault",
            "data_uid": 1000,
            "data_gid": 1000,
        },
        "services": {
            "bitwarden": {
                "image": "ghcr.io/bitwarden/lite@sha256:" + "1" * 64,
                "memory_mib": 1024,
                "cpus": 1,
                "pids_limit": 256,
                "restart": "no",
                "environment": {},
            }
        },
    }
    restore = {
        "schema": "homelab-bitwarden-db-restore-v2",
        "database_guest": 206,
        "database_server": "10.88.100.24",
        "database_name": "bitwarden_vault",
        "source_backup_sha256": "b" * 64,
        "capture_sha256": "c" * 64,
        "source_environment_sha256": envhash,
        "source_image_id": "sha256:" + "a" * 64,
        "database_client_address": "10.88.100.20",
        "writer_fenced": True,
        "checks": {
            "schema_coverage": "passed",
            "data_validation": "passed",
            "retained_account_definition": "passed",
        },
    }
    prerequisites = {
        "schema": "homelab-bitwarden-prerequisites-v1",
        "node": cfg["site"]["node"],
        "vmid": cfg["guest"]["vmid"],
        "backend_address": "10.88.100.20",
        "public_origin": "https://vault.example.invalid",
        "checks": {
            "bootstrap_grant": "passed",
            "discovery_scope": "passed",
            "ingress_backend_allowance": "passed",
            "dns_tls_plan": "reviewed",
        },
    }
    for key, value in [
        ("restore_receipt", restore),
        ("prerequisites_receipt", prerequisites),
    ]:
        data = bitwarden_migration.encoded(value)
        row = cfg["app"]["bitwarden"][key]
        private(Path(row["path"]), data)
        row["sha256"] = hashlib.sha256(data).hexdigest()
        private(bitwarden_migration.nas_receipt(cfg, key), data)
    config = {
        "schema": "homelab-bitwarden-deployment-v1",
        "enabled": True,
        "site": cfg,
        "stack": stack,
        "approved_plan_sha256": None,
    }
    path = root / "deployment.json"
    private(path, bitwarden_migration.encoded(config))
    return (
        config,
        path,
        destination,
        {"BITWARDEN_RUNTIME_JSON": json.dumps(source)},
        source,
    )


class CDTests(unittest.TestCase):
    def test_shared_installer_cannot_skip_admission_when_stack_path_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            config, _, _, _, _ = setup(Path(d))
            cfg = config["site"]
            cfg["app"].pop("stack_config")
            with patch.object(
                deploy, "api_get", side_effect=AssertionError("no target access")
            ) as api:
                with self.assertRaisesRegex(deploy.InputNeeded, "stack"):
                    deploy.validate(cfg)
                api.assert_not_called()

    def test_shared_installer_checks_render_budget_before_any_native_planning(self):
        with tempfile.TemporaryDirectory() as d:
            _, path, dest, environment, _ = setup(Path(d))
            cfg, _ = bitwarden_cd.prepare_inputs(path, dest, environment)
            stack_path = dest / "stack.json"
            stack = json.loads(stack_path.read_text())
            stack["services"]["bitwarden"]["memory_mib"] = cfg["app"]["memory_mib"]
            private(stack_path, bitwarden_migration.encoded(stack))
            with patch.object(
                deploy, "api_get", side_effect=AssertionError("no target access")
            ) as api:
                with self.assertRaisesRegex(ValueError, "256 MiB"):
                    deploy.validate(cfg)
                api.assert_not_called()

    def test_persisted_stack_render_must_match_the_preflight_before_native_work(self):
        with tempfile.TemporaryDirectory() as d:
            _, path, dest, environment, _ = setup(Path(d))
            with patch.object(
                bitwarden_cd.render,
                "compose",
                side_effect=[{"synthetic": 1}, {"synthetic": 1}, {"synthetic": 2}],
            ):
                with self.assertRaisesRegex(
                    ValueError, "Persisted stack render differs"
                ):
                    bitwarden_cd.prepare_inputs(path, dest, environment)
            self.assertTrue((dest / "prepared.json").exists())

    def test_restore_account_definition_must_bind_the_actual_database_client_interface(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            cfg = config["site"]
            row = cfg["app"]["bitwarden"]["restore_receipt"]
            record = json.loads(Path(row["path"]).read_text())
            record["database_client_address"] = "10.88.100.99"
            raw = bitwarden_migration.encoded(record)
            private(Path(row["path"]), raw)
            private(bitwarden_migration.nas_receipt(cfg, "restore_receipt"), raw)
            row["sha256"] = hashlib.sha256(raw).hexdigest()
            path.write_bytes(bitwarden_migration.encoded(config))
            with self.assertRaisesRegex(ValueError, "does not match"):
                bitwarden_cd.prepare_inputs(path, dest, environment)
            self.assertFalse(dest.exists())

    def test_database_query_proof_is_required_even_when_shared_installer_reports_success(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            config["approved_plan_sha256"] = "d" * 64
            path.write_bytes(bitwarden_migration.encoded(config))
            engine = Mock()
            engine.validate = deploy.validate
            engine.source_hash.return_value = "f" * 64
            engine.input_hashes = deploy.input_hashes
            engine.execute.return_value = {
                "vmid": config["site"]["guest"]["vmid"],
                "status": "passed",
            }
            engine.sha = deploy.sha
            work = Path(config["site"]["paths"]["state_root"]) / str(
                config["site"]["guest"]["vmid"]
            )
            private(work / "terraform.tfstate", b"synthetic state")
            private(work / "rollout-complete.json", b"synthetic rollout")
            (
                Path(config["site"]["paths"]["backup_directory"])
                / str(config["site"]["guest"]["vmid"])
            ).mkdir(parents=True, mode=0o700)
            with self.assertRaises((ValueError, FileNotFoundError)):
                bitwarden_cd.run("deploy", path, dest, environment, engine)
            self.assertFalse((work / "bitwarden-complete.json").exists())
            self.assertTrue((work / "BITWARDEN-CD-HOLD.json").exists())

    def test_disabled_packet_cannot_create_inputs_or_read_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / "disabled.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "homelab-bitwarden-deployment-v1",
                        "enabled": False,
                        "site": None,
                        "stack": None,
                        "approved_plan_sha256": None,
                    }
                )
            )
            with self.assertRaises(ValueError):
                bitwarden_cd.prepare_inputs(path, root / "missing", {})
            self.assertFalse((root / "missing").exists())

    def test_same_credentials_survive_with_only_database_endpoint_changed_and_are_bound(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, source = setup(Path(d))
            cfg, site = bitwarden_cd.prepare_inputs(path, dest, environment)
            stack = json.loads((dest / "stack.json").read_text())
            actual = stack["services"]["bitwarden"]["environment"]
            self.assertEqual(actual, dict(source, BW_DB_SERVER="10.88.100.24"))
            document = render.compose(stack)
            self.assertEqual(
                document["services"]["bitwarden"]["environment"]["BW_DB_PASSWORD"],
                source["BW_DB_PASSWORD"].replace("$", "$$"),
            )
            self.assertNotIn("env_file", document["services"]["bitwarden"])
            self.assertNotIn("TZ", document["services"]["bitwarden"]["environment"])
            self.assertEqual(deploy.validate(cfg), cfg["guest"]["vmid"])
            hashes = deploy.input_hashes(cfg)
            self.assertIn(cfg["app"]["bitwarden"]["restore_receipt"]["path"], hashes)
            self.assertIn(
                str(bitwarden_migration.nas_receipt(cfg, "restore_receipt")), hashes
            )
            environment["BITWARDEN_RUNTIME_JSON"] = json.dumps(
                dict(source, BW_DB_PASSWORD="rotated")
            )
            with self.assertRaises(ValueError):
                bitwarden_cd.prepare_inputs(path, dest, environment)

    def test_image_default_cannot_change_original_numeric_owner(self):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, source = setup(Path(d))
            source.pop("PUID")
            config["site"]["app"]["bitwarden"]["source_environment_sha256"] = (
                bitwarden_migration.environment_hash(source)
            )
            with self.assertRaisesRegex(ValueError, "UID/GID"):
                bitwarden_migration.runtime_environment(
                    config["site"], config["stack"], source
                )

    def test_private_runtime_file_and_shared_contract_are_bound_without_new_cloud_secrets(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, source = setup(Path(d))
            root = Path(d)
            runtime = root / "runtime.json"
            private(runtime, bitwarden_migration.encoded(source))
            contract = root / "network.json"
            private(contract, b'{"synthetic":"network"}\n')
            config["site"]["app"]["network_contract"] = {
                "path": str(contract),
                "sha256": deploy.sha(contract),
                "source_revision": "e" * 40,
            }
            path.write_bytes(bitwarden_migration.encoded(config))
            cfg, _ = bitwarden_cd.prepare_inputs(path, dest, {}, runtime_file=runtime)
            self.assertIn(str(contract), deploy.input_hashes(cfg))
            with self.assertRaisesRegex(ValueError, "one private runtime"):
                bitwarden_cd.prepare_inputs(
                    path, dest, environment, runtime_file=runtime
                )
            contract.write_bytes(b'{"synthetic":"drift"}\n')
            with self.assertRaisesRegex(ValueError, "contract drifted"):
                bitwarden_cd.prepare_inputs(path, dest, {}, runtime_file=runtime)

    def test_invalid_container_budget_stops_before_private_inputs_or_native_work(self):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            config["stack"]["services"]["bitwarden"]["memory_mib"] = config["site"][
                "guest"
            ]["memory_mib"]
            path.write_bytes(bitwarden_migration.encoded(config))
            with self.assertRaisesRegex(ValueError, "256 MiB"):
                bitwarden_cd.prepare_inputs(path, dest, environment)
            self.assertFalse(dest.exists())

    def test_restore_or_prerequisite_drift_stops_before_any_deployment(self):
        for key in ("restore_receipt", "prerequisites_receipt"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as d:
                config, path, dest, environment, _ = setup(Path(d))
                Path(config["site"]["app"]["bitwarden"][key]["path"]).write_text("{}")
                with self.assertRaises(ValueError):
                    bitwarden_cd.prepare_inputs(path, dest, environment)
                self.assertFalse(dest.exists())

    def test_latest_reference_requires_the_observed_source_image_identity(self):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            config["stack"]["services"]["bitwarden"][
                "image"
            ] = "ghcr.io/bitwarden/lite:latest"
            path.write_bytes(bitwarden_migration.encoded(config))
            bitwarden_cd.prepare_inputs(path, dest, environment)
            config["stack"]["bitwarden"]["source_image_id"] = "unknown"
            path.write_bytes(bitwarden_migration.encoded(config))
            with self.assertRaises(ValueError):
                bitwarden_cd.prepare_inputs(path, dest, environment)

    def test_incomplete_input_directory_is_preserved_and_never_filled(self):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            dest.mkdir(mode=0o700)
            (dest / "partial").write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                bitwarden_cd.prepare_inputs(path, dest, environment)
            self.assertEqual({p.name for p in dest.iterdir()}, {"partial"})

    def test_hostname_cutover_and_invented_health_cannot_enter_this_migration(self):
        for key in ("discovery_routes", "health_checks"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as d:
                config, path, dest, environment, _ = setup(Path(d))
                if key == "discovery_routes":
                    config["site"]["app"][key][0]["host"] = "new.example.invalid"
                else:
                    config["site"]["app"][key][0]["argv"] = ["true"]
                path.write_bytes(bitwarden_migration.encoded(config))
                with self.assertRaises(ValueError):
                    bitwarden_cd.prepare_inputs(path, dest, environment)

    def test_native_operations_require_an_exact_reviewed_plan_and_keep_failure_hold(
        self,
    ):
        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            engine = Mock()
            engine.validate = deploy.validate
            engine.source_hash.return_value = "f" * 64
            engine.input_hashes = deploy.input_hashes
            engine.sha = deploy.sha
            with self.assertRaises(ValueError):
                bitwarden_cd.run("deploy", path, dest, environment, engine)
            engine.execute.assert_not_called()
            config["approved_plan_sha256"] = "d" * 64
            path.write_bytes(bitwarden_migration.encoded(config))
            engine.execute.side_effect = RuntimeError("synthetic failed native command")
            with self.assertRaises(RuntimeError):
                bitwarden_cd.run("deploy", path, dest, environment, engine)
            hold = (
                Path(config["site"]["paths"]["state_root"])
                / str(config["site"]["guest"]["vmid"])
                / "BITWARDEN-CD-HOLD.json"
            )
            self.assertTrue(hold.exists())
            engine.execute.reset_mock()
            with self.assertRaises(ValueError):
                bitwarden_cd.run("deploy", path, dest, environment, engine)
            engine.execute.assert_not_called()

    def test_reviewed_plan_uses_common_deploy_once_then_only_verifies(self):
        from test_plan import fixture as plan_fixture

        with tempfile.TemporaryDirectory() as d:
            config, path, dest, environment, _ = setup(Path(d))
            cfg = config["site"]
            # Git tracks non-secret source as 0644; only generated runtime inputs/receipts require 0600.
            path.chmod(0o644)
            work = Path(cfg["paths"]["state_root"]) / str(cfg["guest"]["vmid"])
            engine = Mock()
            engine.validate = deploy.validate
            engine.source_hash.return_value = "f" * 64
            engine.input_hashes = deploy.input_hashes
            engine.sha = deploy.sha
            engine.check_merge_create_plan = deploy.check_merge_create_plan
            selected = hashlib.sha256(b"synthetic saved plan").hexdigest()

            def execute(phase, site, approved=None):
                if phase == "plan":
                    plan = plan_fixture()
                    for row in plan["resource_changes"]:
                        row["change"]["after"]["node_name"] = cfg["site"]["node"]
                        for key in ("vm_id", "container_id"):
                            if key in row["change"]["after"]:
                                row["change"]["after"][key] = cfg["guest"]["vmid"]
                    private(
                        work / "guest.tfplan.json", bitwarden_migration.encoded(plan)
                    )
                    private(work / "guest.tfplan", b"synthetic saved plan")
                    return {
                        "vmid": cfg["guest"]["vmid"],
                        "plan_sha256": selected,
                        "creates_guest": True,
                    }
                if phase == "deploy":
                    self.assertEqual(approved, selected)
                    private(work / "terraform.tfstate", b"synthetic private state")
                    private(work / "rollout-complete.json", b'{"status":"passed"}')
                    private(
                        work / "rendered" / "bitwarden-database-query.json",
                        bitwarden_migration.encoded(
                            bitwarden_migration.database_query_record(
                                cfg, config["stack"]
                            )
                        ),
                    )
                    (
                        Path(cfg["paths"]["backup_directory"])
                        / str(cfg["guest"]["vmid"])
                    ).mkdir(mode=0o700)
                return {"vmid": cfg["guest"]["vmid"], "status": "passed", "step": phase}

            engine.execute.side_effect = execute
            plan = bitwarden_cd.run("plan", path, dest, environment, engine)
            config["approved_plan_sha256"] = plan["plan_sha256"]
            path.write_bytes(bitwarden_migration.encoded(config))
            bitwarden_cd.run("deploy", path, dest, environment, engine)
            bitwarden_cd.run("deploy", path, dest, environment, engine)
            self.assertEqual(
                [c.args[0] for c in engine.execute.call_args_list],
                ["plan", "deploy", "verify"],
            )
            self.assertTrue((work / "bitwarden-complete.json").is_file())
            self.assertFalse((work / "BITWARDEN-CD-HOLD.json").exists())


if __name__ == "__main__":
    unittest.main()
