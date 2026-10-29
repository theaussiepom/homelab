"""Shared route rendering and private artifact/evidence custody."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import render
import private_io
from test_foundation import fixture
from test_plan import fixture as plan_fixture


class StrictCleanupTests(unittest.TestCase):
    def test_provider_fixture_uses_the_shared_route_contract(self):
        import provider_fixture

        notes = provider_fixture.fixture_notes()
        self.assertEqual(set(notes), {"authentik", "pgadmin", "node-red"})
        node = notes["node-red"]
        self.assertIn(
            "traefik.http.routers.node-red.middlewares: security-headers@file", node
        )
        self.assertIn(
            "traefik.http.services.node-red.loadbalancer.server.url: http://127.0.0.1:1880",
            node,
        )

    def test_rendering_does_not_repair_private_artifact_permission_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = fixture(directory, "ingress")
            source = root / "stack.json"
            source.write_text(json.dumps(cfg))
            output = root / "rendered"
            command = [
                sys.executable,
                str(Path(render.__file__)),
                "--config",
                str(source),
                "--output",
                str(output),
            ]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            artifact = output / "traefik.yml"
            artifact.chmod(0o644)
            before = artifact.read_bytes()
            stamps = {p.name: p.stat().st_mtime_ns for p in output.iterdir()}
            repeated = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(artifact.read_bytes(), before)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o644)
            self.assertEqual(
                stamps, {p.name: p.stat().st_mtime_ns for p in output.iterdir()}
            )

    def test_json_writer_refuses_drift_before_truncating_the_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(b"original evidence")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                private_io.write(path, {"replacement": True})
            self.assertEqual(path.read_bytes(), b"original evidence")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_import_metadata_is_refused_by_the_authoritative_policy(self):
        import plan_policy

        value = plan_fixture()
        value["resource_changes"][0]["change"]["importing"] = {"id": "6100"}
        with self.assertRaises(ValueError):
            plan_policy.check_plan(value, "pve-lab", 6100, existing=False)
