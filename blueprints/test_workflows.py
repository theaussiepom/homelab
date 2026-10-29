"""Generated job graphs follow declarative edits; stale checks never mutate source."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import workflows


CATALOGUE = {
    "database": {
        "name": "Database",
        "applications": ["database"],
        "application_names": {"database": "Database"},
    },
    "web": {
        "name": "Web",
        "applications": ["web"],
        "application_names": {"web": "Web"},
    },
}


def manifest():
    return {
        "schema": "homelab-stack-v2",
        "routes": {},
        "values": {},
        "guests": {
            "database": {"depends_on": [], "prerequisites": []},
            "web": {"depends_on": ["database"], "prerequisites": []},
        },
    }


class WorkflowGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalogue = copy.deepcopy(CATALOGUE)
        self.manifest = manifest()
        self.write_manifest()
        patcher = patch.object(workflows.compiler, "CATALOGUE", self.catalogue)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_manifest(self):
        import json

        (self.root / "stack.json").write_text(json.dumps(self.manifest))

    def test_declarative_phase_and_dependency_edits_change_the_actual_job_graph(self):
        first = workflows.models(self.root)
        self.assertEqual(
            first["deploy.yml"]["on"]["workflow_call"]["inputs"]["disabled"],
            {
                "type": "string",
                "required": False,
                "default": "[]",
            },
        )
        self.assertEqual(first["deploy.yml"]["jobs"]["web"]["needs"], ["database"])
        self.catalogue["web"]["applications"].append("verify")
        self.catalogue["web"]["application_names"]["verify"] = "Verify"
        self.manifest["guests"]["web"]["depends_on"] = []
        self.write_manifest()
        current = workflows.models(self.root)
        self.assertNotIn("needs", current["deploy.yml"]["jobs"]["web"])
        jobs = current["guest-web.yml"]["jobs"]
        self.assertEqual(list(jobs), ["infrastructure", "preparation", "web", "verify"])
        self.assertEqual(jobs["verify"]["needs"], "web")
        self.assertEqual(jobs["verify"]["with"]["phase"], "verify")
        self.assertEqual(jobs["verify"]["uses"], "./.github/workflows/phase.yml")

    def test_new_guest_metadata_adds_a_permanent_workflow_without_generator_changes(
        self,
    ):
        self.catalogue["worker"] = {
            "name": "Worker",
            "applications": ["worker"],
            "application_names": {"worker": "Worker"},
        }
        self.manifest["guests"]["worker"] = {
            "depends_on": ["database"],
            "prerequisites": [],
        }
        self.write_manifest()
        current = workflows.models(self.root)
        self.assertIn("guest-worker.yml", current)
        self.assertEqual(current["deploy.yml"]["jobs"]["worker"]["needs"], ["database"])
        self.assertIn(
            "!contains(fromJSON(inputs.disabled || '[]'), 'worker')",
            current["deploy.yml"]["jobs"]["worker"]["if"],
        )

    def test_check_reports_missing_changed_and_extra_files_without_writing(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            workflows.synchronize(self.root, check=True)
        result = workflows.synchronize(self.root, check=False)
        self.assertEqual(result, {"workflows": 3, "changed": 3})
        self.assertEqual(workflows.synchronize(self.root, check=False)["changed"], 0)
        directory = self.root / ".github/workflows"
        path = directory / "guest-web.yml"
        path.write_text("unexpected change\n")
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        with self.assertRaisesRegex(ValueError, "guest-web.yml"):
            workflows.synchronize(self.root, check=True)
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
        extra = directory / "guest-obsolete.yaml"
        extra.write_text("preserve for explicit removal\n")
        with self.assertRaisesRegex(ValueError, "obsolete"):
            workflows.synchronize(self.root, check=False)
        self.assertEqual(path.read_bytes(), before[path.name])
        self.assertTrue(extra.exists())

    def test_missing_display_metadata_has_no_compatibility_default(self):
        del self.catalogue["web"]["name"]
        with self.assertRaisesRegex(ValueError, "current blueprint metadata"):
            workflows.synchronize(self.root, check=False)
        self.assertFalse((self.root / ".github").exists())

    def test_generated_paths_cannot_overwrite_symlink_targets(self):
        workflows.synchronize(self.root, check=False)
        outside = self.root / "manual.yml"
        outside.write_text("manual workflow\n")
        path = self.root / ".github/workflows/guest-web.yml"
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular files"):
            workflows.synchronize(self.root, check=False)
        self.assertEqual(outside.read_text(), "manual workflow\n")
        self.assertTrue(path.is_symlink())

    def test_generator_cli_preserves_stale_source_and_checks_current_output(self):
        import sys
        import runpy

        with patch.object(sys, "argv", ["workflows", "--stack", str(self.root)]):
            workflows.main()
        with patch.object(
            sys, "argv", ["workflows", "--stack", str(self.root), "--check"]
        ):
            workflows.main()
        (self.root / ".github/workflows/deploy.yml").write_text("stale")
        with (
            patch.object(
                sys, "argv", ["workflows", "--stack", str(self.root), "--check"]
            ),
            self.assertRaises(SystemExit),
        ):
            workflows.main()
        with (
            patch.object(sys, "argv", ["workflows", "--stack", str(self.root)]),
            patch.object(workflows.compiler, "CATALOGUE", self.catalogue),
        ):
            runpy.run_path(str(Path(workflows.__file__)), run_name="__main__")
