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
        directory = self.root / ".github/workflows"
        directory.mkdir(parents=True)
        self.phase = directory / "phase.yml"
        self.phase.write_text("jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@" + "1" * 40 + "\n")
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
        self.assertEqual(first["deploy.yml"]["jobs"]["web"]["needs"], ["selection", "database"])
        self.catalogue["web"]["applications"].append("verify")
        self.catalogue["web"]["application_names"]["verify"] = "Verify"
        self.manifest["guests"]["web"]["depends_on"] = []
        self.write_manifest()
        current = workflows.models(self.root)
        self.assertEqual(current["deploy.yml"]["jobs"]["web"]["needs"], ["selection"])
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
        self.assertEqual(current["deploy.yml"]["jobs"]["worker"]["needs"], ["selection", "database"])
        self.assertIn(
            "!contains(fromJSON(inputs.disabled || '[]'), 'worker')",
            current["deploy.yml"]["jobs"]["worker"]["if"],
        )

    def test_generated_selection_gate_rejects_invalid_lists_before_any_guest_can_skip(self):
        import json
        import os
        import subprocess

        model = workflows.models(self.root)["deploy.yml"]
        gate = model["jobs"]["selection"]
        self.assertEqual(gate["runs-on"], "ubuntu-24.04")
        self.assertEqual(gate["if"], workflows.PRIVATE_MAIN)
        self.assertNotIn("secrets", gate)
        self.assertNotIn("environment", gate)
        step = gate["steps"][0]
        for guest in self.manifest["guests"]:
            self.assertIn("selection", model["jobs"][guest]["needs"])
        for disabled, expected in [
            ("", 0), ("[]", 0), ('["web"]', 0),
            ('["database", "web"]', 0),
            ('["database"]', 1), ('["unknown"]', 1),
            ('["web", "web"]', 1), ('["database", "web", "unknown"]', 1),
            ('[1]', 1), ('{}', 1), ('null', 1), ('broken', 1),
        ]:
            with self.subTest(disabled=disabled):
                environment = dict(os.environ, **dict(step["env"], DISABLED=disabled))
                result = subprocess.run(
                    ["bash", "-e", "-c", step["run"]], env=environment,
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                try:
                    workflows.compiler.selection(self.manifest, workflows.compiler.parse_disabled(disabled))
                except (ValueError, TypeError):
                    compiler_status = 1
                else:
                    compiler_status = 0
                self.assertEqual(result.returncode, compiler_status)
        self.assertEqual(json.loads(step["env"]["DEPENDENCIES"]),
                         {name: row["depends_on"] for name, row in self.manifest["guests"].items()})

    def test_guest_names_cannot_replace_the_selection_gate(self):
        self.catalogue["selection"] = self.catalogue.pop("web")
        self.manifest["guests"]["selection"] = self.manifest["guests"].pop("web")
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "safe guest workflow identifier"):
            workflows.models(self.root)

    def test_check_reports_missing_changed_and_extra_files_without_writing(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            workflows.synchronize(self.root, check=True)
        result = workflows.synchronize(self.root, check=False)
        self.assertEqual(result, {"workflows": 4, "changed": 4})
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
        self.assertFalse((self.root / ".github/workflows/deploy.yml").exists())
        self.assertTrue(self.phase.is_file())

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

    def test_phase_selection_is_preserved_and_required_without_guessing_a_pin(self):
        current = workflows.models(self.root)
        self.assertEqual(current["phase.yml"]["jobs"]["run"]["uses"],
                         "example/framework/.github/workflows/guest-phase.yml@" + "1" * 40)
        self.phase.unlink()
        with self.assertRaisesRegex(ValueError, "regular selected framework phase"):
            workflows.models(self.root)
        outside = self.root / "outside-phase.yml"
        outside.write_text("preserve source")
        self.phase.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular selected framework phase"):
            workflows.models(self.root)
        self.assertEqual(outside.read_text(), "preserve source")
