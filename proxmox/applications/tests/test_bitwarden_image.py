"""Retained Bitwarden content identity; real local Ansible with an inert Docker CLI."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import render
import test_bitwarden_runtime as runtime_cases


class RetainedImageTests(unittest.TestCase):
    def stack(self):
        case = runtime_cases.RuntimeTests(); case.setUp()
        self.addCleanup(case.doCleanups)
        return copy.deepcopy(case.stack)

    def test_mutable_source_reference_renders_only_the_expected_retained_id(self):
        stack = self.stack(); original = copy.deepcopy(stack)
        self.assertEqual(render.compose(stack)["services"]["bitwarden"]["image"], stack["bitwarden"]["image_id"])
        self.assertEqual(stack, original)
        for reference in ("ghcr.io/bitwarden/lite@sha256:" + "a" * 64, stack["bitwarden"]["image_id"]):
            stack["services"]["bitwarden"]["image"] = reference
            if reference.startswith("sha256:"):
                stack["services"]["bitwarden"].update(archive="/fixture/image.tar", archive_sha256="b" * 64)
            self.assertEqual(render.compose(stack)["services"]["bitwarden"]["image"], reference)

    def execute(self, stack, *, available=True, mismatch=False):
        td = tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        root = Path(td.name); binary = root / "bin"; binary.mkdir()
        docker = binary / "docker"
        docker.write_text(r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['FIXTURE_CALLS']).open('a') as log:
    log.write(json.dumps(args) + '\n')
if args[:2] == ['image', 'pull']:
    raise SystemExit(0)
if args[:2] != ['image', 'inspect']:
    raise SystemExit(99)
expected = 'sha256:' + '1' * 64
if args[2] == expected and os.environ['FIXTURE_AVAILABLE'] != 'true':
    raise SystemExit(1)
print('sha256:' + '2' * 64 if args[2].endswith(':latest') or os.environ['FIXTURE_MISMATCH'] == 'true' else expected)
""")
        docker.chmod(0o700)
        tasks = yaml.safe_load((Path(__file__).resolve().parents[1] / "ansible/tasks/bitwarden.yml").read_text())[:2]
        checkpoint = root / "checkpoint"
        tasks.append({"name": "Synthetic checkpoint after the image guard", "ansible.builtin.copy": {"content": "passed", "dest": str(checkpoint)}})
        playbook = root / "fixture.yml"
        playbook.write_text(yaml.safe_dump([{"hosts": "localhost", "gather_facts": False,
            "vars": {"stack": stack, "ansible_python_interpreter": sys.executable},
            "environment": {"PATH": str(binary) + os.pathsep + os.environ["PATH"],
                "FIXTURE_CALLS": str(root / "calls.jsonl"), "FIXTURE_AVAILABLE": str(available).lower(),
                "FIXTURE_MISMATCH": str(mismatch).lower()}, "tasks": tasks}], sort_keys=False))
        env = dict(os.environ, ANSIBLE_HOME=str(root / "ansible"), ANSIBLE_LOCAL_TEMP=str(root / "local"), ANSIBLE_REMOTE_TEMP=str(root / "remote"))
        result = subprocess.run([sys.executable, "-m", "ansible.cli.playbook", "-i", "localhost,", "-c", "local", str(playbook)], env=env, capture_output=True, text=True, timeout=30)
        self.assertTrue((root / "calls.jsonl").exists(), result.stdout + result.stderr)
        calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
        return result, calls, checkpoint.exists()

    def test_local_expected_image_survives_changed_latest_without_pull_or_retag(self):
        stack = self.stack()
        result, calls, checkpoint = self.execute(stack)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(checkpoint)
        self.assertEqual([c[:3] for c in calls], [["image", "inspect", stack["bitwarden"]["image_id"]]])

    def test_missing_or_wrong_retained_image_stops_before_any_start_or_pull(self):
        for available, mismatch in ((False, False), (True, True)):
            with self.subTest(available=available, mismatch=mismatch):
                result, calls, checkpoint = self.execute(self.stack(), available=available, mismatch=mismatch)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(checkpoint)
                self.assertTrue(all(c[:2] == ["image", "inspect"] for c in calls))

    def test_pinned_registry_and_archived_paths_keep_their_existing_selection(self):
        stack = self.stack()
        for reference in ("ghcr.io/bitwarden/lite@sha256:" + "a" * 64, stack["bitwarden"]["image_id"]):
            stack["services"]["bitwarden"]["image"] = reference
            result, calls, checkpoint = self.execute(stack)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(checkpoint)
            self.assertEqual(calls[-1][2], reference)
            self.assertEqual(any(c[:2] == ["image", "pull"] for c in calls), "@sha256:" in reference)
