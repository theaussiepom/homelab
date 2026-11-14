"""Source scanner adapters preserve fail-closed diagnostics under malformed tooling."""

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import source_safety as safety


class SafetyEdges(unittest.TestCase):
    def test_scanner_cli_reports_success_refusal_and_unexpected_error_separately(self):
        for value, code in [
            ({"status": "passed"}, 0),
            (safety.guard.Blocked("fixture_refusal"), 1),
            (ValueError("private payload"), 2),
        ]:
            with (
                self.subTest(code=code),
                patch.object(sys, "argv", ["source", "--scanner", "scanner"]),
                patch.object(
                    safety,
                    "run",
                    **(
                        {"side_effect": value}
                        if isinstance(value, Exception)
                        else {"return_value": value}
                    ),
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(safety.main(), code)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"], "passed" if code == 0 else "blocked")
                self.assertNotIn("private payload", output.getvalue())

    def test_git_failure_and_invalid_revision_stop_before_tree_scan(self):
        with (
            patch.object(
                safety.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1, b"", b"private"),
            ),
            self.assertRaises(safety.guard.Blocked),
        ):
            safety.git(Path("."), "status")
        with (
            patch.object(safety, "git") as command,
            self.assertRaises(safety.guard.Blocked),
        ):
            safety.resolve(Path("."), "untrusted/ref")
        command.assert_not_called()

    def test_review_head_rejects_nonimmutable_input_before_any_git_read(self):
        check = safety.guard.Check(review_head='HEAD')
        with patch.object(check, 'git') as command, self.assertRaises(safety.guard.Blocked):
            check.head_review()
        command.assert_not_called()

    def test_commit_metadata_and_maintainer_trailer_identity_are_exact(self):
        for row in [
            "invalid metadata",
            "\0".join(
                [
                    safety.OWN_NAME,
                    safety.OWN_EMAIL,
                    safety.OWN_NAME,
                    safety.OWN_EMAIL,
                    "Signed-off-by: theaussiepom <wrong@example.invalid>",
                ]
            ),
        ]:
            with (
                patch.object(safety, "git", return_value=row.encode()),
                self.assertRaises(safety.guard.Blocked),
            ):
                safety.check_identity(Path("."), "a" * 40)
        row = "\0".join(
            [
                safety.OWN_NAME,
                safety.OWN_EMAIL,
                safety.OWN_NAME,
                safety.OWN_EMAIL,
                "Signed-off-by: theaussiepom <" + safety.OWN_EMAIL + ">",
            ]
        )
        with patch.object(safety, "git", return_value=row.encode()):
            safety.check_identity(Path("."), "a" * 40)

    def test_history_count_and_wall_clock_limits_preserve_bounds(self):
        with (
            patch.object(safety, "resolve", return_value="a" * 40),
            patch.object(
                safety,
                "git",
                return_value=("\n".join(str(i).zfill(40) for i in range(201))).encode(),
            ),
            self.assertRaises(safety.guard.Blocked),
        ):
            safety.run(Path("."), "HEAD", "", Path("scanner"))
        with (
            patch.object(safety, "resolve", return_value="a" * 40),
            patch.object(safety, "git", return_value=("a" * 40).encode()),
            patch.object(safety.time, "monotonic", side_effect=[0, 181]),
            self.assertRaises(safety.guard.Blocked),
        ):
            safety.run(Path("."), "HEAD", "", Path("scanner"))

    def test_author_display_labels_keep_exact_public_email_and_committer_rules(self):
        """Display labels vary; reserved handles, committers and trailers stay bound."""
        contributor = ("contributor", "123+contributor@users.noreply.github.com")
        maintainer = (safety.OWN_NAME, safety.OWN_EMAIL)
        github = ("GitHub", "noreply@github.com")
        accepted = [
            (*maintainer, *maintainer, ""),
            ("Public display name", safety.OWN_EMAIL, *github, ""),
            (safety.OWN_NAME.upper(), safety.OWN_EMAIL, *contributor, ""),
            ("另一个公开名称", safety.OWN_EMAIL, *maintainer, ""),
            (*contributor, *github, ""),
            ("Other display name", "other@example.invalid", *contributor, ""),
            (*contributor, *contributor, "Signed-off-by: other <other@example.invalid>"),
            ("Public display name", safety.OWN_EMAIL, *github,
             "Co-authored-by: THEAUSSIEPOM <" + safety.OWN_EMAIL + ">"),
        ]
        rejected = [
            ("", safety.OWN_EMAIL, *github, ""),
            (" \t\u2003", safety.OWN_EMAIL, *github, ""),
            (safety.OWN_NAME, "wrong@example.invalid", *github, ""),
            (safety.OWN_NAME.upper(), "wrong@example.invalid", *github, ""),
            (safety.OWN_NAME, safety.OWN_EMAIL.upper(), *github, ""),
            (safety.OWN_NAME, safety.OWN_EMAIL + " ", *github, ""),
            ("Public display name", safety.OWN_EMAIL,
             safety.OWN_NAME, "wrong@example.invalid", ""),
            (*contributor, safety.OWN_NAME.upper(), safety.OWN_EMAIL, ""),
            (*contributor, "Other display name", safety.OWN_EMAIL, ""),
            (*contributor, "", safety.OWN_EMAIL, ""),
            (*contributor, safety.OWN_NAME, safety.OWN_EMAIL.upper(), ""),
            (*contributor, safety.OWN_NAME, safety.OWN_EMAIL + " ", ""),
            (*contributor, safety.OWN_NAME.upper(), "wrong@example.invalid", ""),
        ]
        for row in accepted:
            with self.subTest(accepted=row), patch.object(
                safety, "git", return_value="\0".join(row).encode()
            ):
                safety.check_identity(Path("."), "a" * 40)
        for row in rejected:
            with self.subTest(rejected=row), patch.object(
                safety, "git", return_value="\0".join(row).encode()
            ), self.assertRaises(safety.guard.Blocked) as error:
                safety.check_identity(Path("."), "a" * 40)
            self.assertEqual(error.exception.reason, "maintainer_identity_mismatch")
        for trailer in ("Co-authored-by", "Signed-off-by", "SIGNED-OFF-BY"):
            for email in ("wrong@example.invalid", safety.OWN_EMAIL.upper()):
                row = ("Public display name", safety.OWN_EMAIL, *github,
                       trailer + ": THEAUSSIEPOM <" + email + ">")
                with self.subTest(trailer=row), patch.object(
                    safety, "git", return_value="\0".join(row).encode()
                ), self.assertRaises(safety.guard.Blocked) as error:
                    safety.check_identity(Path("."), "a" * 40)
                self.assertEqual(error.exception.reason, "maintainer_trailer_email_mismatch")

    def test_ci_selector_entrypoint_reads_only_the_event_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "event"
            path.write_text("{}")
            with (
                patch.dict(
                    os.environ,
                    {
                        "GITHUB_EVENT_PATH": str(path),
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
                        "GITHUB_SHA": "a" * 40,
                    },
                ),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                runpy.run_path(
                    str(safety.ROOT / ".github/scripts/ci_changes.py"),
                    run_name="__main__",
                )
            self.assertEqual(output.getvalue().strip(), "iso=true")

    def test_absolute_object_store_is_used_without_rewriting_the_source_index(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as tmp:
            objects = Path(tmp) / "objects"
            objects.mkdir()

            def git(root, *args, **kwargs):
                return str(objects).encode() if args[0] == "rev-parse" else b""

            def command(args, **kwargs):
                if args[0] == "git":
                    return real_run(args, **kwargs)
                self.assertEqual(args[0], sys.executable)
                self.assertEqual(kwargs["env"]["GITLEAKS_BIN"], "/synthetic/scanner")
                return subprocess.CompletedProcess(
                    args, 0, b'{"status":"passed","scanned_files":2}'
                )

            with (
                patch.object(safety, "git", side_effect=git),
                patch.object(safety.subprocess, "run", side_effect=command),
            ):
                self.assertEqual(
                    safety.scan_tree(Path(tmp), "a" * 40, Path("/synthetic/scanner"))[
                        "scanned_files"
                    ],
                    2,
                )

    def test_identical_commit_trees_are_scanned_once_with_each_identity_checked(self):
        first, second = "a" * 40, "b" * 40

        def git(root, *args):
            return (
                (first + "\n" + second + "\n").encode()
                if args[0] == "rev-list"
                else b"identical-tree"
            )

        with (
            patch.object(safety, "resolve", return_value=first),
            patch.object(safety, "git", side_effect=git),
            patch.object(safety, "check_identity") as identity,
            patch.object(
                safety, "scan_tree", return_value={"scanned_files": 2}
            ) as scan,
        ):
            result = safety.run(Path("/synthetic"), "HEAD", "", Path("/scanner"))
            self.assertEqual(result["commits_checked"], 2)
            self.assertEqual(result["unique_trees_checked"], 1)
            self.assertEqual(identity.call_count, 2)
            scan.assert_called_once()
