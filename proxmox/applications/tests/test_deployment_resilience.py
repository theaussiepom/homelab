"""Real process/OS boundaries with disposable files and synthetic guest transports."""

import errno
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deployment_state as state
import commands
import guest_contract as contract
import private_io as io
from fixtures import guest, github_source

WORKER = Path(__file__).with_name("deployment_process_fixture.py")


class DeploymentResilienceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cfg = guest(self.root)
        self.work = self.root / "state/808"
        self.work.parent.mkdir(mode=0o700)
        self.work.mkdir(mode=0o700)
        io.write_new(self.work / "terraform.tfstate", b"authoritative backend")
        io.write_new(self.root / "site.json", b"{}")
        self.binding = {"vmid": 808, "site_sha256": "a" * 64}
        self.phases = ["preparation", "mariadb"]
        self.source, self.revisions = github_source(self.root)
        context = patch.dict(
            os.environ,
            {"GITHUB_SHA": self.revisions[0], "GITHUB_WORKSPACE": str(self.source)},
        )
        context.start()
        self.addCleanup(context.stop)

    def child(self, phase="infrastructure", pause="none", run_id="777", mode="deploy"):
        process = subprocess.Popen(
            [sys.executable, str(WORKER), str(self.root), mode, phase, pause, run_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)

    def checkpoint(self, process, expected):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(
                selector.select(timeout=20), "Fixture did not reach checkpoint"
            )
        self.assertEqual(process.stdout.readline().strip(), expected)

    def finish(self, process, expected=0, release=False):
        output, errors = process.communicate(
            "continue\n" if release else None, timeout=20
        )
        self.assertEqual(process.returncode, expected, output + errors)
        return output

    def test_sigterm_and_sigkill_preserve_custody_and_refuse_replay(self):
        for phase in ("infrastructure", "preparation", "mariadb"):
            for termination in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(phase=phase, termination=termination):
                    # Each failure gets an independent guest history.
                    with tempfile.TemporaryDirectory() as directory:
                        previous_root = self.root
                        self.root = Path(directory)
                        work = self.root / "state/808"
                        work.parent.mkdir(mode=0o700)
                        work.mkdir(mode=0o700)
                        io.write_new(
                            work / "terraform.tfstate", b"authoritative backend"
                        )
                        io.write_new(self.root / "site.json", b"{}")
                        io.write_new(
                            work / "ordinary-complete.json",
                            io.encoded(
                                {
                                    "status": "passed",
                                    "binding": {"old": True},
                                    "run_number": 1,
                                    "site_revision": self.revisions[0],
                                    "workflow": [
                                        "example/private-site",
                                        "example/private-site/.github/workflows/deploy.yml",
                                    ],
                                    "operation": str(work / "ordinary-1-1"),
                                }
                            ),
                        )
                        old = (work / "ordinary-complete.json").read_bytes()
                        try:
                            sequence = ["infrastructure", "preparation", "mariadb"]
                            for preceding in sequence[: sequence.index(phase)]:
                                self.finish(self.child(preceding))
                            process = self.child(phase, pause="operation")
                            self.checkpoint(process, "operation-complete")
                            hold = (work / "ORDINARY-HOLD.json").read_bytes()
                            operations = (self.root / "guest-operations").read_bytes()
                            process.send_signal(termination)
                            self.finish(process, -termination)
                            self.assertEqual(
                                (work / "ORDINARY-HOLD.json").read_bytes(), hold
                            )
                            self.assertEqual(
                                (work / "ordinary-complete.json").read_bytes(), old
                            )
                            self.assertEqual(
                                (work / "terraform.tfstate").read_bytes(),
                                b"authoritative backend",
                            )
                            self.assertFalse(
                                (
                                    work / "ordinary-777-1" / (phase + "-complete.json")
                                ).exists()
                            )
                            if phase != "infrastructure":
                                self.assertTrue(
                                    (
                                        work
                                        / "ordinary-777-1"
                                        / (phase + "-started.json")
                                    ).is_file()
                                )
                            for run_id in ("777", "778"):
                                self.assertIn(
                                    "ValueError",
                                    self.finish(self.child(phase, run_id=run_id), 2),
                                )
                            self.assertEqual(
                                (self.root / "guest-operations").read_bytes(),
                                operations,
                            )
                        finally:
                            self.root = previous_root

    def test_competing_process_cannot_enter_guest_operation(self):
        first = self.child(pause="operation")
        self.checkpoint(first, "operation-complete")
        held = (self.work / "ORDINARY-HOLD.json").read_bytes()
        self.assertIn("BlockingIOError", self.finish(self.child(run_id="778"), 2))
        self.assertEqual(
            (self.root / "guest-operations").read_text(), "infrastructure\n"
        )
        self.assertEqual((self.work / "ORDINARY-HOLD.json").read_bytes(), held)
        self.finish(first, release=True)
        # A subsequent phase can acquire the released locks; the failed contender
        # did not change or clear the first run's hold.
        self.finish(self.child("preparation"))

    def packet(self):
        io.write_new(
            self.root / "packet.json",
            io.encoded(
                {
                    "schema": contract.SCHEMA,
                    "enabled": True,
                    "kind": "mariadb",
                    "identity": "a" * 64,
                    "files": {
                        "site.json": json.dumps(self.cfg),
                        "homelab.cnf": "retained listener\n",
                    },
                }
            ),
        )
        (self.root / "inputs").mkdir(mode=0o700)
        (self.root / "inputs/mariadb").mkdir(mode=0o700)
        return self.root / "inputs/mariadb" / ("a" * 64)

    def assert_prepared(self, destination):
        manifest = io.read_json(destination / "prepared.json", private=True)
        self.assertEqual(manifest["packet_sha256"], io.sha(self.root / "packet.json"))
        self.assertEqual(
            set(p.name for p in destination.iterdir()),
            {"prepared.json", *manifest["files"]},
        )
        for name, digest in manifest["files"].items():
            self.assertEqual(
                io.digest(io.regular(destination / name, private=True)), digest
            )
        self.assertFalse((self.root / "guest-operations").exists())

    def test_simultaneous_first_publication_has_one_winner_and_no_overwrite(self):
        destination = self.packet()
        children = [self.child(mode="prepare", pause="create") for _ in range(2)]
        for child in children:
            self.checkpoint(child, "create-ready")
        for child in children:
            child.stdin.write("continue\n")
            child.stdin.flush()
        results = [child.communicate(timeout=20) for child in children]
        self.assertEqual(
            sorted(child.returncode for child in children), [0, 2], results
        )
        self.assertIn("FileExistsError", "".join(row[0] for row in results))
        self.assert_prepared(destination)

    def test_partial_input_publication_is_never_adopted_by_a_contender(self):
        destination = self.packet()
        first = self.child(mode="prepare", pause="partial")
        self.checkpoint(first, "input-partial")
        before = (destination / "site.json").read_bytes()
        self.assertIn("ValueError", self.finish(self.child(mode="prepare"), 2))
        self.assertEqual((destination / "site.json").read_bytes(), before)
        self.assertFalse((destination / "prepared.json").exists())
        self.finish(first, release=True)
        self.assert_prepared(destination)
        original = {p.name: p.read_bytes() for p in destination.iterdir()}
        self.finish(self.child(mode="prepare"))
        self.assertEqual(
            {p.name: p.read_bytes() for p in destination.iterdir()}, original
        )

    def test_killed_input_publisher_leaves_partial_inputs_for_review(self):
        destination = self.packet()
        publisher = self.child(mode="prepare", pause="partial")
        self.checkpoint(publisher, "input-partial")
        before = {p.name: p.read_bytes() for p in destination.iterdir()}
        publisher.kill()
        self.finish(publisher, -signal.SIGKILL)
        self.assertIn("ValueError", self.finish(self.child(mode="prepare"), 2))
        self.assertEqual(
            {p.name: p.read_bytes() for p in destination.iterdir()}, before
        )
        self.assertFalse((self.root / "guest-operations").exists())

    def test_receipt_storage_failures_preserve_hold_and_old_or_complete_receipt(self):
        for failure in ("write", "flush", "file-fsync", "rename", "directory-fsync"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                cfg = guest(directory)
                work = Path(directory) / "state/808"
                work.parent.mkdir(mode=0o700)
                work.mkdir(mode=0o700)
                io.write_new(work / "terraform.tfstate", b"authoritative backend")
                receipt = work / "ordinary-complete.json"
                old = io.encoded(
                    {
                        "status": "passed",
                        "binding": {"old": True},
                        "run_number": 1,
                        "site_revision": self.revisions[0],
                        "workflow": [
                            "example/private-site",
                            "example/private-site/.github/workflows/deploy.yml",
                        ],
                        "operation": str(work / "ordinary-1-1"),
                    }
                )
                io.write_new(receipt, old)
                with (
                    patch.dict(
                        os.environ,
                        {
                            "GITHUB_RUN_ID": "777",
                            "GITHUB_RUN_ATTEMPT": "1",
                            "GITHUB_RUN_NUMBER": "777",
                            "GITHUB_REPOSITORY": "example/private-site",
                            "HOMELAB_DEPLOYMENT_WORKFLOW": "example/private-site/.github/workflows/deploy.yml@refs/heads/main",
                        },
                    ),
                    state.DeploymentAttempt(cfg, self.binding, self.phases) as attempt,
                ):
                    attempt.begin_infrastructure()
                    attempt.infrastructure_complete(
                        {
                            "changed": False,
                            "state_sha256": io.sha(work / "terraform.tfstate"),
                        }
                    )
                    ready = attempt.begin_phase("preparation")
                    attempt.phase_complete("preparation", {"changed": False}, ready)
                    ready = attempt.begin_phase("mariadb")
                    hold = attempt.hold.read_bytes()
                    pending = receipt.with_name(receipt.name + ".pending")
                    fdopen, fsync, replace, sync = (
                        io.os.fdopen,
                        io.os.fsync,
                        io.os.replace,
                        io.sync,
                    )
                    renamed = False

                    class FaultyStream:
                        def __init__(self, stream):
                            self.stream = stream

                        def __getattr__(self, name):
                            return getattr(self.stream, name)

                        def __enter__(self):
                            return self

                        def __exit__(self, *exc):
                            return self.stream.__exit__(*exc)

                        def write(self, value):
                            if failure == "write":
                                self.stream.write(value[:11])
                                raise OSError(errno.ENOSPC, "synthetic disk full")
                            return self.stream.write(value)

                        def flush(self):
                            self.stream.flush()
                            if failure == "flush":
                                raise OSError(errno.EIO, "synthetic flush failure")

                    def is_pending(fd):
                        return (
                            pending.exists()
                            and os.fstat(fd).st_ino == pending.stat().st_ino
                        )

                    def open_stream(fd, *args, **kwargs):
                        stream = fdopen(fd, *args, **kwargs)
                        return FaultyStream(stream) if is_pending(fd) else stream

                    def sync_file(fd):
                        if failure == "file-fsync" and is_pending(fd):
                            raise OSError(errno.EIO, "synthetic file sync failure")
                        return fsync(fd)

                    def rename(source, target):
                        nonlocal renamed
                        if failure == "rename":
                            raise OSError(errno.EIO, "synthetic rename failure")
                        replace(source, target)
                        renamed = True

                    def sync_directory(path):
                        if failure == "directory-fsync" and renamed:
                            raise OSError(errno.EIO, "synthetic directory sync failure")
                        return sync(path)

                    with (
                        patch.object(io.os, "fdopen", side_effect=open_stream),
                        patch.object(io.os, "fsync", side_effect=sync_file),
                        patch.object(io.os, "replace", side_effect=rename),
                        patch.object(io, "sync", side_effect=sync_directory),
                        self.assertRaises(OSError) as raised,
                    ):
                        attempt.phase_complete("mariadb", {"changed": False}, ready)
                    self.assertEqual(
                        raised.exception.errno,
                        errno.ENOSPC if failure == "write" else errno.EIO,
                    )
                    self.assertEqual(attempt.hold.read_bytes(), hold)
                    self.assertTrue((attempt.operation / "complete.json").is_file())
                    if failure == "directory-fsync":
                        self.assertEqual(
                            json.loads(receipt.read_bytes())["binding"], self.binding
                        )
                        self.assertFalse(pending.exists())
                    else:
                        self.assertEqual(receipt.read_bytes(), old)
                        self.assertTrue(pending.is_file())
                        if failure == "write":
                            self.assertEqual(len(pending.read_bytes()), 11)
                        else:
                            self.assertEqual(
                                json.loads(pending.read_bytes())["binding"],
                                self.binding,
                            )
                    if renamed:
                        with self.assertRaises(ValueError):
                            attempt.completed(commands.is_ancestor)
                    else:
                        self.assertFalse(attempt.completed(commands.is_ancestor))
                with (
                    patch.dict(
                        os.environ,
                        {
                            "GITHUB_RUN_ID": "778",
                            "GITHUB_RUN_ATTEMPT": "1",
                            "GITHUB_RUN_NUMBER": "778",
                            "GITHUB_REPOSITORY": "example/private-site",
                            "HOMELAB_DEPLOYMENT_WORKFLOW": "example/private-site/.github/workflows/deploy.yml@refs/heads/main",
                        },
                    ),
                    state.DeploymentAttempt(
                        cfg, self.binding, self.phases
                    ) as next_attempt,
                ):
                    with self.assertRaisesRegex(ValueError, "existing attempt"):
                        next_attempt.begin_infrastructure()
                self.assertEqual((work / "ORDINARY-HOLD.json").read_bytes(), hold)


if __name__ == "__main__":
    unittest.main()
