"""Identity, bounded Git operations and outgoing history are checked before pushes."""

import importlib.util
import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(params=[Path(os.environ.get("HOMELAB_TEST_GUARD_ROOT", ROOT))])
def guard(request):
    spec = importlib.util.spec_from_file_location(
        "push_" + request.param.name.replace("-", "_"),
        request.param / ".githooks/push_guard.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def history(module, **changes):
    values = {
        "name": "fixture",
        "email": "123+fixture@users.noreply.github.com",
        "committer": "fixture",
        "committer_email": "123+fixture@users.noreply.github.com",
        "author": "fixture",
        "author_email": "123+fixture@users.noreply.github.com",
        "body": "normal message",
        "commits": "a" * 40,
    }
    values.update(changes)

    def git(*args):
        if args[0] == "config":
            return values["name" if args[1] == "user.name" else "email"]
        if args[0] == "rev-list":
            return values["commits"]
        if args[0] == "show":
            return "\0".join(
                values[k]
                for k in (
                    "committer",
                    "committer_email",
                    "author",
                    "author_email",
                    "body",
                )
            )
        assert args[0] == "verify-commit"
        return ""

    return patch.object(module, "git", side_effect=git)


@pytest.mark.parametrize(
    "remote,updates,change,reason",
    [
        ("bad/remote", "", {}, "named_remote"),
        ("origin", "", {"name": ""}, "noreply"),
        ("origin", "", {"email": "personal@example.invalid"}, "noreply"),
        ("origin", "bad row", {}, "invalid_push"),
        (
            "origin",
            "refs/a " + "a" * 40 + " refs/a " + "0" * 40,
            {"commits": "\n".join(str(i).zfill(40) for i in range(201))},
            "count_limit",
        ),
        (
            "origin",
            "refs/a " + "a" * 40 + " refs/a " + "0" * 40,
            {"committer": "other"},
            "committer",
        ),
        (
            "origin",
            "refs/a " + "a" * 40 + " refs/a " + "0" * 40,
            {"author_email": "different@example.invalid"},
            "author_email",
        ),
        (
            "origin",
            "refs/a " + "a" * 40 + " refs/a " + "0" * 40,
            {"body": "Co-authored-by: fixture <wrong@example.invalid>"},
            "trailer",
        ),
    ],
)
def test_outgoing_identity_and_update_refusals(guard, remote, updates, change, reason):
    with history(guard, **change), pytest.raises(guard.Refused, match=reason):
        guard.run(remote, updates)


def test_valid_signed_outgoing_history_and_remote_deletion(guard):
    update = "refs/heads/main " + "a" * 40 + " refs/heads/main " + "0" * 40
    with history(guard):
        assert guard.run("origin", update)["commits_checked"] == 1
    with history(guard):
        assert (
            guard.run("origin", "refs/main " + "0" * 40 + " refs/main " + "a" * 40)[
                "commits_checked"
            ]
            == 0
        )
    with history(
        guard, body="Signed-off-by: fixture <123+fixture@users.noreply.github.com>"
    ):
        assert guard.run("origin", update)["status"] == "passed"
    with history(
        guard, author="External Contributor", author_email="external@example.invalid"
    ):
        assert guard.run("origin", update)["status"] == "passed"


def test_git_helper_bounds_runtime_and_does_not_hide_failure(guard):
    with (
        patch.object(guard.time, "monotonic", return_value=guard.START + 6),
        pytest.raises(guard.Refused, match="budget"),
    ):
        guard.git("status")
    with (
        patch.object(guard.time, "monotonic", return_value=guard.START),
        patch.object(
            guard.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 1, b"", b""),
        ),
        pytest.raises(guard.Refused, match="signature"),
    ):
        guard.git("status")
    with (
        patch.object(guard.time, "monotonic", return_value=guard.START),
        patch.object(
            guard.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, b" result\n", b""),
        ),
    ):
        assert guard.git("status") == "result"
