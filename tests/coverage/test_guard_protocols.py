"""Malformed Git protocol responses fail closed before source publication."""

import contextlib
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest

ROOT = Path(
    os.environ.get("HOMELAB_TEST_GUARD_ROOT", Path(__file__).resolve().parents[2])
)


def load():
    spec = importlib.util.spec_from_file_location(
        "staged_protocol", ROOT / ".githooks/staged_guard.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("error_type", [FileNotFoundError, PermissionError])
def test_os_failures_block_without_disclosing_raw_diagnostics(error_type, capsys):
    module = load()
    with patch.object(
        module.Check, "scan", side_effect=error_type("PRIVATE RAW DIAGNOSTIC")
    ):
        assert module.main() == 2
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["status"] == "blocked" and result["reason"] == "check_error"
    assert result["error_type"] == error_type.__name__
    assert "PRIVATE RAW DIAGNOSTIC" not in captured.out + captured.err


@pytest.mark.parametrize(
    "scenario",
    ["empty", "valid", "headers", "type", "body-header", "length", "trailer"],
)
def test_git_blob_batch_responses_are_exact_and_bounded(scenario):
    module = load()
    check = module.Check()
    oid = "a" * 40
    entry = {"file": ("100644", oid)}
    if scenario == "empty":
        assert check.read_blobs({}) == {}
        return
    header = (oid + " blob 4\n").encode()
    body = header + b"data\n"
    if scenario == "headers":
        header = b""
    elif scenario == "type":
        header = (oid + " tree 4\n").encode()
    elif scenario == "body-header":
        body = b"wrong blob header\ndata\n"
    elif scenario == "length":
        body = body[:-1]
    elif scenario == "trailer":
        body += b"unsolicited bytes"
    check.git = Mock(
        side_effect=[SimpleNamespace(stdout=header), SimpleNamespace(stdout=body)]
    )
    if scenario == "valid":
        assert check.read_blobs(entry) == {"file": b"data"}
    else:
        with pytest.raises(module.Blocked):
            check.read_blobs(entry)


@pytest.mark.parametrize("absolute", [True, False])
def test_index_bytes_resolve_only_the_selected_repository_index(tmp_path, absolute):
    module = load()
    check = module.Check()
    check.root = tmp_path
    index = tmp_path / "index"
    index.write_bytes(b"index bytes")
    check.git = Mock(
        return_value=SimpleNamespace(
            stdout=str(index if absolute else Path("index")).encode()
        )
    )
    assert check.index_bytes() == b"index bytes"
    index.unlink()
    assert check.index_bytes() == b""


def test_staged_budget_is_checked_before_any_subprocess():
    module = load()
    check = module.Check()
    check.started = 0
    with (
        patch.object(module.time, "monotonic", return_value=6),
        patch.object(module.subprocess, "run") as command,
        pytest.raises(module.Blocked),
    ):
        check.run(["git", "status"])
    command.assert_not_called()


def test_push_cli_accepts_empty_update_and_reports_refusal_without_any_push():
    target = ROOT / ".githooks/push_guard.py"
    with (
        patch("sys.argv", ["push", "origin"]),
        patch("sys.stdin", io.StringIO("")),
        patch(
            "subprocess.run",
            side_effect=[
                SimpleNamespace(returncode=0, stdout=b"fixture"),
                SimpleNamespace(
                    returncode=0, stdout=b"123+fixture@users.noreply.github.com"
                ),
            ],
        ),
        contextlib.redirect_stdout(io.StringIO()) as output,
    ):
        runpy.run_path(str(target), run_name="__main__")
    assert json.loads(output.getvalue())["commits_checked"] == 0
    with (
        patch("sys.argv", ["push", "invalid/remote"]),
        patch("sys.stdin", io.StringIO("")),
        patch("subprocess.run") as command,
        contextlib.redirect_stderr(io.StringIO()) as error,
        pytest.raises(SystemExit),
    ):
        runpy.run_path(str(target), run_name="__main__")
    command.assert_not_called()
    assert json.loads(error.getvalue())["status"] == "blocked"


@pytest.mark.parametrize(
    "scenario",
    [
        "unsafe-index",
        "empty-drift",
        "policy-mode",
        "review-type",
        "review-entry",
        "missing-scanner",
        "report-type",
        "report-empty",
        "report-path",
        "relative-reviewed",
        "non-ignore-policy",
        "elapsed",
    ],
)
def test_staged_scan_refuses_corrupt_metadata_and_untrusted_scanner_responses(
    tmp_path, scenario
):
    module = load()
    check = module.Check()
    oid = "a" * 40
    review = {
        "path": "good.txt",
        "sha256": hashlib.sha256(b"content").hexdigest(),
        "rule": "fixture",
        "line": 1,
        "reason": "public fixture",
    }
    blobs = {"good.txt": b"content"}
    rows = [("100644", "good.txt")]
    if scenario in (
        "policy-mode",
        "review-type",
        "review-entry",
        "relative-reviewed",
        "non-ignore-policy",
    ):
        rows.append(
            ("120000" if scenario == "policy-mode" else "100644", module.REVIEW_FILE)
        )
        blobs[module.REVIEW_FILE] = json.dumps(
            {}
            if scenario == "review-type"
            else [dict(review, line=0)] if scenario == "review-entry" else [review]
        ).encode()
    if scenario == "unsafe-index":
        rows = [("100644", "../escape")]

    def git(*args, **kwargs):
        if args[0] == "rev-parse":
            return SimpleNamespace(stdout=str(tmp_path).encode())
        if args[0] == "ls-files":
            return SimpleNamespace(
                stdout=b"".join(
                    f"{mode} {oid} 0\t{name}\0".encode() for mode, name in rows
                )
            )
        if args[0] == "diff":
            return SimpleNamespace(
                stdout=b"" if scenario == "empty-drift" else b"good.txt\0"
            )
        if args[0] == "config":
            return SimpleNamespace(stdout=b"")
        raise AssertionError(args)

    def run(args, **kwargs):
        if args[-1] == "version":
            return SimpleNamespace(stdout=module.VERSION.encode())
        if args[0] == "git":
            return SimpleNamespace(stdout=b"", returncode=0)
        report = Path(args[args.index("--report-path") + 1])
        findings = {} if scenario == "report-type" else []
        if scenario in ("report-path", "relative-reviewed"):
            findings = [
                {
                    "File": "unknown.txt" if scenario == "report-path" else "good.txt",
                    "RuleID": "fixture",
                    "StartLine": 1,
                }
            ]
        report.write_text(json.dumps(findings))
        return SimpleNamespace(returncode=1 if scenario == "report-empty" else 0)

    check.git = Mock(side_effect=git)
    check.index_bytes = Mock(
        side_effect=[b"index", b"drift" if scenario == "empty-drift" else b"index"]
    )
    check.read_blobs = Mock(return_value=blobs)
    check.run = Mock(side_effect=run)
    with (
        patch.dict(
            os.environ,
            {
                "GITLEAKS_BIN": (
                    "" if scenario == "missing-scanner" else "fixture-scanner"
                )
            },
        ),
        patch.object(module.shutil, "which", return_value=None),
        patch.object(
            module.time,
            "monotonic",
            return_value=check.started + (6 if scenario == "elapsed" else 0),
        ),
    ):
        if scenario in ("relative-reviewed", "non-ignore-policy"):
            assert check.scan()["reviewed_findings"] == int(
                scenario == "relative-reviewed"
            )
        else:
            with pytest.raises(module.Blocked):
                check.scan()


def test_push_cli_rejects_oversized_input_before_accepting_a_valid_prefix(tmp_path):
    """A valid 64 KiB deletion prefix must not hide unchecked suffix refs."""
    import subprocess
    import sys

    zero = "0" * 40
    remote = "a" * 40
    padding = 128 - len(f"(delete) {zero} refs/heads/0000 {remote}\n")
    prefix = "".join(f"(delete) {zero} refs/heads/{i:04d}{'x' * padding} {remote}\n" for i in range(512))
    assert len(prefix.encode("utf-8")) == 65536
    suffix = f"refs/heads/unsigned {'1' * 40} refs/heads/unsigned {zero}\n"
    marker = tmp_path / "git-calls"
    executable = tmp_path / "git"
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import os,sys\n"
        "with open(os.environ['HOMELAB_TEST_GIT_CALLS'],'a') as calls: calls.write('call\\n')\n"
        "values={'user.name':'fixture','user.email':'123+fixture@users.noreply.github.com'}\n"
        "if len(sys.argv)!=3 or sys.argv[1]!='config': raise SystemExit(2)\n"
        "print(values[sys.argv[2]])\n"
    )
    executable.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ['PATH'], HOMELAB_TEST_GIT_CALLS=str(marker))
    for payload, accepted in [(prefix, True), (prefix + suffix, False), (prefix.replace('x', 'é'), False)]:
        marker.unlink(missing_ok=True)
        result = subprocess.run([sys.executable, str(ROOT / '.githooks/push_guard.py'), 'origin'], input=payload, capture_output=True, text=True, env=environment, timeout=15)
        if accepted:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['commits_checked'] == 0
            assert marker.is_file()
        else:
            assert result.returncode != 0
            assert json.loads(result.stderr)['reason'] == 'push_update_input_too_large'
            assert not marker.exists()
