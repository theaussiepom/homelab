"""Bootstrap CLI dispatch and synthetic rehearsal stay separate from native work."""

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "proxmox/bootstrap"))
import bootstrap
import native


@pytest.mark.parametrize(
    "command,options,function",
    [
        (
            "prepare",
            ["--catalog", "catalog", "--settings", "settings", "--out", "output"],
            "prepare",
        ),
        (
            "container-prepare",
            ["--catalog", "catalog", "--settings", "settings", "--out", "output"],
            "container_prepare",
        ),
        ("snapshot", ["--out", "output"], "snapshot"),
        ("container-backup", ["--work", "work", "--out", "output"], "container_backup"),
        ("rehearse", ["--evidence", "evidence"], "rehearse"),
    ],
)
def test_bootstrap_cli_routes_explicit_inputs(command, options, function, capsys):
    with (
        patch.object(sys, "argv", ["bootstrap", command, *options]),
        patch.object(bootstrap, function, return_value={"selected": command}) as action,
    ):
        assert bootstrap.main() == 0
    action.assert_called_once()
    if command != "rehearse":
        assert json.loads(capsys.readouterr().out)["selected"] == command


@pytest.mark.parametrize(
    "command,options,function",
    [
        ("backup", ["--work", "work", "--out", "output"], "backup"),
        ("native", ["verify", "--work", "work"], "run"),
    ],
)
def test_native_dispatch_passes_only_the_named_operation(
    command, options, function, capsys
):
    with (
        patch.object(sys, "argv", ["bootstrap", command, *options]),
        patch.object(native, function, return_value={"native_called": True}) as action,
    ):
        assert bootstrap.main() == 0
    action.assert_called_once()
    assert json.loads(capsys.readouterr().out)["native_called"]


@pytest.mark.parametrize(
    "error",
    [
        bootstrap.Refused("reviewed refusal"),
        ValueError("private detail"),
        subprocess.TimeoutExpired(["docker"], 1),
    ],
)
def test_cli_errors_are_structured_and_do_not_publish_private_diagnostics(
    error, capsys
):
    with (
        patch.object(sys, "argv", ["bootstrap", "snapshot", "--out", "output"]),
        patch.object(bootstrap, "snapshot", side_effect=error),
    ):
        assert bootstrap.main() == 3
    result = json.loads(capsys.readouterr().err)
    assert result["refused"] and "private detail" not in result["reason"]


def test_synthetic_rehearsal_composes_owned_source_and_records_scope(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "proxmox").mkdir()
    (source / "proxmox/bootstrap").symlink_to(
        ROOT / "proxmox/bootstrap", target_is_directory=True
    )
    work = tmp_path / "work"
    evidence = tmp_path / "evidence"

    def path(value):
        if str(value) == "/.dockerenv":
            return tmp_path / "dockerenv"
        if str(value) == "/tmp/bootstrap-rehearsal":
            return work
        return Path(value)

    (tmp_path / "dockerenv").touch()
    # The real source preparation and variable projection run; native programs do not.
    with (
        patch.object(bootstrap, "Path", side_effect=path),
        patch.object(bootstrap, "log_run") as command,
        patch.dict(bootstrap.os.environ, {}, clear=False),
    ):
        bootstrap.rehearse(evidence)
    result = json.loads((evidence / "result.json").read_text())
    assert (
        result["native_pve_tested"] is False
        and result["live_execution_admitted"] is False
    )
    assert len([c for c in command.call_args_list if c.args[0][0] == "tofu"]) == 6
    assert (work / "bundle/tofu/modules/deploy/test.auto.tfvars.json").is_file()
    with (
        patch.object(bootstrap, "Path", side_effect=path),
        pytest.raises(bootstrap.Refused, match="already exists"),
    ):
        bootstrap.rehearse(evidence)


def test_rehearsal_refuses_execution_outside_the_test_container(tmp_path):
    with (
        patch.object(bootstrap, "Path", return_value=tmp_path / "absent"),
        pytest.raises(bootstrap.Refused, match="Docker"),
    ):
        bootstrap.rehearse(tmp_path / "evidence")
