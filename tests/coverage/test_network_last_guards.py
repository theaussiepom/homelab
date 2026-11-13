"""Read-only network probes and installer rechecks use inert command adapters."""

import copy
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "services/network-recovery"
sys.path.insert(0, str(ROOT))
import probe
import recovery
import test_install as installation


def test_probe_tcp_and_truncated_http_are_bounded_and_cli_never_mutates(capsys):
    client = MagicMock()
    client.__enter__.return_value = client
    client.recv.side_effect = [b"HTTP/1.1 200 OK\r\n", b""]
    with patch.object(probe.socket, "create_connection", return_value=client):
        assert probe.exchange({"protocol": "tcp", "address": "198.18.1.2", "port": 80})[
            "healthy"
        ]
        with pytest.raises(ValueError, match="Incomplete HTTP"):
            probe.exchange({"protocol": "http", "address": "198.18.1.2", "port": 80})
        with patch.object(
            sys,
            "argv",
            [
                "probe",
                "--exchange",
                json.dumps({"protocol": "tcp", "address": "198.18.1.2", "port": 80}),
            ],
        ):
            runpy.run_path(str(ROOT / "probe.py"), run_name="__main__")
            assert json.loads(capsys.readouterr().out)["healthy"]
    with patch.object(sys, "argv", ["probe", "--exchange", "{}"]):
        runpy.run_path(str(ROOT / "probe.py"), run_name="__main__")
        assert not json.loads(capsys.readouterr().out)["healthy"]
    with patch.object(
        probe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "{}")
    ) as command:
        assert probe.jrun(["fixture"]) == {}
        assert command.call_args.kwargs["timeout"] == 10


def test_recovery_uses_real_link_observer_and_refuses_malformed_candidate(tmp_path):
    import test_recovery as cases

    config = copy.deepcopy(cases.CONFIG)
    engine = recovery.Engine(config, tmp_path, boot="fixture")
    with patch.object(recovery, "links_observe", return_value=["fixture"]) as observe:
        assert engine.observe_links() == ["fixture"]
        observe.assert_called_once_with(config)
    invalid = cases.Scenario(tmp_path, [0])
    invalid.candidate["kind"] = "unexpected"
    with pytest.raises(ValueError, match="Invalid candidate"):
        invalid.tick()


def test_installer_regular_parent_and_source_size_limits_are_not_bypassed(tmp_path):
    module = installation.mod
    with (
        patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1
            ),
        ),
        pytest.raises(module.InstallError, match="not a directory"),
    ):
        module.secure_path(Path("/selected/file"))
    source = tmp_path / "source"
    source.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(module.InstallError, match="oversized"):
        module.source_bytes(source)


@pytest.mark.parametrize(
    "scenario", ["source-drift", "evidence-mode", "enablement", "valid-link"]
)
def test_installer_rechecks_sources_evidence_and_final_enablement(scenario):
    case = installation.Installation()
    case.setUp()
    module = installation.mod
    try:
        if scenario == "evidence-mode":
            (case.state / "installations").mkdir(parents=True, mode=0o755)
        if scenario == "source-drift":
            original = case.installer.preflight
            count = [0]

            def preflight():
                count[0] += 1
                if count[0] == 2:
                    (case.source / "fdb.py").write_text("# changed after review\n")
                return original()

            case.installer.preflight = preflight
        if scenario == "enablement":
            original = case.system.ctl

            def ctl(*args, **kwargs):
                if args[0] == "is-enabled" and case.system.started:
                    return SimpleNamespace(stdout="disabled")
                return original(*args, **kwargs)

            case.system.ctl = ctl
        if scenario == "valid-link":
            link = case.units / "timers.target.wants" / module.TIMER
            link.parent.mkdir(parents=True)
            link.symlink_to(case.units / module.TIMER)
            original = Path.lstat

            def lstat(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path == link:
                    fields = list(result)
                    fields[4] = 0
                    return os.stat_result(fields)
                return result

            with (
                patch.object(Path, "lstat", lstat),
                patch.object(
                    module.os.path,
                    "realpath",
                    return_value=str(case.units / module.TIMER),
                ),
            ):
                assert case.installer.install()["status"] == "dry_run"
        else:
            with pytest.raises(module.InstallError):
                case.installer.install(apply=True)
    finally:
        case.tearDown()
