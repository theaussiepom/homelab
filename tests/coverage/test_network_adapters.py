"""Recovery command, namespace and scheduler boundaries use local synthetic adapters."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "services/network-recovery"
sys.path.insert(0, str(ROOT))
import macvlan
import probe
import recovery

CONFIG = json.loads((ROOT / "fixtures/network-recovery.synthetic.json").read_text())


@pytest.mark.parametrize(
    "scenario", ["success", "failed", "timeout", "missing-process", "unreaped"]
)
def test_macvlan_command_lifetime_and_private_output_are_bounded(scenario):
    child = Mock(pid=1234, returncode=7 if scenario == "failed" else 0)
    if scenario in ("success", "failed"):
        child.communicate.return_value = ("ok", "private diagnostics")
    elif scenario == "unreaped":
        child.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 1),
            subprocess.TimeoutExpired("fixture", 1),
        ]
    else:
        child.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 1),
            ("", ""),
        ]
    with (
        patch.object(macvlan.subprocess, "Popen", return_value=child),
        patch.object(
            macvlan.os,
            "killpg",
            side_effect=ProcessLookupError if scenario == "missing-process" else None,
        ),
    ):
        if scenario == "success":
            assert macvlan._run(["fixture"]) == "ok"
        else:
            with pytest.raises(macvlan.RecoveryError) as raised:
                macvlan._run(["fixture"])
            assert "private diagnostics" not in str(raised.value)
            if scenario == "unreaped":
                assert raised.value.details["orphan_pid"] == 1234


def test_macvlan_json_and_unique_inspection_are_strict():
    with patch.object(macvlan, "_run", return_value="{}"):
        assert macvlan._json(["fixture"]) == {}
    with (
        patch.object(macvlan, "_run", return_value="not json"),
        pytest.raises(macvlan.RecoveryError),
    ):
        macvlan._json(["fixture"])
    with (
        patch.object(macvlan, "_json", return_value=[]),
        pytest.raises(macvlan.RecoveryError),
    ):
        macvlan._inspect("fixture")


@pytest.mark.parametrize(
    "scenario",
    [
        "type",
        "network",
        "container",
        "duplicate",
        "port",
        "ready-network",
        "dependency",
    ],
)
def test_macvlan_config_refuses_unbounded_or_inconsistent_identity(scenario):
    cfg = copy.deepcopy(CONFIG["macvlan"])
    if scenario == "type":
        cfg = []
    elif scenario == "network":
        cfg["network"] = "invalid/name"
    elif scenario == "container":
        cfg["containers"][0]["project"] = "invalid/name"
    elif scenario == "duplicate":
        cfg["containers"].append(copy.deepcopy(cfg["containers"][0]))
    elif scenario == "port":
        cfg["containers"][0]["ready_port"] = 0
    elif scenario == "ready-network":
        cfg["containers"][0]["ready_network"] = "undeclared"
    else:
        cfg["containers"][0]["dependency"] = "not-enrolled"
    with pytest.raises(macvlan.RecoveryError):
        macvlan._cfg({"macvlan": cfg})


@pytest.mark.parametrize(
    "scenario",
    ["valid", "source-stopped", "ambiguous-target", "namespace", "probe-failed"],
)
def test_namespace_probe_binds_declared_target_and_open_descriptor(tmp_path, scenario):
    check = {
        "source": "source",
        "target": "target",
        "network": "overlay",
        "protocol": "tcp",
        "port": 80,
    }
    container = {
        "State": {"Running": scenario != "source-stopped"},
        "NetworkSettings": {
            "SandboxKey": (
                "bad" if scenario == "namespace" else "/var/run/docker/netns/fixture"
            )
        },
    }
    tasks = (
        []
        if scenario == "ambiguous-target"
        else [{"Name": "target", "EndpointIP": "198.18.0.2/24"}]
    )
    network = {"Services": {"fixture": {"Tasks": tasks}}}
    namespace = tmp_path / "namespace"
    namespace.touch()
    original_open = open

    def local_open(path, *args, **kwargs):
        return (
            original_open(namespace, *args, **kwargs)
            if str(path).startswith("/var/run/docker/netns/")
            else original_open(path, *args, **kwargs)
        )

    with (
        patch.object(probe, "jrun", side_effect=[[container], [network]]),
        patch("builtins.open", side_effect=local_open),
        patch.object(
            probe.subprocess,
            "run",
            return_value=SimpleNamespace(
                returncode=1 if scenario == "probe-failed" else 0,
                stdout='{"healthy":true}',
            ),
        ) as command,
    ):
        if scenario == "namespace":
            with pytest.raises(ValueError):
                probe.check_one(check)
        else:
            result = probe.check_one(check)
            assert result["healthy"] is (scenario == "valid")
            if scenario == "valid":
                assert command.call_args.kwargs["pass_fds"]


@pytest.mark.parametrize(
    "change", [{"source": "invalid/name"}, {"port": True}, {"protocol": "udp"}]
)
def test_probe_invalid_parameters_never_open_a_socket(change):
    with (
        patch.object(probe.socket, "create_connection") as connect,
        pytest.raises(ValueError),
    ):
        cfg = {
            "source": "source",
            "target": "target",
            "network": "network",
            "address": "198.18.0.2",
            "port": 80,
            **change,
        }
        probe.check_one(cfg) if "source" in change else probe.exchange(cfg)
    connect.assert_not_called()


@pytest.mark.parametrize(
    "scenario",
    [
        "healthy",
        "apply",
        "symlink-state",
        "unhealthy",
        "engine-error",
        "locked",
        "not-root",
        "wrong-host",
        "bad-owner",
    ],
)
def test_scheduler_cli_publishes_failure_and_never_implicitly_repairs(
    tmp_path, scenario, capsys
):
    config = copy.deepcopy(CONFIG)
    config["hostname"] = "ben-beast"
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(config))
    state = tmp_path / "state"
    if scenario == "symlink-state":
        state.symlink_to(tmp_path / "unmanaged", target_is_directory=True)
    native_stat = Path.stat

    def owned_stat(path, *args, **kwargs):
        value = native_stat(path, *args, **kwargs)
        if path in (state, state / "receipts"):
            row = list(value)
            row[4] = 1 if scenario == "bad-owner" else 0
            return os.stat_result(row)
        return value

    engine = Mock()
    engine.tick.return_value = {
        "healthy": scenario in ("healthy", "apply"),
        "phase": "fixture",
    }
    if scenario == "engine-error":
        engine.tick.side_effect = ValueError("synthetic observation failure")
    with (
        patch.object(
            sys,
            "argv",
            [
                "recovery",
                "--config",
                str(cfg),
                "--state-dir",
                str(state),
                *(["--apply"] if scenario == "apply" else []),
            ],
        ),
        patch.object(
            recovery.os, "geteuid", return_value=1 if scenario == "not-root" else 0
        ),
        patch.object(recovery.os, "umask"),
        patch.dict(recovery.os.environ, {}),
        patch.object(
            recovery.socket,
            "gethostname",
            return_value="other" if scenario == "wrong-host" else config["hostname"],
        ),
        patch.object(Path, "stat", owned_stat),
        patch.object(recovery, "Engine", return_value=engine),
        patch.object(
            recovery.fcntl,
            "flock",
            side_effect=BlockingIOError if scenario == "locked" else None,
        ),
    ):
        if scenario in ("not-root", "wrong-host", "bad-owner", "symlink-state"):
            with pytest.raises(SystemExit):
                recovery.main()
        else:
            code = recovery.main()
            assert code == (
                0
                if scenario in ("healthy", "apply")
                else 1 if scenario == "engine-error" else 2
            )
    if scenario == "engine-error":
        assert (
            json.loads((state / "status.json").read_text())["phase"]
            == "observation_error"
        )
    if scenario == "healthy":
        engine.tick.assert_called_once_with(apply=False, acknowledge=False)


@pytest.mark.parametrize(
    "scenario", ["valid", "no-vlan", "not-unique", "mac", "vlan", "flags", "carrier"]
)
def test_link_observation_requires_live_declared_identity(tmp_path, scenario):
    cfg = copy.deepcopy(CONFIG)
    expected = cfg["links"][0]
    cfg["links"] = [expected]
    expected["vlan"] = 25
    if scenario == "no-vlan":
        expected.pop("vlan")
    row = {
        "ifname": expected["name"],
        "ifindex": 2,
        "address": "different" if scenario == "mac" else expected["mac"],
        "flags": [] if scenario == "flags" else ["UP", "LOWER_UP"],
        "linkinfo": {
            "info_kind": "vlan",
            "info_data": {"id": 26 if scenario == "vlan" else 25},
        },
    }
    carrier = tmp_path / "carrier"
    carrier.write_text("0" if scenario == "carrier" else "1")
    with (
        patch.object(
            recovery, "run_json", return_value=[] if scenario == "not-unique" else [row]
        ),
        patch.object(recovery, "Path", return_value=carrier),
    ):
        if scenario in ("valid", "no-vlan"):
            assert recovery.links_observe(cfg)[0]["mac"] == expected["mac"]
        else:
            with pytest.raises(ValueError):
                recovery.links_observe(cfg)


def test_observation_engine_turns_module_failure_into_scoped_evidence(tmp_path):
    engine = recovery.Engine(CONFIG, tmp_path, boot="fixture")
    with (
        patch.object(recovery.fdb, "observe", side_effect=ValueError("fixture")),
        patch.object(recovery.macvlan, "observe", return_value={"healthy": True}),
    ):
        result = engine.observe_modules()
        assert (
            result["fdb"]["issues"][0]["reason"] == "observation_failed"
            and result["macvlan"]["healthy"]
        )
    with patch.object(recovery.probe, "observe", return_value=[]):
        assert engine.observe_probes() == []


@pytest.mark.parametrize("scenario", ["valid", "identity", "parent", "link", "carrier"])
def test_macvlan_network_guard_binds_the_live_parent(tmp_path, scenario):
    cfg = {"network": "fixture", "parent": "eth0.25"}
    network = {
        "Name": "wrong" if scenario == "identity" else "fixture",
        "Id": "fixture-id",
        "Driver": "macvlan",
        "Scope": "local",
        "Options": {"parent": "wrong" if scenario == "parent" else cfg["parent"]},
    }
    link = {
        "ifindex": 2,
        "operstate": "DOWN" if scenario == "link" else "UP",
        "flags": ["LOWER_UP"],
        "address": "02:00:00:00:00:01",
    }
    carrier = tmp_path / "carrier"
    carrier.write_text("0" if scenario == "carrier" else "1")
    with (
        patch.object(macvlan, "_json", side_effect=[[network], [link]]),
        patch.object(macvlan, "Path", return_value=carrier),
    ):
        if scenario == "valid":
            assert macvlan._network_guard(cfg)["network_id"] == "fixture-id"
        else:
            with pytest.raises(macvlan.RecoveryError):
                macvlan._network_guard(cfg)


@pytest.mark.parametrize("count", [0, 1, 2])
def test_kernel_address_lookup_requires_a_unique_interface(count):
    rows = [
        {"ifname": str(i), "addr_info": [{"local": "198.18.0.2"}]} for i in range(count)
    ]
    with patch.object(macvlan, "_json", return_value=rows):
        if count == 2:
            with pytest.raises(macvlan.RecoveryError):
                macvlan._interface({"pid": 123}, "198.18.0.2")
        else:
            assert macvlan._interface({"pid": 123}, "198.18.0.2") == (
                "0" if count else None
            )
    with pytest.raises(macvlan.RecoveryError):
        macvlan._ns(0)


@pytest.mark.parametrize("scenario", ["valid", "oversize", "error", "bad-status"])
def test_docker_stats_request_is_bounded_and_connection_always_closes(scenario):
    connection = Mock()
    connection.getresponse.return_value = SimpleNamespace(
        status=500 if scenario == "bad-status" else 200,
        read=lambda _: (
            b"x" * (2 * 1024 * 1024 + 1) if scenario == "oversize" else b"{}"
        ),
    )
    if scenario == "error":
        connection.request.side_effect = OSError("private detail")
    with patch.object(macvlan, "_DockerConnection", return_value=connection):
        assert macvlan._stats({"id": "fixture-id"}) is (scenario == "valid")
    connection.close.assert_called_once()


def test_docker_connection_uses_only_the_local_unix_socket():
    client = Mock()
    with patch.object(macvlan.socket, "socket", return_value=client):
        connection = macvlan._DockerConnection()
        connection.connect()
    client.connect.assert_called_once_with("/var/run/docker.sock")


def test_multicast_membership_decodes_only_the_selected_interface(tmp_path):
    proc = tmp_path / "igmp"
    proc.write_text(
        "Idx Device : Count\n1 other : 1\n010000E0 1\n2 eth0 : 1\nFB0000E0 1\nnot-hex\n"
    )
    with patch.object(macvlan, "Path", return_value=proc):
        assert macvlan._multicast(123, "eth0") == {"224.0.0.251"}


@pytest.mark.parametrize(
    "scenario", ["valid", "missing", "listener", "unreaped", "wrong-route"]
)
def test_readiness_requires_address_stats_listener_routes_and_multicast(scenario):
    entry = {
        "static_ipv4": "198.18.0.2",
        "ready_port": 80,
        "route_targets": ["198.18.0.3"],
        "multicast_groups": ["224.0.0.251"],
    }
    error = macvlan.RecoveryError(
        "timeout", **({"orphan_pid": 123} if scenario == "unreaped" else {})
    )
    with (
        patch.object(
            macvlan,
            "_interface",
            return_value=None if scenario == "missing" else "eth0",
        ),
        patch.object(macvlan, "_stats", return_value=True),
        patch.object(
            macvlan,
            "_run",
            side_effect=error if scenario in ("listener", "unreaped") else None,
        ),
        patch.object(
            macvlan,
            "_json",
            side_effect=[
                [{"dst": "default"}],
                [{"dev": "wrong" if scenario == "wrong-route" else "eth0"}],
            ],
        ),
        patch.object(macvlan, "_multicast", return_value={"224.0.0.251"}),
    ):
        if scenario == "unreaped":
            with pytest.raises(macvlan.RecoveryError):
                macvlan._readiness({"pid": 123}, entry)
        else:
            result = macvlan._readiness({"pid": 123}, entry)
            assert all(result.values()) is (scenario == "valid")
            if scenario == "missing":
                assert not any(result.values())


@pytest.mark.parametrize("scenario", ["valid", "path", "mount"])
def test_nas_prerequisite_checks_exact_mount_and_reads_without_mutation(scenario):
    cfg = {
        "nas_mount": "/fixture",
        "nas_source": "nas:/fixture",
        "nas_probe_file": "/other" if scenario == "path" else "/fixture/probe",
    }
    with (
        patch.object(
            macvlan,
            "_json",
            return_value={
                "filesystems": [
                    {
                        "source": "other" if scenario == "mount" else "nas:/fixture",
                        "fstype": "nfs4",
                    }
                ]
            },
        ),
        patch.object(macvlan, "_run") as command,
    ):
        if scenario == "valid":
            macvlan._nas(cfg)
            assert command.call_count == 2
        else:
            with pytest.raises(macvlan.RecoveryError):
                macvlan._nas(cfg)
            command.assert_not_called()


@pytest.mark.parametrize(
    "scenario", ["ready", "changed", "static", "timeout", "stopped"]
)
def test_post_restart_wait_requires_preserved_identity_and_two_successes(scenario):
    before = {
        "id": "fixture",
        "running": True,
        "restarting": False,
        "runtime_static": {"fixture": "198.18.0.2"},
    }
    latest = dict(before)
    if scenario == "changed":
        latest["id"] = "other"
    if scenario == "static":
        latest["runtime_static"] = {}
    if scenario == "stopped":
        latest["running"] = False
    times = iter([0, 0, 0, 1, 200, 201])
    with (
        patch.object(macvlan.time, "monotonic", side_effect=lambda: next(times)),
        patch.object(macvlan.time, "sleep"),
        patch.object(macvlan, "_inspect", return_value={}),
        patch.object(macvlan, "_entry_identity", return_value=latest),
        patch.object(
            macvlan, "_readiness", return_value={"healthy": scenario != "timeout"}
        ),
    ):
        if scenario == "ready":
            assert macvlan._wait_ready(before, {}, {}, {})[0] == latest
        else:
            with pytest.raises(macvlan.RecoveryError):
                macvlan._wait_ready(before, {}, {}, {})


@pytest.mark.parametrize("scenario", ["valid", "failed", "malformed", "oversized"])
def test_overlay_reads_bound_process_output_before_json_decoding(scenario):
    import fdb

    result = SimpleNamespace(
        returncode=1 if scenario == "failed" else 0,
        stdout=(
            "{}"
            if scenario == "valid"
            else "x" * (4 * 1024 * 1024 + 1) if scenario == "oversized" else "not json"
        ),
        stderr="",
    )
    with patch.object(fdb.subprocess, "run", return_value=result) as command:
        if scenario == "valid":
            assert fdb._json(["fixture"], fd=12) == {}
            assert command.call_args.kwargs["pass_fds"] == (12,)
            assert command.call_args.kwargs["timeout"] == fdb.TIMEOUT
        else:
            with pytest.raises(fdb.GuardError):
                fdb._json(["fixture"])


def test_overlay_snapshot_binds_routes_to_the_open_namespace(tmp_path):
    import fdb
    import test_fdb as cases

    network, links, neighbours, entries, routes = cases.fixture()
    namespace = tmp_path / ("1-" + network["Id"][:10])
    namespace.touch()

    def command(args, fd=None):
        if args[0] == "docker":
            return [network]
        if args == ["ip", "-j", "route", "get", cases.PEER]:
            return routes[cases.PEER]
        assert fd is not None
        assert str(fd) in args[1]
        return links if "link" in args else neighbours if "neigh" in args else entries

    with (
        patch.object(fdb, "NETNS_ROOT", tmp_path),
        patch.object(fdb, "_json", side_effect=command),
    ):
        result = fdb.observe(cases.CONFIG)
    assert result["candidates"][0]["identity"]["peer"] == cases.PEER
    assert (
        result["candidates"][0]["identity"]["namespace"]["inode"]
        == namespace.stat().st_ino
    )


def test_recovery_install_cli_reports_review_or_failure_without_mutating():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "recovery_install_cli", ROOT / "install.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for failed in (False, True):
        with (
            patch.object(sys, "argv", ["install"]),
            patch.object(
                module.Installer,
                "install",
                **(
                    {"side_effect": ValueError("fixture refusal")}
                    if failed
                    else {"return_value": {"status": "planned"}}
                ),
            ),
            patch("builtins.print") as output,
        ):
            assert module.main() == int(failed)
            value = json.loads(output.call_args.args[0])
            assert value["status"] == ("failed" if failed else "planned")


@pytest.mark.parametrize(
    "scenario",
    [
        "valid",
        "schema",
        "policy",
        "links-empty",
        "links-bound",
        "name",
        "mac",
        "probes",
    ],
)
def test_recovery_policy_refuses_unbounded_inputs_before_any_observation(scenario):
    cfg = copy.deepcopy(CONFIG)
    cfg["hostname"] = "ben-beast"
    if scenario == "schema":
        cfg["schema"] = 2
    if scenario == "policy":
        cfg["policy"]["stable_seconds"] = True
    if scenario == "links-empty":
        cfg["links"] = []
    if scenario == "links-bound":
        cfg["links"] *= 3
    if scenario == "name":
        cfg["links"][0]["name"] = "../unrelated"
    if scenario == "mac":
        cfg["links"][0]["mac"] = "not a MAC"
    if scenario == "probes":
        cfg["probes"] = [{}] * 9
    with patch.object(recovery, "run_json") as observe:
        if scenario == "valid":
            recovery.validate_config(cfg)
        else:
            with pytest.raises(ValueError):
                recovery.validate_config(cfg)
        observe.assert_not_called()


def test_recovery_state_write_and_version_guards_preserve_existing_authority(tmp_path):
    target = tmp_path / "state.json"
    target.write_text('{"schema": 2}')
    with pytest.raises(ValueError, match="Unsupported persistent state"):
        recovery.Engine(CONFIG, tmp_path, boot="fixture")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        recovery.atomic_json(alias, {})
    before = target.read_bytes()
    with patch.object(
        recovery.os, "replace", side_effect=OSError("synthetic rename refusal")
    ):
        with pytest.raises(OSError):
            recovery.atomic_json(target, {"schema": 1})
    assert target.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))
    with patch.object(
        recovery.subprocess,
        "run",
        return_value=SimpleNamespace(stdout='{"healthy":true}'),
    ):
        assert recovery.run_json(["fixture"]) == {"healthy": True}
