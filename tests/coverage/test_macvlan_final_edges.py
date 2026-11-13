"""Repair races preserve dependency ownership and refuse unproven restarts."""

from contextlib import ExitStack
import copy
from pathlib import Path
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "services/network-recovery"
sys.path.insert(0, str(ROOT))
import macvlan as m
import test_macvlan as cases


@pytest.mark.parametrize(
    "scenario,reason",
    [
        ("no-dependency", "namespace_rebuilt"),
        ("unknown", "candidate_not_enrolled"),
        ("dependency-restarting", "dependency_restarting"),
        ("dependency-stopped", "namespace_rebuilt"),
        ("stop-unconfirmed", "dependency_stop_not_confirmed"),
        ("parent-before", "parent_changed_before_restart"),
        ("container-before", "container_changed_before_restart"),
        ("recovered", "recovered_before_restart"),
        ("degraded", "present_address_readiness_degraded"),
        ("same-namespace", "namespace_not_rebuilt"),
        ("orphan", "command_timeout"),
        ("parent-resume", "readiness_timeout"),
        ("stop-ownership", "readiness_timeout"),
    ],
)
def test_repair_races_keep_each_owned_dependency_outcome_explicit(scenario, reason):
    h = cases.Harness(dependency_running=scenario != "dependency-stopped")
    config = copy.deepcopy(cases.CONFIG)
    if scenario == "no-dependency":
        config["containers"][0].pop("dependency")
    with ExitStack() as stack:
        for item in h.patches():
            stack.enter_context(item)
        candidate = m.observe(config)["candidates"][0]
        if scenario == "unknown":
            candidate["kind"] = "unknown"
        if scenario == "dependency-restarting":
            h.containers["nodered"]["State"]["Restarting"] = True
        real_run = h.run
        real_inspect = h.inspect
        real_ready = h.ready
        seen = {"network": 0, "hass": 0, "interface": 0}

        def network(cfg):
            seen["network"] += 1
            value = copy.deepcopy(cases.NET)
            if (scenario == "parent-before" and seen["network"] == 2) or (
                scenario == "parent-resume" and seen["network"] >= 3
            ):
                value["parent_ifindex"] += 1
            return value

        def inspect(name):
            value = real_inspect(name)
            if name.removesuffix("-id") == "hass":
                seen["hass"] += 1
                if scenario == "container-before" and seen["hass"] >= 2:
                    value["Image"] = "sha256:independent-change"
            return value

        def run(args, timeout=15):
            if args[1] == "stop" and scenario == "stop-unconfirmed":
                return ""
            if args[1] == "restart" and scenario == "orphan":
                raise m.RecoveryError("command_timeout", orphan_pid=12345)
            return real_run(args, timeout)

        def interface(identity, address):
            seen["interface"] += 1
            return (
                "eth2"
                if scenario in ("recovered", "degraded") and seen["interface"] >= 2
                else h.interface(identity, address)
            )

        def ready(before, entry, cfg, net):
            if entry["name"] == "hass" and scenario in (
                "parent-resume",
                "stop-ownership",
            ):
                if scenario == "stop-ownership":
                    h.containers["nodered"]["State"]["FinishedAt"] = "unrelated stop"
                raise m.RecoveryError("readiness_timeout")
            result, checks = real_ready(before, entry, cfg, net)
            if entry["name"] == "hass" and scenario == "same-namespace":
                result["sandbox"] = before["sandbox"]
            return result, checks

        with (
            patch.object(m, "_network_guard", side_effect=network),
            patch.object(m, "_inspect", side_effect=inspect),
            patch.object(m, "_run", side_effect=run),
            patch.object(m, "_interface", side_effect=interface),
            patch.object(m, "_wait_ready", side_effect=ready),
            patch.object(
                m, "_readiness", return_value={"listener": scenario != "degraded"}
            ),
        ):
            result = m.repair(candidate, config, h.record)
        assert result["reason"] == reason
        if scenario in (
            "unknown",
            "dependency-restarting",
            "stop-unconfirmed",
            "parent-before",
            "container-before",
            "recovered",
            "degraded",
        ):
            assert not any(args[1] == "restart" for args in h.commands)
        if scenario in ("orphan", "parent-resume", "stop-ownership"):
            assert not result["dependency_restored"]
            assert not any(args[1] == "start" for args in h.commands)


@pytest.mark.parametrize(
    "scenario", ["network", "configured-address", "configured-ipam", "absent-network"]
)
def test_endpoint_configuration_conflicts_are_never_normalized(scenario):
    cfg = copy.deepcopy(cases.CONFIG)
    entry = cfg["containers"][0]
    container = cases.container(entry)
    if scenario == "network":
        container["NetworkSettings"]["Networks"]["macvlan_100"]["NetworkID"] = "other"
    else:
        entry["static_networks"] = {"mqtt": "10.0.2.10"}
        if scenario == "configured-address":
            container["NetworkSettings"]["Networks"]["mqtt"]["IPAddress"] = "10.0.2.11"
        if scenario == "configured-ipam":
            container["NetworkSettings"]["Networks"]["mqtt"]["IPAMConfig"][
                "IPv4Address"
            ] = "10.0.2.11"
        if scenario == "absent-network":
            container["NetworkSettings"]["Networks"].pop("mqtt")
    with pytest.raises(m.RecoveryError):
        m._entry_identity(container, entry, cfg, cases.NET)


def test_read_adapter_unique_container_and_bad_observation_remain_bounded():
    with patch.object(m, "_json", return_value=[{"Id": "fixture"}]):
        assert m._inspect("fixture") == {"Id": "fixture"}
    result = m.observe({})
    assert result["healthy"] is False and not result["candidates"] and result["issues"]
