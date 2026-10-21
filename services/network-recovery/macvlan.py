"""Bounded repair of missing static macvlan addresses on explicitly enrolled containers.

No detach/attach, recreation, image pull, daemon restart or application configuration
change. The caller owns debounce, locking, persistent attempts/cooldowns and status.
TCP readiness is transport/application-listener evidence, not authenticated app health.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import time


class RecoveryError(RuntimeError):
    def __init__(self, reason: str, **details):
        super().__init__(reason)
        self.reason = reason
        self.details = details


def _run(argv: list[str], timeout: float = 15) -> str:
    """Bound subprocess lifetime, including a child stuck in uninterruptible I/O.

    An orphan_pid in a returned error MUST suppress further repairs until inspected.
    Never emit command stderr, which can include private resolved configuration.
    """
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
    try:
        stdout, _ = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            raise RecoveryError("command_timeout_unreaped", orphan_pid=child.pid) from None
        raise RecoveryError("command_timeout") from None
    if child.returncode:
        raise RecoveryError("command_failed", executable=Path(argv[0]).name,
                            exit_code=child.returncode)
    return stdout


def _json(argv: list[str], timeout: float = 15):
    try:
        return json.loads(_run(argv, timeout))
    except (ValueError, TypeError):
        raise RecoveryError("invalid_command_json") from None


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _cfg(config: dict) -> dict:
    value = config.get("macvlan", config)
    if not isinstance(value, dict):
        raise RecoveryError("invalid_macvlan_config")
    for key in ("network", "parent"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value.get(key, "")):
            raise RecoveryError("invalid_network_config", field=key)
    entries = value.get("containers", [])
    names = set()
    for entry in entries:
        for key in ("name", "project", "service"):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", entry.get(key, "")):
                raise RecoveryError("invalid_container_config", field=key)
        if entry["name"] in names:
            raise RecoveryError("duplicate_container_config")
        names.add(entry["name"])
        ipaddress.IPv4Address(entry["static_ipv4"])
        if not 1 <= int(entry["ready_port"]) <= 65535:
            raise RecoveryError("invalid_ready_port")
        ready_network = entry.get("ready_network", value["network"])
        if ready_network != value["network"] and ready_network not in entry.get("static_networks", {}):
            raise RecoveryError("readiness_network_not_declared")
        for address in entry.get("static_networks", {}).values():
            ipaddress.IPv4Address(address)
    for entry in entries:
        if entry.get("dependency") and (entry["dependency"] not in names or entry["dependency"] == entry["name"]):
            raise RecoveryError("invalid_dependency")
    return value


def _inspect(name: str) -> dict:
    result = _json(["docker", "inspect", name])
    if len(result) != 1:
        raise RecoveryError("container_not_unique")
    return result[0]


def _network_guard(config: dict) -> dict:
    network = _json(["docker", "network", "inspect", config["network"]])[0]
    if network.get("Name") != config["network"] or network.get("Driver") != "macvlan" or network.get("Scope") != "local":
        raise RecoveryError("network_identity_conflict")
    if network.get("Options", {}).get("parent") != config["parent"]:
        raise RecoveryError("network_parent_conflict")
    link = _json(["ip", "-j", "-d", "link", "show", "dev", config["parent"]])
    if len(link) != 1 or link[0].get("operstate") != "UP" or "LOWER_UP" not in link[0].get("flags", []):
        raise RecoveryError("parent_not_ready")
    if Path(f"/sys/class/net/{config['parent']}/carrier").read_text().strip() != "1":
        raise RecoveryError("parent_no_carrier")
    return {"network_id": network["Id"], "parent_ifindex": link[0]["ifindex"],
            "parent_address": link[0].get("address"), "parent_link": link[0].get("link"),
            "parent_linkinfo": link[0].get("linkinfo", {})}


def _entry_identity(container: dict, entry: dict, config: dict, network: dict) -> dict:
    state = container["State"]
    running = state.get("Running", False)
    labels = container.get("Config", {}).get("Labels", {}) or {}
    if container.get("Name", "").lstrip("/") != entry["name"] or labels.get("com.docker.compose.project") != entry["project"] or labels.get("com.docker.compose.service") != entry["service"]:
        raise RecoveryError("container_identity_conflict", name=entry["name"])
    endpoint = container.get("NetworkSettings", {}).get("Networks", {}).get(config["network"])
    if not endpoint or endpoint.get("NetworkID") != network["network_id"]:
        raise RecoveryError("container_network_conflict", name=entry["name"])
    if ((running and endpoint.get("IPAddress") != entry["static_ipv4"])
            or (endpoint.get("IPAMConfig") or {}).get("IPv4Address") != entry["static_ipv4"]):
        raise RecoveryError("static_address_conflict", name=entry["name"])
    fixed = dict(entry.get("static_networks", {}))
    fixed[config["network"]] = entry["static_ipv4"]
    networks, runtime_static = {}, {}
    for name, ep in container["NetworkSettings"]["Networks"].items():
        networks[name] = {k: ep.get(k) for k in ("NetworkID", "Aliases", "DriverOpts", "GwPriority", "Links")}
        if name in fixed:
            if running and ep.get("IPAddress") != fixed[name]:
                raise RecoveryError("configured_address_conflict", name=entry["name"], network=name)
            configured_ip = (ep.get("IPAMConfig") or {}).get("IPv4Address")
            if configured_ip != fixed[name]:
                raise RecoveryError("configured_ipam_conflict", name=entry["name"], network=name)
            networks[name]["configured_ipv4"] = fixed[name]
            # Runtime leases, gateway, prefix and generated MAC clear during stop.
            # Preserve explicit IPAM requests; Docker-managed leases may change.
            networks[name]["configured_ipam"] = ep.get("IPAMConfig")
            if running:
                runtime_static[name] = {k: ep.get(k) for k in ("IPAddress", "IPPrefixLen", "Gateway", "GlobalIPv6Address", "GlobalIPv6PrefixLen", "IPv6Gateway")}
    if not set(fixed).issubset(networks):
        raise RecoveryError("configured_network_absent")
    return {"id": container["Id"], "image": container["Image"], "name": entry["name"],
            "project": entry["project"], "service": entry["service"],
            "config_hash": _hash(container["Config"]),
            "host_config_hash": _hash(container["HostConfig"]),
            "mounts_hash": _hash(sorted(container.get("Mounts", []), key=lambda x: x["Destination"])),
            "restart_policy": container["HostConfig"].get("RestartPolicy"),
            "networks": networks, "runtime_static": runtime_static, "pid": state.get("Pid"), "started": state.get("StartedAt"),
            "running": state.get("Running", False), "restarting": state.get("Restarting", False),
            "sandbox": container["NetworkSettings"].get("SandboxID")}


def _preserved(before: dict, after: dict) -> bool:
    volatile = {"pid", "started", "running", "restarting", "sandbox", "runtime_static"}
    return {k: v for k, v in before.items() if k not in volatile} == {k: v for k, v in after.items() if k not in volatile}


def _ns(pid: int) -> list[str]:
    if not isinstance(pid, int) or pid <= 0:
        raise RecoveryError("invalid_container_pid")
    return ["nsenter", f"--net=/proc/{pid}/ns/net", "--"]


def _interface(identity: dict, address: str) -> str | None:
    links = _json(_ns(identity["pid"]) + ["ip", "-j", "address", "show"])
    matches = [link["ifname"] for link in links
               if any(a.get("local") == address for a in link.get("addr_info", []))]
    if len(matches) > 1:
        raise RecoveryError("duplicate_kernel_address")
    return matches[0] if matches else None


class _DockerConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=10)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/var/run/docker.sock")


def _stats(identity: dict) -> bool:
    connection = _DockerConnection()
    try:
        connection.request("GET", f"/containers/{identity['id']}/stats?stream=false&one-shot=true")
        response = connection.getresponse()
        # Bound size and discard details; the response may contain arbitrary labels.
        body = response.read(2 * 1024 * 1024 + 1)
        return response.status == 200 and len(body) <= 2 * 1024 * 1024
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def _multicast(pid: int, interface: str) -> set[str]:
    groups, current = set(), None
    for line in Path(f"/proc/{pid}/net/igmp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields and fields[0].isdigit() and len(fields) >= 3 and fields[2] == ":":
            current = fields[1]
        elif current == interface and fields and re.fullmatch(r"[0-9A-Fa-f]{8}", fields[0]):
            groups.add(socket.inet_ntoa(struct.pack("=I", int(fields[0], 16))))
    return groups


def _readiness(identity: dict, entry: dict) -> dict:
    interface = _interface(identity, entry["static_ipv4"])
    result = {"kernel_address": bool(interface), "stats": False, "listener": False,
              "routes": False, "multicast": False}
    if not interface:
        return result
    result["stats"] = _stats(identity)
    script = "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3);s.close()"
    # Several services deliberately bind their UI only to a declared overlay IP.
    # The LAN address is still required for discovery, independently of UI binding.
    ready_network = entry.get("ready_network")
    ready_address = entry.get("static_networks", {}).get(ready_network, entry["static_ipv4"])
    try:
        _run(_ns(identity["pid"]) + ["/usr/bin/python3", "-c", script,
                                     ready_address, str(entry["ready_port"])], 5)
        result["listener"] = True
    except RecoveryError as exc:
        if exc.details.get("orphan_pid"):
            raise
    routes = _json(_ns(identity["pid"]) + ["ip", "-j", "route", "show"])
    result["routes"] = any(r.get("dst") == "default" for r in routes)
    for target in entry.get("route_targets", []):
        ipaddress.ip_address(target)
        route = _json(_ns(identity["pid"]) + ["ip", "-j", "route", "get", target])
        result["routes"] = result["routes"] and bool(route) and route[0].get("dev") == interface
    expected_groups = set(entry.get("multicast_groups", []))
    result["multicast"] = not expected_groups or expected_groups.issubset(_multicast(identity["pid"], interface))
    return result


def _nas(config: dict):
    mount = config["nas_mount"]
    source = config["nas_source"]
    probe = config["nas_probe_file"]
    if not mount.startswith("/") or not probe.startswith(mount.rstrip("/") + "/"):
        raise RecoveryError("invalid_nas_probe_path")
    observed = _json(["findmnt", "--json", "--mountpoint", mount, "-o", "TARGET,SOURCE,FSTYPE"])
    mounts = observed.get("filesystems", [])
    if len(mounts) != 1 or mounts[0].get("source") != source or mounts[0].get("fstype") not in ("nfs", "nfs4"):
        raise RecoveryError("nas_mount_mismatch")
    # GNU stat requests forced metadata synchronization rather than accepting cache.
    _run(["/usr/bin/stat", "--cached=never", "--format=%i:%s:%Y", "--", probe], 5)
    # Read a bounded amount of the known non-secret probe; return no file content.
    _run(["/usr/bin/python3", "-c", "import sys; f=open(sys.argv[1],'rb'); f.read(4096); f.close()", probe], 5)


def observe(config: dict) -> dict:
    candidates, issues, states = [], [], []
    try:
        cfg = _cfg(config)
        network = _network_guard(cfg)
    except (RecoveryError, OSError, ValueError, KeyError) as exc:
        return {"healthy": False, "candidates": [], "issues": [{"reason": getattr(exc, "reason", type(exc).__name__), **getattr(exc, "details", {})}]}
    for entry in cfg["containers"]:
        try:
            current = _inspect(entry["name"])
            identity = _entry_identity(current, entry, cfg, network)
            if not identity["running"] or identity["restarting"]:
                states.append({"name": entry["name"], "state": "not_running_enrollment_unchanged"})
                issues.append({"name": entry["name"], "reason": "enrolled_container_not_running", "automatic_start": False})
                continue
            interface = _interface(identity, entry["static_ipv4"])
            if not interface:
                candidates.append({"kind": "macvlan", "key": f"macvlan:{entry['project']}:{entry['service']}:{cfg['network']}",
                                   "name": entry["name"], "identity": identity, "network_identity": network,
                                   "reason": "declared_static_address_missing"})
                states.append({"name": entry["name"], "state": "missing_kernel_address"})
            else:
                checks = _readiness(identity, entry)
                states.append({"name": entry["name"], "state": "kernel_address_present", "readiness": checks})
                if not all(checks.values()):
                    issues.append({"name": entry["name"], "reason": "present_address_readiness_degraded", "readiness": checks, "automatic_restart": False})
        except (RecoveryError, OSError, ValueError, KeyError) as exc:
            issues.append({"name": entry["name"], "reason": getattr(exc, "reason", type(exc).__name__), **getattr(exc, "details", {})})
    if candidates:
        try:
            _nas(cfg)
        except (RecoveryError, OSError, ValueError, KeyError) as exc:
            # An unavailable prerequisite is not a failed recovery attempt. Wait
            # until a fresh NAS read succeeds; an unreaped probe is still fatal
            # to the caller, which recognizes orphan_pid in an issue.
            candidates.clear()
            issues.append({"reason": "nas_prerequisite_unavailable",
                           "cause": getattr(exc, "reason", type(exc).__name__),
                           **getattr(exc, "details", {})})
    return {"healthy": not candidates and not issues, "candidates": candidates, "issues": issues, "containers": states}


def _wait_ready(before: dict, entry: dict, cfg: dict, network: dict) -> tuple[dict, dict]:
    deadline = time.monotonic() + min(180, max(1, int(entry.get("ready_timeout_seconds", 120))))
    successes, latest, checks = 0, None, {}
    while time.monotonic() < deadline:
        latest = _entry_identity(_inspect(before["id"]), entry, cfg, network)
        if not _preserved(before, latest):
            raise RecoveryError("post_restart_identity_conflict")
        if latest["running"] and not latest["restarting"]:
            if latest["runtime_static"] != before["runtime_static"]:
                raise RecoveryError("post_restart_static_network_changed")
            checks = _readiness(latest, entry)
            successes = successes + 1 if all(checks.values()) else 0
            if successes >= 2:
                return latest, checks
        else:
            successes = 0
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise RecoveryError("readiness_timeout", checks=checks)


def repair(candidate: dict, config: dict, record) -> dict:
    """One repair attempt. Caller must not retry uncertain/incomplete mutations blindly."""
    result = {"kind": "macvlan", "key": candidate.get("key"), "ok": False,
              "success": False, "changed": False, "mutation_attempted": False}
    dependency = None
    dependency_stop_owned = False
    dependency_stop_finished = None
    checking_nas = False
    cfg = _cfg(config)
    entries = {x["name"]: x for x in cfg["containers"]}
    entry = entries.get(candidate.get("name"))
    if candidate.get("kind") != "macvlan" or not entry:
        return {**result, "reason": "candidate_not_enrolled"}
    try:
        network = _network_guard(cfg)
        if network != candidate["network_identity"]:
            raise RecoveryError("network_changed_since_observation")
        before = _entry_identity(_inspect(entry["name"]), entry, cfg, network)
        if before != candidate["identity"] or not before["running"] or before["restarting"]:
            raise RecoveryError("container_changed_since_observation")
        if _interface(before, entry["static_ipv4"]):
            checks = _readiness(before, entry)
            passed = all(checks.values())
            return {**result, "ok": passed, "success": passed, "reason": "already_recovered" if passed else "present_address_readiness_degraded", "readiness": checks}
        checking_nas = True
        _nas(cfg)
        checking_nas = False
        if entry.get("dependency"):
            dep_entry = entries[entry["dependency"]]
            dep_container = _inspect(dep_entry["name"])
            dependency = _entry_identity(dep_container, dep_entry, cfg, network)
            if dependency["restarting"]:
                raise RecoveryError("dependency_restarting")
            if dependency["running"]:
                record("dependency_stop_prepared", {"dependency": dependency, "candidate": candidate["key"]})
                # Mark ownership before the request: a timeout may still have stopped it.
                dependency_stop_owned = True
                result.update(mutation_attempted=True, changed=True)
                _run(["docker", "stop", "--timeout", "60", dependency["id"]], 75)
                stopped = _inspect(dependency["id"])
                stopped_identity = _entry_identity(stopped, dep_entry, cfg, network)
                if not _preserved(dependency, stopped_identity) or stopped_identity["running"]:
                    raise RecoveryError("dependency_stop_not_confirmed")
                dependency_stop_finished = stopped["State"].get("FinishedAt")
                record("dependency_stopped", {"identity": stopped_identity, "finished": dependency_stop_finished})
        # Recheck immediately before the mutation, after any dependency stop.
        checking_nas = True
        _nas(cfg)
        checking_nas = False
        if _network_guard(cfg) != network:
            raise RecoveryError("parent_changed_before_restart")
        current = _entry_identity(_inspect(before["id"]), entry, cfg, network)
        if current != before:
            raise RecoveryError("container_changed_before_restart")
        if _interface(current, entry["static_ipv4"]):
            checks = _readiness(current, entry)
            result.update(ok=all(checks.values()), reason="recovered_before_restart" if all(checks.values()) else "present_address_readiness_degraded", readiness=checks)
        else:
            record("restart_prepared", {"identity": before, "network_identity": network})
            result.update(mutation_attempted=True, changed=True)
            _run(["docker", "restart", "--timeout", "60", before["id"]], 90)
            record("restart_returned", {"id": before["id"]})
            after, checks = _wait_ready(before, entry, cfg, network)
            if after["started"] == before["started"] or after["sandbox"] == before["sandbox"]:
                raise RecoveryError("namespace_not_rebuilt")
            record("restart_verified", {"identity": after, "readiness": checks})
            result.update(ok=True, reason="namespace_rebuilt", readiness=checks, id=after["id"])
    except (RecoveryError, OSError, ValueError, KeyError) as exc:
        result.update(reason=getattr(exc, "reason", type(exc).__name__), **getattr(exc, "details", {}))
        if checking_nas and not result["mutation_attempted"] and not result.get("orphan_pid"):
            result["deferred"] = True
        record("repair_deferred" if result.get("deferred") else "repair_failed", result)
    finally:
        if dependency and dependency_stop_owned:
            try:
                if result.get("orphan_pid"):
                    raise RecoveryError("unreaped_probe_dependency_resume_deferred")
                fresh_network = _network_guard(cfg)
                if fresh_network != candidate["network_identity"]:
                    raise RecoveryError("parent_changed_dependency_resume_deferred")
                _nas(cfg)
                dep_entry = entries[dependency["name"]]
                current = _inspect(dependency["id"])
                dep_now = _entry_identity(current, dep_entry, cfg, fresh_network)
                if not _preserved(dependency, dep_now):
                    raise RecoveryError("dependency_identity_changed")
                if not dep_now["running"]:
                    # A failed/uncertain stop cannot establish exclusive ownership;
                    # retain an actionable journal instead of guessing about a later stop.
                    if not dependency_stop_finished or current["State"].get("FinishedAt") != dependency_stop_finished:
                        raise RecoveryError("dependency_stop_ownership_uncertain")
                    record("dependency_start_prepared", {"identity": dep_now, "finished": dependency_stop_finished})
                    _run(["docker", "start", dependency["id"]], 45)
                    record("dependency_start_returned", {"id": dependency["id"]})
                    resumed, checks = _wait_ready(dependency, dep_entry, cfg, fresh_network)
                    record("dependency_resumed", {"identity": resumed, "readiness": checks})
                else:
                    resumed, checks = _wait_ready(dependency, dep_entry, cfg, fresh_network)
                    record("dependency_already_running", {"identity": resumed, "readiness": checks})
                result["dependency_restored"] = True
            except (RecoveryError, OSError, ValueError, KeyError) as exc:
                result.update(ok=False, dependency_restored=False,
                              pending_dependency={"identity": dependency, "stop_finished": dependency_stop_finished},
                              dependency_error=getattr(exc, "reason", type(exc).__name__),
                              **getattr(exc, "details", {}))
                record("dependency_resume_failed", result)
    result["success"] = bool(result["ok"])
    record("repair_complete", result)
    return result
