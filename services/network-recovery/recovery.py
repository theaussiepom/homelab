#!/usr/bin/env python3
"""Local, bounded Docker network recovery. Audit by default; --apply enables repairs."""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import uuid

import fdb
import macvlan
import probe

MODULES = {"fdb": fdb, "macvlan": macvlan}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def atomic_json(path, value, mode=0o600):
    """Durable replacement; directories are installer-owned, never NAS-backed."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing symlink: " + str(path))
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_json(argv):
    out = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10)
    return json.loads(out.stdout)


def validate_config(config):
    if config.get("schema") != 1 or config.get("hostname") != "ben-beast":
        raise ValueError("Unsupported configuration/host")
    policy = config["policy"]
    bounds = {"stable_seconds": (60, 600), "fault_seconds": (60, 600),
              "cooldown_seconds": (900, 86400), "max_repairs_per_hour": (1, 6)}
    for key, (minimum, maximum) in bounds.items():
        if type(policy[key]) is not int or not minimum <= policy[key] <= maximum:
            raise ValueError("Unsafe policy: " + key)
    if not 1 <= len(config["links"]) <= 4:
        raise ValueError("Expected bounded link inventory")
    for link in config["links"]:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", link["name"]):
            raise ValueError("Invalid interface name")
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", link["mac"]):
            raise ValueError("Invalid expected MAC")
    if len(config.get("probes", [])) > 8:
        raise ValueError("Too many probes")


def links_observe(config):
    facts = []
    for expected in config["links"]:
        links = run_json(["ip", "-j", "-d", "link", "show", "dev", expected["name"]])
        if len(links) != 1:
            raise ValueError("Link identity not unique")
        link = links[0]
        if link.get("address") != expected["mac"]:
            raise ValueError("Unexpected adapter identity: " + expected["name"])
        if expected.get("vlan") is not None:
            info = link.get("linkinfo", {})
            if info.get("info_kind") != "vlan" or info.get("info_data", {}).get("id") != expected["vlan"]:
                raise ValueError("Unexpected VLAN identity")
        if not {"UP", "LOWER_UP"}.issubset(link.get("flags", [])):
            raise ValueError("Link not ready: " + expected["name"])
        if Path("/sys/class/net", expected["name"], "carrier").read_text().strip() != "1":
            raise ValueError("Carrier not ready")
        facts.append({"name": link["ifname"], "index": link["ifindex"], "mac": link["address"]})
    return facts


class Engine:
    def __init__(self, config, directory, *, clock=time.monotonic, boot=None):
        self.config = config
        self.directory = Path(directory)
        self.clock = clock
        self.boot = boot or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.state_file = self.directory / "state.json"
        self.state = {"schema": 1, "boot": self.boot, "seen": {}, "attempts": [], "halted": False}
        if self.state_file.exists():
            self.state = json.loads(self.state_file.read_text())
            if self.state.get("schema") != 1:
                raise ValueError("Unsupported persistent state; manual review needed")
        if self.state.get("pending"):
            self.state["halted"] = True
            self.state["halt_reason"] = "An earlier operation was interrupted; inspect its receipt"
        if self.state.get("boot") != self.boot:
            # A host reboot does not permit replay of an uncertain operation.
            self.state.update(boot=self.boot, seen={}, stable=None)
        config_hash = fingerprint(config)
        if self.state.get("config_hash") != config_hash:
            self.state.update(config_hash=config_hash, seen={}, stable=None)
        self.state["attempts"] = self.state.get("attempts", [])[-200:]

    def save(self):
        atomic_json(self.state_file, self.state)

    def observe_links(self):
        return links_observe(self.config)

    def observe_modules(self):
        result = {}
        for name, module in MODULES.items():
            try:
                result[name] = module.observe(self.config)
            except Exception as exc:
                result[name] = {"healthy": False, "candidates": [],
                                "issues": [{"reason": "observation_failed", "error": type(exc).__name__}]}
        return result

    def observe_probes(self):
        return probe.observe(self.config)

    def publish(self, report):
        report.update(at=utc(), schema=1, host=self.config["hostname"],
                      halted=self.state.get("halted", False),
                      last_repair=self.state.get("last_repair"),
                      last_success=self.state.get("last_success"))
        atomic_json(self.directory / "status.json", report, 0o644)
        signature = fingerprint({k: report.get(k) for k in ("healthy", "phase", "halted", "issues")})
        if signature != self.state.get("last_status_signature"):
            # Only transitions enter journal; avoid repeating an unchanged fault every 30 seconds.
            print(json.dumps({"event": "status", "at": report["at"], "healthy": report["healthy"],
                              "phase": report["phase"], "halted": report["halted"]}), file=sys.stderr)
            self.state["last_status_signature"] = signature
        self.save()
        return report

    def tick(self, apply=False, acknowledge=False):
        now = self.clock()
        previous = self.state.get("last_observed")
        # The settling interval must contain recent observations, not merely
        # elapsed time while the timer was stopped or the host suspended.
        if previous is None or not 0 <= now - previous <= 120:
            self.state.update(stable=None, seen={})
        self.state["last_observed"] = now
        report = {"healthy": False, "phase": "observing", "mode": "apply" if apply else "audit"}
        if self.state.get("halted") and not acknowledge:
            # Especially important after an unreaped I/O helper: do not spawn
            # another probe every timer tick while waiting for inspection.
            return self.publish({**report, "phase": "manual_review_required",
                                 "halt_reason": self.state.get("halt_reason"),
                                 "issues": self.state.get("halt_details", [])})
        try:
            links = self.observe_links()
        except Exception as exc:
            self.state.update(stable=None, seen={})
            return self.publish({**report, "phase": "waiting_for_network", "issues": [str(exc)[:250]]})
        generation = fingerprint(links)
        stable = self.state.get("stable")
        if not stable or stable["generation"] != generation or now < stable["since"]:
            self.state["stable"] = {"generation": generation, "since": now}
            self.state["seen"] = {}
        observations = self.observe_modules()
        probes = self.observe_probes()
        candidates = []
        issues = []
        for kind, observation in observations.items():
            issues += [{"kind": kind, "detail": issue} for issue in observation.get("issues", [])]
            if any(isinstance(issue, dict) and issue.get("orphan_pid") for issue in observation.get("issues", [])):
                self.state.update(halted=True, halt_reason="An observation subprocess could not be reaped; inspect status before resuming",
                                  halt_details=observation.get("issues", []))
            for candidate in observation.get("candidates", []):
                if candidate.get("kind") != kind or not isinstance(candidate.get("identity"), dict):
                    raise ValueError("Invalid candidate contract")
                candidates.append(candidate)
        seen = {}
        for candidate in candidates:
            key = candidate["key"]
            digest = fingerprint(candidate["identity"])
            old = self.state.get("seen", {}).get(key, {})
            same = old.get("fingerprint") == digest and now >= old.get("since", now + 1)
            seen[key] = {"fingerprint": digest, "since": old["since"] if same else now}
        self.state["seen"] = seen
        network_healthy = all(value.get("healthy") for value in observations.values()) and not candidates
        path_healthy = all(value.get("healthy") for value in probes)
        healthy = network_healthy and path_healthy
        report.update(links=links, modules=observations, probes=probes, issues=issues,
                      healthy=healthy and not self.state.get("halted"),
                      stable_seconds=round(now - self.state["stable"]["since"], 1))
        if acknowledge:
            if apply or not healthy:
                raise ValueError("Acknowledge requires a healthy audit; inspect/resolve the fault first")
            self.state.update(halted=False, pending=None, halt_reason=None, halt_details=[])
            report["healthy"] = True
        if self.state.get("halted"):
            report.update(phase="manual_review_required", halt_reason=self.state.get("halt_reason"))
            return self.publish(report)
        if healthy:
            self.state["last_success"] = utc()
            report["phase"] = "healthy"
            return self.publish(report)
        if not apply:
            report["phase"] = "degraded_audit"
            return self.publish(report)
        policy = self.config["policy"]
        if report["stable_seconds"] < policy["stable_seconds"]:
            report["phase"] = "settling"
            return self.publish(report)
        # Rate limits survive reboot using UTC timestamps. A clock moving backwards is conservative.
        epoch = time.time()
        attempts = self.state["attempts"]
        if sum(epoch - item["epoch"] < 3600 for item in attempts) >= policy["max_repairs_per_hour"]:
            report["phase"] = "rate_limited"
            return self.publish(report)
        selected = None
        # FDB first: it does not stop applications. At most one repair transaction per invocation.
        for candidate in sorted(candidates, key=lambda item: (item["kind"] != "fdb", item["key"])):
            if now - seen[candidate["key"]]["since"] < policy["fault_seconds"]:
                continue
            if any(item["key"] == candidate["key"] and epoch - item["epoch"] < policy["cooldown_seconds"]
                   for item in attempts):
                continue
            selected = candidate
            break
        if selected is None:
            report["phase"] = "degraded_no_eligible_repair"
            return self.publish(report)
        # Last-moment link-generation guard, independent of each repair's endpoint guards.
        if fingerprint(self.observe_links()) != generation:
            self.state.update(stable=None, seen={})
            report["phase"] = "network_changed"
            return self.publish(report)
        operation = uuid.uuid4().hex
        receipt = {"operation": operation, "started_at": utc(), "candidate": selected, "steps": []}
        self.state["pending"] = operation
        self.state["attempts"].append({"key": selected["key"], "epoch": epoch, "operation": operation})
        self.save()  # A crash from here must never cause an unattended repeat.
        receipt_path = self.directory / "receipts" / (operation + ".json")

        def record(phase, detail=None):
            receipt["steps"].append({"at": utc(), "phase": phase, "detail": detail or {}})
            atomic_json(receipt_path, receipt)

        record("intent_saved")
        try:
            result = MODULES[selected["kind"]].repair(selected, self.config, record)
            record("repair_returned", result)
            if (result.get("deferred") is True and result.get("mutation_attempted") is False
                    and result.get("changed") is False and not result.get("orphan_pid")
                    and not result.get("pending_dependency")):
                # A proven unavailable prerequisite is a wait, not an uncertain
                # repair. Do not spend the mutation budget or leave a pending stop.
                self.state["pending"] = None
                self.state["attempts"] = [x for x in self.state["attempts"] if x.get("operation") != operation]
                self.state["seen"][selected["key"]]["since"] = self.clock()
                report.update(phase="waiting_for_dependency", deferred=result)
                return self.publish(report)
            if result.get("success") is not True:
                raise RuntimeError("Repair acceptance not satisfied")
            record("repair_verified", result)
            self.state.update(pending=None, last_repair={"at": utc(), "kind": selected["kind"],
                                                      "key": selected["key"], "operation": operation})
            # Fresh complete observation required; command success alone is not full recovery.
            report["modules"] = self.observe_modules()
            report["probes"] = self.observe_probes()
            report["issues"] = [{"kind": kind, "detail": issue}
                                for kind, item in report["modules"].items() for issue in item.get("issues", [])]
            report["healthy"] = all(x.get("healthy") for x in report["modules"].values()) and all(
                x.get("healthy") for x in report["probes"])
            report["phase"] = "recovered" if report["healthy"] else "repair_verified_services_pending"
            if any(isinstance(x["detail"], dict) and x["detail"].get("orphan_pid") for x in report["issues"]):
                self.state.update(halted=True, halt_reason="Post-repair observation subprocess could not be reaped",
                                  halt_details=report["issues"])
                report.update(healthy=False, phase="manual_review_required")
            if report["healthy"]:
                self.state["last_success"] = utc()
        except Exception as exc:
            record("failed_manual_review_required", {"error": type(exc).__name__, "message": str(exc)[:500]})
            self.state.update(halted=True, halt_reason="Repair failed or uncertain; inspect receipt " + operation)
            report.update(healthy=False, phase="manual_review_required", operation=operation)
        return self.publish(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/homelab/network-recovery.json")
    parser.add_argument("--state-dir", default="/var/lib/homelab-network-recovery")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--acknowledge", action="store_true", help="Clear a reviewed halt only after a healthy audit")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root on the configured host")
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.umask(0o077)
    config = json.loads(Path(args.config).read_text())
    validate_config(config)
    if socket.gethostname() != config["hostname"]:
        parser.error("Wrong host")
    directory = Path(args.state_dir)
    for path in (directory, directory / "receipts"):
        if path.is_symlink():
            parser.error("State paths cannot be symlinks")
        path.mkdir(parents=True, exist_ok=True, mode=0o755 if path == directory else 0o700)
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            parser.error("State paths must be root owned and not group/world writable")
    lock_fd = os.open(directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"healthy": False, "phase": "already_running"}))
            return 2
        try:
            engine = Engine(config, directory)
            report = engine.tick(apply=args.apply, acknowledge=args.acknowledge)
        except Exception as exc:
            report = {"schema": 1, "at": utc(), "healthy": False, "phase": "observation_error",
                      "error": type(exc).__name__, "message": str(exc)[:500]}
            atomic_json(directory / "status.json", report, 0o644)
            print(json.dumps(report))
            return 1
        # The daemon records status transitions on stderr and the full current
        # report on disk. Healthy timer runs must not flood the journal.
        if not args.apply:
            print(json.dumps(report))
        return 0 if report["healthy"] else 2


if __name__ == "__main__":
    sys.exit(main())
