#!/usr/bin/env python3
"""Install only the fixed BenBeast recovery payload; dry-run unless --apply."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys

SERVICE = "homelab-network-recovery.service"
TIMER = "homelab-network-recovery.timer"
RUNTIME = Path("/usr/local/lib/homelab-network-recovery")
CONFIG = Path("/etc/homelab/network-recovery.json")
STATE = Path("/var/lib/homelab-network-recovery")
UNITS = Path("/etc/systemd/system")
REQUIRED = {
    "recovery.py": (RUNTIME / "recovery.py", 0o755),
    "fdb.py": (RUNTIME / "fdb.py", 0o755),
    "macvlan.py": (RUNTIME / "macvlan.py", 0o755),
    "probe.py": (RUNTIME / "probe.py", 0o755),
    "network-recovery.json": (CONFIG, 0o644),
    SERVICE: (UNITS / SERVICE, 0o644),
    TIMER: (UNITS / TIMER, 0o644),
}


class InstallError(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def secure_path(path: Path, *, uid: int = 0, leaf_file: bool = False) -> None:
    """Reject symlinks, non-root or writable path components, and odd leaves."""
    if not path.is_absolute() or ".." in path.parts:
        raise InstallError("destination must be an absolute normalized path")
    for item in [*reversed(path.parents), path]:
        try:
            st = item.lstat()
        except FileNotFoundError:
            continue
        is_leaf = item == path
        if stat.S_ISLNK(st.st_mode):
            raise InstallError(f"symlink destination component: {item}")
        if st.st_uid != uid or st.st_mode & 0o022:
            raise InstallError(f"unsafe destination ownership or permissions: {item}")
        expected_file = is_leaf and leaf_file
        if expected_file:
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise InstallError(f"destination is not a unique regular file: {item}")
        elif not stat.S_ISDIR(st.st_mode):
            raise InstallError(f"destination component is not a directory: {item}")


def source_bytes(path: Path) -> bytes:
    # Staging may be owned by the invoking operator, but a symlink cannot redirect it.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 2 * 1024 * 1024:
            raise InstallError(f"unsafe or oversized source: {path.name}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int, *, uid: int = 0, gid: int = 0) -> None:
    secure_path(path, uid=uid, leaf_file=True)
    tmp = path.parent / ("." + path.name + ".install-" + secrets.token_hex(6))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


class System:
    def run(self, args: list[str], *, check: bool = True, timeout: int = 30):
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if check and result.returncode:
            # Only fixed commands are used; avoid spilling a core audit's config into output.
            raise InstallError(f"command failed ({result.returncode}): {args[0]} {args[1]}")
        return result

    def ctl(self, *args: str, check: bool = True):
        return self.run(["/usr/bin/systemctl", *args], check=check)


def audit_healthy(result) -> dict:
    if result.returncode != 0:
        raise InstallError("audit did not exit successfully; timer will not be enabled")
    try:
        report = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise InstallError("audit did not return a JSON health report") from exc
    if not isinstance(report, dict) or report.get("healthy") is not True:
        raise InstallError("audit did not explicitly report healthy=true")
    return {"returncode": 0, "healthy": True, "stdout_sha256": sha(result.stdout.encode())}


class Installer:
    def __init__(self, source: Path, system: System | None = None):
        self.source = source
        self.system = system or System()
        self.files = dict(REQUIRED)
        self.payload: dict[str, bytes] = {}

    def local_filesystems(self) -> dict:
        # Read mount metadata without traversing a possibly unavailable NFS or
        # autofs path. Longest-prefix resolution also covers absent destinations.
        result = self.system.run(["/usr/bin/findmnt", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE"])
        mounts = json.loads(result.stdout).get("filesystems")
        if not isinstance(mounts, list) or not mounts:
            raise InstallError("findmnt did not return mount metadata")
        selected = {}
        for path in (RUNTIME, CONFIG, STATE, UNITS):
            matches = [item for item in mounts if isinstance(item.get("target"), str)
                       and path.is_relative_to(Path(item["target"]))]
            if not matches or any(item.get("fstype") == "autofs" for item in matches):
                raise InstallError(f"missing or automounted destination filesystem: {path}")
            item = max(matches, key=lambda entry: len(Path(entry["target"]).parts))
            if item.get("fstype") not in ("ext4", "xfs", "btrfs") or not str(item.get("source", "")).startswith("/dev/"):
                raise InstallError(f"destination is not a supported local block filesystem: {path}")
            selected[str(path)] = {key: item[key] for key in ("target", "source", "fstype")}
        return selected

    def preflight(self) -> None:
        if os.geteuid() != 0:
            raise InstallError("installer must run as root, including dry-run")
        if socket.gethostname() != "ben-beast":
            raise InstallError("installer is restricted to hostname ben-beast")
        self.mounts = self.local_filesystems()
        for name, (target, _) in self.files.items():
            secure_path(target, leaf_file=True)
            self.payload[name] = source_bytes(self.source / name)
            if name.endswith(".py"):
                compile(self.payload[name], name, "exec")
        if not isinstance(json.loads(self.payload["network-recovery.json"]), dict):
            raise InstallError("configuration must be a JSON object")
        for path in (STATE, STATE / "installations", UNITS / "timers.target.wants"):
            secure_path(path)
        link = UNITS / "timers.target.wants" / TIMER
        if link.is_symlink():
            if link.lstat().st_uid != 0 or Path(os.path.realpath(link)) != UNITS / TIMER:
                raise InstallError("unexpected timer enablement symlink")
        elif link.exists():
            raise InstallError("timer enablement path is not a managed symlink")

    def unit_state(self) -> dict:
        state = {}
        for unit in (SERVICE, TIMER):
            result = self.system.ctl("show", unit, "--property=DropInPaths", "--value", check=False)
            if result.stdout.strip():
                raise InstallError(f"unexpected unit drop-ins: {unit}")
            result = self.system.ctl("show", unit, "--property=FragmentPath", "--value", check=False)
            fragment = result.stdout.strip()
            if fragment and fragment != str(UNITS / unit):
                raise InstallError(f"unit is managed elsewhere: {unit}")
            result = self.system.ctl("is-active", unit, check=False)
            active = result.stdout.strip()
            if active not in ("active", "inactive", "failed", "unknown"):
                raise InstallError(f"unsupported unit active state: {unit}")
            state[unit] = {"active": active}
        enabled = self.system.ctl("is-enabled", TIMER, check=False).stdout.strip()
        if enabled not in ("enabled", "disabled", "not-found"):
            raise InstallError("unsupported or masked timer enablement state")
        state[TIMER]["enabled"] = enabled
        return state

    def mkdir(self, path: Path, mode: int) -> None:
        secure_path(path)
        missing = []
        walk = path
        while not walk.exists():
            missing.append(walk)
            walk = walk.parent
        for item in reversed(missing):
            item.mkdir(mode=mode if item == path else 0o755)
            os.chown(item, 0, 0)
            fsync_dir(item.parent)
        secure_path(path)

    def install(self, *, apply: bool = False) -> dict:
        self.preflight()
        before = self.unit_state()
        plan = [{"source": name, "target": str(target), "mode": oct(mode),
                 "sha256": sha(self.payload[name])} for name, (target, mode) in self.files.items()]
        if not apply:
            return {"status": "dry_run", "host": "ben-beast", "files": plan,
                    "units_before": before, "audit_required_before_timer": True,
                    "destination_filesystems": self.mounts,
                    "runtime_state_preserved": True}
        self.mkdir(STATE, 0o755)
        lock_path = STATE / ".installation.lock"
        secure_path(lock_path, leaf_file=True)
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(lock_fd, 0, 0)
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstallError("another installation holds the installation lock") from exc
            # Recheck after obtaining the lock; another completed install may have
            # changed unit state since the read-only plan was gathered.
            source_hashes = {name: sha(data) for name, data in self.payload.items()}
            self.preflight()
            if source_hashes != {name: sha(data) for name, data in self.payload.items()}:
                raise InstallError("staged sources changed during preflight")
            return self.apply_locked(plan, self.unit_state())
        finally:
            os.close(lock_fd)

    def apply_locked(self, plan: list[dict], before: dict) -> dict:
        self.mkdir(STATE / "installations", 0o700)
        if stat.S_IMODE((STATE / "installations").stat().st_mode) != 0o700:
            raise InstallError("installation evidence directory must have mode 0700")
        directory = STATE / "installations" / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4))
        self.mkdir(directory, 0o700)
        receipt = {"status": "started", "host": "ben-beast", "files": plan,
                   "units_before": before, "runtime_state_preserved": True, "backups": {},
                   "destination_filesystems": self.mounts}
        receipt_path = directory / "receipt.json"

        def save():
            atomic_write(receipt_path, (json.dumps(receipt, indent=2) + "\n").encode(), 0o600)

        save()
        written = []
        core_fd = None

        def acquire_core():
            lock = STATE / "lock"
            secure_path(lock, leaf_file=True)
            fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BaseException:
                os.close(fd)
                raise

        try:
            if before[TIMER]["active"] == "active":
                self.system.ctl("stop", TIMER)
            current = self.system.ctl("is-active", SERVICE, check=False).stdout.strip()
            if current not in ("inactive", "failed", "unknown"):
                raise InstallError("recovery service is running; no files changed")
            try:
                core_fd = acquire_core()
            except BlockingIOError as exc:
                raise InstallError("recovery core lock is held; no files changed") from exc
            for name, (target, mode) in self.files.items():
                self.mkdir(target.parent, 0o755)
                secure_path(target, leaf_file=True)
                if target.exists():
                    st = target.stat()
                    data = source_bytes(target)
                    backup = directory / (name + ".before")
                    atomic_write(backup, data, 0o600)
                    receipt["backups"][name] = {"path": str(backup), "sha256": sha(data),
                                                "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
                else:
                    receipt["backups"][name] = None
                save()
                # Roll back even if replace succeeds but its durability fsync raises.
                written.append(name)
                atomic_write(target, self.payload[name], mode)
            self.system.run(["/usr/bin/systemd-analyze", "verify", str(UNITS / SERVICE), str(UNITS / TIMER)])
            os.close(core_fd)
            core_fd = None  # The default audit acquires this same core lock itself.
            audit = self.system.run(["/usr/bin/python3", str(RUNTIME / "recovery.py"), "--config", str(CONFIG),
                                     "--state-dir", str(STATE)], check=False, timeout=360)
            receipt["audit"] = audit_healthy(audit)
            save()
            self.system.ctl("daemon-reload")
            self.system.ctl("enable", TIMER)
            self.system.ctl("start", TIMER)
            if self.system.ctl("is-enabled", TIMER, check=False).stdout.strip() != "enabled":
                raise InstallError("timer enablement did not verify")
            if self.system.ctl("is-active", TIMER, check=False).stdout.strip() != "active":
                raise InstallError("timer activation did not verify")
            receipt["status"] = "installed"
            receipt["timer_enabled"] = True
            receipt["timer_started"] = True
            receipt["production_repairs_invoked_by_installer"] = False
            save()
            return {"status": "installed", "receipt": str(receipt_path), "audit_healthy": True}
        except Exception as exc:
            receipt["status"] = "failed"
            receipt["error_type"] = type(exc).__name__
            receipt["reason"] = str(exc)
            failures = []
            # Disable the new schedule before restoring exact managed bytes.
            for args in (("stop", TIMER), ("disable", TIMER)):
                try:
                    self.system.ctl(*args)
                except Exception as rollback_error:
                    failures.append(str(rollback_error))
            safe_to_restore = True
            if written:
                try:
                    active = self.system.ctl("is-active", SERVICE, check=False).stdout.strip()
                    if active not in ("inactive", "failed", "unknown"):
                        raise InstallError("recovery service is active; payload rollback deferred")
                    if core_fd is None:
                        core_fd = acquire_core()
                except Exception as rollback_error:
                    safe_to_restore = False
                    failures.append("managed files left in place: " + str(rollback_error))
            for name in reversed(written) if safe_to_restore else []:
                target = self.files[name][0]
                try:
                    backup = receipt["backups"][name]
                    if backup is None:
                        secure_path(target, leaf_file=True)
                        target.unlink()
                        fsync_dir(target.parent)
                    else:
                        data = source_bytes(Path(backup["path"]))
                        if sha(data) != backup["sha256"]:
                            raise InstallError("backup checksum mismatch")
                        atomic_write(target, data, backup["mode"], uid=backup["uid"], gid=backup["gid"])
                except Exception as rollback_error:
                    failures.append(str(rollback_error))
            try:
                self.system.ctl("daemon-reload")
                if before[TIMER]["enabled"] == "enabled" and not failures:
                    self.system.ctl("enable", TIMER)
                if before[TIMER]["active"] == "active" and not failures:
                    self.system.ctl("start", TIMER)
            except Exception as rollback_error:
                failures.append(str(rollback_error))
            receipt["rollback"] = {"complete": not failures, "errors": failures,
                                    "runtime_state_preserved": True}
            save()
            raise InstallError(f"installation failed; rollback complete={not failures}; receipt={receipt_path}") from exc
        finally:
            if core_fd is not None:
                os.close(core_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="install and enable only after a healthy audit")
    args = parser.parse_args()
    try:
        print(json.dumps(Installer(Path(__file__).resolve().parent).install(apply=args.apply)))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
