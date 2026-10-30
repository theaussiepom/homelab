"""Per-guest custody: locks, immutable phase receipts and durable failure holds."""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from private_io import (
    require,
    regular,
    private_directory,
    write_new,
    encoded,
    sha,
    replace_receipt,
    sync,
)

HOLDS = {
    "HOLD.json",
    "ROLLOUT-HOLD.json",
    "CONTINUATION-HOLD.json",
    "FOUNDATION-HOLD.json",
    "ORDINARY-HOLD.json",
    "SERVICE-VERIFY-HOLD.json",
    "SERVICE-VERIFYING.json",
}


def coordinated_members(directory):
    """Read durable legacy ownership; completion never releases it implicitly."""
    private_directory(directory)
    raw = regular(directory / "request.json", private=True)

    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "Preserve duplicate coordinated custody fields")
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict) and isinstance(value.get("members"), dict),
            "Preserve unrecognized coordinated maintenance custody")
    members = value["members"]
    if value.get("schema") == "homelab-postgresql-cutover-v1":
        require(set(members) == {"postgresql", "identity", "db-tools"},
                "Preserve unrecognized coordinated member roles")
    else:
        require(value.get("schema") == "homelab-database-server-cutover-v1"
                and len(members) == 1 and set(members) <= {"mariadb", "influxdb"},
                "Preserve unrecognized coordinated member roles")
    require(all(isinstance(member, dict) and type(member.get("vmid")) is int
                and member["vmid"] >= 100 and member["vmid"] not in {900, 4914, 4915, 4920}
                for member in members.values()), "Preserve unrecognized coordinated member identities")
    ids = [member["vmid"] for member in members.values()]
    require(len(ids) == len(set(ids)), "Preserve ambiguous coordinated member identities")
    claim = directory / "claim.json"
    if claim.exists() or claim.is_symlink():
        require(regular(claim, private=True) == raw, "Preserve changed coordinated request/claim custody")
    return set(ids)


def bootstrap_closed():
    require(
        not any(
            p.exists() or p.is_symlink()
            for p in (
                Path("/var/lib/homelab-bootstrap/CONFIGURING"),
                Path("/var/lib/homelab-bootstrap/BOOTSTRAP-CD-HOLD.json"),
            )
        ),
        "Preserve bootstrap maintenance custody",
    )


class DeploymentAttempt:
    """Own an existing state directory and one GitHub run's ordered phase evidence."""

    def __init__(self, cfg, binding, phases):
        self.vmid = cfg["guest"]["vmid"]
        self.root = Path(cfg["paths"]["state_root"])
        self.work = self.root / str(cfg["guest"]["vmid"])
        self.binding = binding
        self.phases = phases
        self.hold = self.work / "ORDINARY-HOLD.json"
        self.receipt = self.work / "ordinary-complete.json"
        self.locks = ExitStack()

    def __enter__(self):
        private_directory(self.root)
        private_directory(self.work, create=not self.work.exists())
        try:
            for path, shared in [
                (self.root / "database-network.lock", True),
                (self.work / "workflow.lock", False),
                (self.work / "deployment.lock", False),
            ]:
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stream = self.locks.enter_context(os.fdopen(fd, "a+"))
                fcntl.flock(
                    stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
                )
            coordinated = [*self.root.glob("database-network-cutover-*"),
                           *self.root.glob("database-server-cutover-*")]
            for directory in [self.work, *coordinated]:
                require(
                    not any(
                        p.exists() or p.is_symlink()
                        for p in directory.glob("*HOLD.json")
                        if p != self.hold
                    )
                    and not any(
                        (directory / n).exists() or (directory / n).is_symlink()
                        for n in HOLDS - {"ORDINARY-HOLD.json"}
                    )
                    and not (
                        (directory / "VERIFYING.json").exists()
                        or (directory / "VERIFYING.json").is_symlink()
                    ),
                    "Preserve an unresolved operation or verification hold",
                )
            require(
                not any(self.work.glob("database-*/*HOLD.json")),
                "Preserve a nested database operation hold",
            )
            for directory in coordinated:
                require(self.vmid not in coordinated_members(directory),
                        "This guest belongs to coordinated maintenance; preserve its custody before mutation")
            self._require_backend()
            return self
        except BaseException:
            self.locks.close()
            raise

    def __exit__(self, *exc):
        return self.locks.__exit__(*exc)

    def _require_backend(self):
        """Only an empty guest history may start without its backend."""
        try:
            info = (self.work / "terraform.tfstate").lstat()
        except FileNotFoundError:
            records = [
                self.work / name
                for name in (
                    "ssh-trust.json",
                    "host-key-evidence.json",
                    "plan.json",
                    "applied.json",
                    "started.json",
                    "rollout-complete.json",
                    "foundation-complete.json",
                )
            ]
            records.extend(self.work.glob("ordinary-*"))
            records.extend(self.work.glob("terraform.tfstate.*"))
            require(
                not any(p.exists() or p.is_symlink() for p in records),
                "Guest custody exists without its backend; no automatic recreation",
            )
        else:
            require(
                stat.S_ISREG(info.st_mode),
                "Preserve a backend that is not a regular file",
            )

    def completed(self, is_ancestor):
        if self.receipt.exists() or self.receipt.is_symlink():
            self._select_run()
            old = json.loads(regular(self.receipt, private=True))
            require(
                old.get("workflow") == self.workflow
                and type(old.get("run_number")) is int
                and 0 < old["run_number"] <= self.run_number,
                "Preserve deployment ownership and reject older workflow runs",
            )
            require(
                isinstance(old.get("site_revision"), str)
                and re.fullmatch("[0-9a-f]{40}", old["site_revision"])
                and is_ancestor(
                    self.workspace, old["site_revision"], self.site_revision
                ),
                "Never roll back an already deployed private-source revision",
            )
            if old["run_number"] != self.run_number:
                return False
            require(
                old.get("operation") == str(self.operation)
                and old["site_revision"] == self.site_revision,
                "A completed run cannot replay under another attempt",
            )
            if (
                old.get("status") == "passed"
                and old.get("binding") == self.binding
                and old.get("state_sha256") == sha(self.work / "terraform.tfstate")
            ):
                require(
                    not self.hold.exists() and not self.hold.is_symlink(),
                    "Preserve an interrupted deployment",
                )
                return True
        return False

    def _select_run(self):
        identity = "-".join(
            os.environ.get(k, "") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        )
        require(
            re.fullmatch(r"[1-9][0-9]*-[1-9][0-9]*", identity),
            "Use the identified merge-triggered deployment run",
        )
        number = os.environ.get("GITHUB_RUN_NUMBER", "")
        self.workflow = [
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("HOMELAB_DEPLOYMENT_WORKFLOW", "").partition("@")[0],
        ]
        require(
            re.fullmatch(r"[1-9][0-9]*", number)
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.workflow[0])
            and re.fullmatch(
                re.escape(self.workflow[0])
                + r"/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml",
                self.workflow[1],
            ),
            "Require the identified private workflow and its run sequence",
        )
        self.run_number = int(number)
        self.site_revision = os.environ.get("GITHUB_SHA", "")
        self.workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
        require(
            re.fullmatch("[0-9a-f]{40}", self.site_revision)
            and self.workspace.is_absolute()
            and self.workspace.is_dir(),
            "Require the checked-out private source and immutable revision",
        )
        self.operation = self.work / ("ordinary-" + identity)
        self.marker = {
            "binding": self.binding,
            "operation": str(self.operation),
            "automatic_retry": False,
            "workflow": self.workflow,
            "run_number": self.run_number,
            "site_revision": self.site_revision,
        }

    def begin_infrastructure(self):
        self._select_run()
        require(
            not self.hold.exists()
            and not self.hold.is_symlink()
            and not self.operation.exists(),
            "An existing attempt requires review; no replay",
        )
        private_directory(self.operation, create=True)
        write_new(self.hold, encoded(self.marker))

    def infrastructure_complete(self, result):
        write_new(
            self.operation / "infrastructure-complete.json",
            encoded({"binding": self.binding, **result}),
        )

    def begin_phase(self, phase):
        self._select_run()
        require(
            regular(self.hold, private=True) == encoded(self.marker),
            "Only the same run may complete this attempt",
        )
        ready = json.loads(
            regular(self.operation / "infrastructure-complete.json", private=True)
        )
        require(
            ready["binding"] == self.binding
            and ready["state_sha256"] == sha(self.work / "terraform.tfstate")
            and not (self.operation / (phase + "-started.json")).exists(),
            "Preserve changed or interrupted phase custody",
        )
        for previous in self.phases[: self.phases.index(phase)]:
            require(
                json.loads(
                    regular(
                        self.operation / (previous + "-complete.json"), private=True
                    )
                )["binding"]
                == self.binding,
                "Complete the preceding phase before its consumer",
            )
        write_new(self.operation / (phase + "-started.json"), encoded(self.marker))
        return ready

    def phase_complete(self, phase, result, ready):
        require(
            sha(self.work / "terraform.tfstate") == ready["state_sha256"],
            "Backend state changed during the phase; preserve its hold and evidence",
        )
        write_new(
            self.operation / (phase + "-complete.json"),
            encoded({"binding": self.binding, "result": result}),
        )
        if phase != self.phases[-1]:
            return result["changed"]
        changed = ready["changed"] or any(
            json.loads(regular(self.operation / (p + "-complete.json"), private=True))[
                "result"
            ]["changed"]
            for p in self.phases
        )
        receipt = {
            "status": "passed",
            "binding": self.binding,
            "state_sha256": ready["state_sha256"],
            "result": result,
            "workflow": self.workflow,
            "run_number": self.run_number,
            "site_revision": self.site_revision,
            "operation": str(self.operation),
        }
        write_new(self.operation / "complete.json", encoded(receipt))
        replace_receipt(self.receipt, receipt)
        require(
            regular(self.hold, private=True) == encoded(self.marker),
            "Deployment hold ownership changed",
        )
        self.hold.unlink()
        sync(self.work)
        return changed
