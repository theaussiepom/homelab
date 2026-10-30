"""Per-guest custody: locks, immutable phase receipts and durable failure holds."""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import coordinated_contract
import coordinated_evidence
import coordinated_generation
from custody_records import no_markers, read_existing
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


def bootstrap_closed(root=Path("/var/lib/homelab-bootstrap")):
    if root.exists() or root.is_symlink():
        require(root.is_dir() and not root.is_symlink(), "Preserve bootstrap maintenance custody")
        no_markers(root, bootstrap=True)


class DeploymentAttempt:
    """Own an existing state directory and one GitHub run's ordered phase evidence."""

    def __init__(self, cfg, binding, phases):
        self.cfg = cfg
        self.custody = coordinated_contract.selection(cfg)
        self.custody_identity = None
        self.initial_ordinary = None
        self.receipt_checked = self.custody is None
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
                private_directory(directory)
                no_markers(directory, own_ordinary=directory == self.work)
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
            for child in self.work.iterdir():
                if child.name.startswith("database-"):
                    require(not child.is_symlink(), "Preserve unexpected nested custody")
                    if child.is_dir():
                        private_directory(child)
                        no_markers(child)
            require(
                not any(self.work.glob("database-*/*HOLD.json")),
                "Preserve a nested database operation hold",
            )
            matched = False
            for directory in coordinated:
                if self.vmid in coordinated_members(directory):
                    require(self.custody is not None and directory.name == self.custody["directory"] and not matched,
                            "This guest belongs to coordinated maintenance; preserve its custody before mutation")
                    matched = True
            self._require_backend()
            if self.custody is not None:
                require(matched, "The selected completed group is missing")
                proofs, lineage, self.initial_ordinary = coordinated_evidence.inspect(self.cfg)
                require(all(self.binding["input_hashes"].get(path) == value for path, value in proofs.items())
                        and self.binding.get("coordinated_custody_sha256") == coordinated_contract.selection_digest(self.cfg),
                        "Coordinated immutable evidence changed before admission")
                from proxmox_guest import guest_trust
                read_existing(Path(self.cfg["paths"]["known_hosts"]))
                guest_trust(self.cfg, self.work, persist=False)
                member = self.custody["members"][self.cfg["app"]["kind"]]
                self.custody_identity = coordinated_generation.classify(self, member, lineage, self.initial_ordinary)
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
        if self.initial_ordinary is not None and (self.receipt.exists() or self.receipt.is_symlink()):
            if read_existing(self.receipt) == self.initial_ordinary:
                self.receipt_checked = True
                return False
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
                self.receipt_checked = True
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
                self.receipt_checked = True
                return True
        self.receipt_checked = True
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
        if hasattr(self, "previous_ordinary_sha256"):
            self.marker["previous_ordinary_sha256"] = self.previous_ordinary_sha256

    def begin_infrastructure(self):
        require(self.receipt_checked, "Validate ordinary receipt provenance before mutation")
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
        if self.custody_identity is not None:
            member = self.custody["members"][self.cfg["app"]["kind"]]
            state_hash, identity = coordinated_generation.backend(self.work, member)
            require(identity == self.custody_identity and result["state_sha256"] == state_hash,
                    "The applied backend differs from its admitted identity")
            result = dict(result, state_identity=identity)
        write_new(
            self.operation / "infrastructure-complete.json",
            encoded({"binding": self.binding, **result}),
        )

    def begin_phase(self, phase):
        require(self.receipt_checked, "Validate ordinary receipt provenance before mutation")
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
        if self.custody_identity is not None:
            receipt["state_identity"] = ready["state_identity"]
        write_new(self.operation / "complete.json", encoded(receipt))
        replace_receipt(self.receipt, receipt)
        require(
            regular(self.hold, private=True) == encoded(self.marker),
            "Deployment hold ownership changed",
        )
        self.hold.unlink()
        sync(self.work)
        return changed
