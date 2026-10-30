"""Guarded Proxmox LXC plans, trusted identity and state recovery copies."""

import json
from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import shutil
import ssl
import stat
import subprocess
import time
from urllib.parse import urlparse
from urllib.request import (
    Request,
    build_opener,
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
)
import discovery
import guest_identity
import host_devices
from guest_contract import SOURCE
from private_io import (
    sha,
    write,
    regular,
    require,
    read_json,
    write_new,
    encoded,
    private_writer,
)
from commands import quiet
from plan_policy import check_plan


class InputNeeded(ValueError):
    """A fixed operator diagnostic without private values."""


class RefuseRedirects(HTTPRedirectHandler):
    """A token-bearing request must stay on its explicitly trusted endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InputNeeded(
            "Proxmox API redirected; inspect its trusted endpoint before continuing"
        )


def api_get(cfg, path):
    """Read only the declared Proxmox endpoint, with its existing CA and token."""
    endpoint = urlparse(cfg["site"]["api_endpoint"])
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.port != 8006
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
        or endpoint.path not in ("", "/")
    ):
        raise ValueError("Guest discovery requires the trusted Proxmox HTTPS endpoint")
    if not path.startswith("/nodes/"):
        raise ValueError("Use the selected Proxmox node API")
    request = Request(
        "https://" + endpoint.netloc + "/api2/json" + path,
        headers={
            "Authorization": "PVEAPIToken="
            + regular(Path(cfg["paths"]["api_token"]), private=True).decode().strip()
        },
    )
    context = ssl.create_default_context(cafile=cfg["paths"]["ca_file"])
    opener = build_opener(
        ProxyHandler({}), HTTPSHandler(context=context), RefuseRedirects()
    )
    with opener.open(request, timeout=15) as response:
        return json.load(response)["data"]


def dhcp_admission(cfg):
    """Verify reviewed DHCP leases through trusted PVE before guest SSH."""
    if any(nic["ipv4"] == "dhcp" for nic in cfg["guest"]["interfaces"]):
        guest_identity.verify_network(cfg, cfg["app"]["address"], lambda p: api_get(cfg, p))


def guest_trust(cfg, work, *, persist=True):
    """Pin this guest after creation; unrelated known_hosts additions are harmless."""
    address = cfg["app"]["address"]
    instruction = "Verify the new guest SSH host key using the trusted Proxmox route, then supply its private known_hosts entry before Ansible"
    if not Path(cfg["paths"]["known_hosts"]).is_file():
        raise InputNeeded(instruction)
    result = subprocess.run(
        ["ssh-keygen", "-F", address, "-f", cfg["paths"]["known_hosts"]],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 1 and not result.stdout:
        raise InputNeeded(instruction)
    if result.returncode != 0:
        raise InputNeeded(
            "Guest host-key lookup failed; inspect the private known_hosts file before continuing"
        )
    output = result.stdout
    keys = []
    for line in output.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if (
            len(parts) < 3
            or parts[0].startswith("@")
            or not (parts[0] == address or parts[0].startswith("|1|"))
        ):
            raise ValueError(
                "Use exact pinned guest host keys; do not introduce a wildcard or SSH CA"
            )
        keys.append(parts[1:3])
    if not keys:
        raise InputNeeded(instruction)
    binding = {"address": address, "keys": sorted(keys)}
    path = work / "ssh-trust.json"
    if path.exists():
        if read_json(path, private=True) != binding:
            raise ValueError(
                "Guest host trust changed; preserve the old binding for review"
            )
    else:
        require(persist, "The existing commissioned guest trust record is required")
        write_new(path, encoded(binding))


@contextmanager
def recovery_directory(cfg):
    """Pin the selected NAS and walk only real directories on its filesystem."""
    mount = Path(cfg["paths"]["backup_mount"])
    destination = Path(cfg["paths"]["backup_directory"]) / str(cfg["guest"]["vmid"])
    require(
        mount.is_absolute() and destination.is_absolute(), "Use absolute recovery paths"
    )
    parts = destination.relative_to(mount).parts
    require(
        parts and not {".", ".."}.intersection(parts),
        "Keep recovery copies below the selected mount",
    )
    if not os.path.ismount(mount):
        raise ValueError(
            "The declared NAS recovery mount is unavailable; no local fallback"
        )
    with ExitStack() as opened:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = mount_fd = os.open(mount, flags)
        opened.callback(os.close, directory)
        original = os.fstat(directory)
        actual = (
            subprocess.check_output(
                ["findmnt", "-rn", "-o", "FSTYPE,SOURCE", "--target", str(mount)],
                text=True,
            )
            .strip()
            .split()
        )
        current = mount.lstat()
        require(
            len(actual) == 2
            and actual[0] in {"nfs", "nfs4", "cifs"}
            and actual[1] == cfg["paths"]["backup_source"]
            and (original.st_dev, original.st_ino) == (current.st_dev, current.st_ino),
            "The recovery mount must match the selected NAS filesystem and source",
        )
        chain = []
        for name in parts:
            try:
                child = os.open(name, flags, dir_fd=directory)
            except FileNotFoundError:
                os.mkdir(name, mode=0o700, dir_fd=directory)
                os.fsync(directory)
                child = os.open(name, flags, dir_fd=directory)
            opened.callback(os.close, child)
            require(
                os.fstat(child).st_dev == original.st_dev,
                "Preserve a different recovery filesystem",
            )
            chain.append((name, os.fstat(child)))
            directory = child
        yield directory
        current = mount.lstat()
        require(
            (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
            "Recovery mount changed during backup",
        )
        parent = mount_fd
        for name, expected in chain:
            child = os.open(name, flags, dir_fd=parent)
            opened.callback(os.close, child)
            current = os.fstat(child)
            require(
                (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino),
                "Recovery path changed during backup",
            )
            parent = child


def backup(cfg, state, label):
    with recovery_directory(cfg) as directory:
        # All writes and readback stay relative to the verified open directory.
        stamp = f"{time.time_ns()}-{label}"
        if state.exists() or state.is_symlink():
            target = f"{stamp}.tfstate"
            fd = os.open(state, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as src:
                require(
                    stat.S_ISREG(os.fstat(src.fileno()).st_mode),
                    "Back up only a regular backend",
                )
                with private_writer(target, exclusive=True, dir_fd=directory) as dst:
                    shutil.copyfileobj(src, dst)
            checksum = sha(target, dir_fd=directory)
            require(checksum == sha(state), "State backup readback differs")
            receipt = {"sha256": checksum, "file": target}
        else:
            receipt = {"state": "not-created", "vmid": cfg["guest"]["vmid"]}
        write_new(f"{stamp}.json", encoded(receipt), dir_fd=directory)


def infrastructure(cfg, site, work, operation, expected, *, state_identity=None):
    """Plan the existing backend; apply only this reviewed guest's safe delta."""
    from deployment_inputs import binding

    host_devices.check(cfg, operation)
    existing = (work / "terraform.tfstate").is_file()
    if existing:
        dhcp_admission(cfg)
    backup(cfg, work / "terraform.tfstate", "before-ordinary")
    shutil.copytree(
        SOURCE / "tofu",
        operation / "tofu",
        ignore=shutil.ignore_patterns(".terraform", "*.tfstate*", "*.tfplan"),
    )
    variables = {k: cfg[k] for k in ("site", "guest", "ssh_public_keys")}
    variables["guest"] = dict(
        {key: value for key, value in cfg["guest"].items() if key != "serial_device"},
        interfaces=[
            {key: value for key, value in nic.items() if key != "ipv4_endpoint"}
            for nic in cfg["guest"]["interfaces"]
        ],
        routing_labels=discovery.labels(cfg),
    )
    write(operation / "tofu/site.auto.tfvars.json", variables)
    environment = os.environ.copy()
    environment.update(
        TF_IN_AUTOMATION="1",
        CHECKPOINT_DISABLE="1",
        SSL_CERT_FILE=cfg["paths"]["ca_file"],
        PROXMOX_VE_API_TOKEN=regular(Path(cfg["paths"]["api_token"]), private=True)
        .decode()
        .strip(),
    )
    tofu = ["tofu", "-chdir=" + str(operation / "tofu")]
    log = operation / "infrastructure.log"
    quiet(
        tofu
        + [
            "init",
            "-input=false",
            "-lockfile=readonly",
            "-backend-config=path=" + str(work / "terraform.tfstate"),
        ],
        environment,
        log,
    )
    quiet(
        tofu
        + [
            "plan",
            "-input=false",
            "-lock-timeout=30s",
            "-out=" + str(operation / "guest.tfplan"),
        ],
        environment,
        log,
    )
    value = json.loads(
        subprocess.check_output(
            tofu + ["show", "-json", str(operation / "guest.tfplan")], env=environment
        )
    )
    check_plan(
        value,
        cfg["site"]["node"],
        cfg["guest"]["vmid"],
        existing=existing,
        serial_device=cfg["guest"].get("serial_device"),
    )
    if state_identity is not None:
        from coordinated_generation import plan_identity
        plan_identity(value, state_identity)
    require(binding(cfg, site) == expected, "Approved inputs changed while planning")
    changed = any(
        row["change"]["actions"] != ["no-op"] for row in value["resource_changes"]
    )
    write(
        operation / "plan.json",
        {
            "binding": expected,
            "plan_sha256": sha(operation / "guest.tfplan"),
            "changed": changed,
            "existing_guest": existing,
        },
    )
    if changed:
        window = {
            "plan_sha256": sha(operation / "guest.tfplan"),
            "started_at_ns": time.time_ns(),
        }
        write(operation / "apply-window.json", window)
        quiet(
            tofu
            + [
                "apply",
                "-input=false",
                "-lock-timeout=30s",
                str(operation / "guest.tfplan"),
            ],
            environment,
            log,
        )
        write(
            operation / "apply-window.json",
            dict(window, finished_at_ns=time.time_ns()),
        )
    if not existing:
        guest_identity.pin(
            cfg, operation, cfg["app"]["address"], lambda p: api_get(cfg, p), write
        )
    changed = host_devices.attach(cfg, operation) or changed
    backup(cfg, work / "terraform.tfstate", "after-ordinary")
    return {
        "changed": changed,
        "created": not existing,
        "state_sha256": sha(work / "terraform.tfstate"),
    }
