"""Policy-only maintenance through the existing job, locks and original receipts."""

from contextlib import ExitStack
import fcntl
import json
import os
import re
import shlex
import subprocess

from bitwarden_startup_guest import admitted, require

SCHEMA = "homelab-bitwarden-startup-v1"


def packet(value):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "revision",
            "source_revision",
            "vmid",
            "plan_sha256",
            "bitwarden_complete_sha256",
            "public_origin",
            "container",
        }
    )
    require(
        value["schema"] == SCHEMA
        and type(value["vmid"]) is int
        and value["vmid"] >= 100
        and value["vmid"] not in {900, 4914, 4915, 4920}
    )
    for key in ("revision", "source_revision"):
        require(
            isinstance(value[key], str) and re.fullmatch("[0-9a-f]{40}", value[key])
        )
    for key in ("plan_sha256", "bitwarden_complete_sha256"):
        require(
            isinstance(value[key], str) and re.fullmatch("[0-9a-f]{64}", value[key])
        )
    container = value["container"]
    require(
        isinstance(container, dict)
        and set(container) == {"id", "name", "image", "fingerprint_sha256"}
    )
    for key in ("id", "fingerprint_sha256"):
        require(
            isinstance(container[key], str)
            and re.fullmatch("[0-9a-f]{64}", container[key])
        )
    require(
        isinstance(container["image"], str)
        and re.fullmatch("sha256:[0-9a-f]{64}", container["image"])
        and isinstance(container["name"], str)
        and re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container["name"])
        and isinstance(value["public_origin"], str)
        and value["public_origin"].startswith("https://")
    )
    return value


def remote(cfg, helper, selected, observe=False):
    """Strict existing SSH trust; raw inspect/environment never leaves the guest."""
    code = (helper / "bitwarden_startup_guest.py").read_text()
    command = ["python3", "-B", "-c", code]
    if observe:
        command += ["--observe", selected["container"]["id"]]
    argv = ["ssh", "-T", "-F", "/dev/null", "-i", cfg["paths"]["private_key"]]
    for option in (
        "IdentitiesOnly=yes",
        "ForwardAgent=no",
        "BatchMode=yes",
        "ControlMaster=no",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "VerifyHostKeyDNS=no",
        "UpdateHostKeys=no",
        "ConnectTimeout=10",
        "ConnectionAttempts=1",
        "UserKnownHostsFile=" + cfg["paths"]["known_hosts"],
    ):
        argv += ["-o", option]
    argv += ["root@" + cfg["app"]["address"], shlex.join(command)]
    result = subprocess.run(
        argv,
        input=json.dumps(selected["container"]),
        text=True,
        capture_output=True,
        timeout=50,
        check=True,
    )
    require(len(result.stdout.encode()) <= 16384)
    return json.loads(result.stdout)


def run(
    deployment,
    fc,
    cfg,
    site,
    helper,
    selected,
    state_root,
    nas_root,
    expected,
    config,
    execute=remote,
):
    settings = packet(selected)
    work = state_root / str(settings["vmid"])
    fc.private_directory(work)
    fc.private_directory(site.parent)
    with ExitStack() as locks:
        for name in ("bitwarden.lock", "workflow.lock", "deployment.lock"):
            lock = locks.enter_context(
                os.fdopen(
                    os.open(
                        work / name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
                    ),
                    "w",
                )
            )
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(
            not any(
                (work / name).exists() or (work / name).is_symlink()
                for name in (*fc.HOLDS, "BITWARDEN-CD-HOLD.json")
            )
        )
        # Maintenance cannot create or change the original guest trust record.
        fc.regular(work / "ssh-trust.json", private=True)
        require(
            cfg["app"]["kind"] == "bitwarden"
            and cfg["app"]["bitwarden"]["public_origin"] == settings["public_origin"]
        )
        plan = expected(deployment, fc, cfg, site, work, settings)
        stack = json.loads(fc.regular(site.parent / "stack.json", private=True))
        committed = json.loads(config.read_bytes())
        clean_stack = json.loads(json.dumps(stack))
        clean_stack["services"]["bitwarden"]["environment"] = {}
        require(
            set(committed)
            == {"schema", "enabled", "site", "stack", "approved_plan_sha256"}
            and committed["schema"] == "homelab-bitwarden-deployment-v1"
            and committed["enabled"] is True
            and committed["site"] == cfg
            and committed["stack"] == clean_stack
            and committed["approved_plan_sha256"] == settings["plan_sha256"]
        )
        nas = nas_root(cfg)
        raw = fc.regular(work / "bitwarden-complete.json", private=True)
        completion = json.loads(raw)
        query = fc.regular(
            work / "rendered/bitwarden-database-query.json", private=True
        )
        require(
            fc.digest(raw) == settings["bitwarden_complete_sha256"]
            and fc.regular(nas / "bitwarden-complete.json", private=True) == raw
            and completion["status"] == "passed"
            and completion["binding"]
            == {
                "prepared_sha256": deployment.sha(site.parent / "prepared.json"),
                "source_sha256": plan["source_sha256"],
                "input_hashes": plan["input_hashes"],
                "vmid": settings["vmid"],
            }
            and completion["plan_sha256"] == settings["plan_sha256"]
            and completion["state_sha256"] == deployment.sha(work / "terraform.tfstate")
            and completion["rollout_sha256"]
            == deployment.sha(work / "rollout-complete.json")
            and completion["database_query_sha256"] == fc.digest(query)
            and fc.regular(nas / "bitwarden-database-query.json", private=True) == query
        )
        before = {
            p: fc.regular(p, private=True)
            for p in (
                site,
                site.parent / "stack.json",
                site.parent / "prepared.json",
                *(
                    work / name
                    for name in (
                        "plan.json",
                        "applied.json",
                        "started.json",
                        "ssh-trust.json",
                        "terraform.tfstate",
                        "rollout-complete.json",
                        "bitwarden-complete.json",
                    )
                ),
                work / "rendered/bitwarden-database-query.json",
                nas / "bitwarden-complete.json",
                nas / "bitwarden-database-query.json",
            )
        }
        claim, done = (
            work / ("bitwarden-startup-" + name + ".json")
            for name in ("claim", "complete")
        )
        encoded = fc.encoded(settings)
        completed = done.exists() or done.is_symlink()
        if completed:
            require(
                fc.regular(claim, private=True)
                == fc.regular(done, private=True)
                == encoded
                and fc.regular(nas / claim.name, private=True) == encoded
                and fc.regular(nas / done.name, private=True) == encoded
                and fc.regular(work / "bitwarden-startup-result.json", private=True)
                == fc.regular(nas / "bitwarden-startup-result.json", private=True)
            )
        else:
            # Exclusive claims block every failed/interrupted attempt, even at a new helper revision.
            fc.write_new(claim, encoded)
            fc.write_new(nas / claim.name, encoded)
            require(fc.regular(nas / claim.name, private=True) == encoded)
        marker = work / "CONTINUATION-HOLD.json"
        fc.write_new(marker, encoded)
        result = execute(cfg, helper, settings, observe=completed)
        current = result if completed else result["container"]
        admitted(settings["container"], current)
        require(
            current["restart"] == "unless-stopped"
            and current["running"] is True
            and (
                completed
                or result["status"] == "passed"
                and type(result["changed"]) is bool
            )
            and all(fc.regular(p, private=True) == data for p, data in before.items())
        )
        if not completed:
            fc.write_new(work / "bitwarden-startup-result.json", fc.encoded(result))
            fc.write_new(nas / "bitwarden-startup-result.json", fc.encoded(result))
            require(
                fc.regular(nas / "bitwarden-startup-result.json", private=True)
                == fc.encoded(result)
            )
            fc.write_new(done, encoded)
            fc.write_new(nas / done.name, encoded)
            require(fc.regular(nas / done.name, private=True) == encoded)
        require(fc.regular(marker, private=True) == encoded)
        marker.unlink()
        fc.sync(work)
        return {
            "status": "passed",
            "changed": False if completed else result["changed"],
            "public_origin": settings["public_origin"],
            "client_acceptance_verified": False,
        }
