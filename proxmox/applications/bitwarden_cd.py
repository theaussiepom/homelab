"""One Bitwarden guest through the existing saved-plan installer; never restore its database."""

import argparse, fcntl, json, os, re
from pathlib import Path
import deploy
import render
import foundation_cd as files
import bitwarden_migration as migration

INPUTS = Path("/var/lib/homelab-inputs/bitwarden")
HOLDS = (*files.HOLDS, "BITWARDEN-CD-HOLD.json")


def prepare_inputs(config, destination=INPUTS, environment=None, runtime_file=None):
    value = migration.read_json(config)
    files.require(
        isinstance(value, dict)
        and set(value) == {"schema", "enabled", "site", "stack", "approved_plan_sha256"}
        and value["schema"] == "homelab-bitwarden-deployment-v1"
        and value["enabled"] is True,
        "Bitwarden deployment is disabled or its concrete migration packet is incomplete",
    )
    cfg, stack = value["site"], value["stack"]
    files.require(
        cfg["app"]["kind"] == stack["kind"] == "bitwarden"
        and cfg["app"]["stack_config"] == str(destination / "stack.json"),
        "Select the fixed private Bitwarden input bundle",
    )
    migration.validate_admission(cfg, stack, runtime=False)
    environment = os.environ if environment is None else environment
    secret = environment.get("BITWARDEN_RUNTIME_JSON")
    if runtime_file is not None:
        files.require(
            not secret,
            "Select one private runtime binding, never two competing sources",
        )
        secret = files.regular(Path(runtime_file), private=True).decode()
    files.require(
        isinstance(secret, str) and 0 < len(secret.encode()) <= 1024 * 1024,
        "Supply the retained private runtime JSON binding",
    )

    def unique(pairs):
        result = {}
        for key, item in pairs:
            files.require(key not in result, "Duplicate runtime environment key")
            result[key] = item
        return result

    original = json.loads(secret, object_pairs_hook=unique)
    files.require(
        stack["services"]["bitwarden"].get("environment", {}) == {},
        "Keep runtime values out of tracked stack inputs",
    )
    stack["services"]["bitwarden"]["environment"] = migration.runtime_environment(
        cfg, stack, original
    )
    migration.validate_admission(cfg, stack)
    compose_sha256 = files.digest(files.encoded(render.compose(stack)))
    deploy.validate(cfg, stack)
    payload = {"site.json": files.encoded(cfg), "stack.json": files.encoded(stack)}
    manifest = {
        "schema": value["schema"],
        "files": {key: files.digest(data) for key, data in payload.items()},
        "compose_sha256": compose_sha256,
    }
    files.private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        files.private_directory(destination)
        files.require(
            {p.name for p in destination.iterdir()} == set(payload) | {"prepared.json"}
            and files.regular(destination / "prepared.json", private=True)
            == files.encoded(manifest)
            and all(
                files.regular(destination / key, private=True) == data
                for key, data in payload.items()
            ),
            "Bitwarden inputs changed or are incomplete; preserve them and do not fill gaps",
        )
    else:
        files.private_directory(destination, create=True)
        for key, data in payload.items():
            files.write_new(destination / key, data)
        files.write_new(destination / "prepared.json", files.encoded(manifest))
    files.require(
        files.digest(
            files.encoded(
                render.compose(
                    migration.read_json(destination / "stack.json", private=True)
                )
            )
        )
        == compose_sha256,
        "Persisted stack render differs from the admitted preflight output",
    )
    return cfg, destination / "site.json"


def run(
    phase,
    config,
    destination=INPUTS,
    environment=None,
    deployment=deploy,
    runtime_file=None,
):
    files.require(
        phase in ("plan", "deploy", "verify"), "Select a bounded Bitwarden phase"
    )
    value = migration.read_json(config)
    approved = value.get("approved_plan_sha256")
    files.require(
        (
            phase != "deploy"
            or isinstance(approved, str)
            and re.fullmatch("[0-9a-f]{64}", approved)
        )
        and (phase != "plan" or approved is None),
        "Deploy needs the exact reviewed saved-plan fingerprint; plan cannot carry an old approval",
    )
    cfg, site = prepare_inputs(config, destination, environment, runtime_file)
    vmid = deployment.validate(cfg)
    work = Path(cfg["paths"]["state_root"]) / str(vmid)
    work.mkdir(parents=True, mode=0o700, exist_ok=True)
    files.private_directory(work)
    fd = os.open(
        work / "bitwarden.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        files.require(
            not any(
                (work / name).exists() or (work / name).is_symlink() for name in HOLDS
            ),
            "A Bitwarden/native operation is held; no automatic retry or continuation",
        )
        binding = {
            "prepared_sha256": files.digest(
                files.regular(destination / "prepared.json", private=True)
            ),
            "source_sha256": deployment.source_hash(),
            "input_hashes": deployment.input_hashes(cfg),
            "vmid": vmid,
        }
        complete = work / "bitwarden-complete.json"
        query = work / "rendered" / "bitwarden-database-query.json"
        query_recovery = Path(cfg["paths"]["backup_directory"]) / str(vmid) / query.name
        recovery = (
            Path(cfg["paths"]["backup_directory"])
            / str(vmid)
            / "bitwarden-complete.json"
        )
        if complete.exists() or complete.is_symlink():
            raw = files.regular(complete, private=True)
            receipt = json.loads(raw)
            files.require(
                files.regular(recovery, private=True) == raw
                and receipt["binding"] == binding
                and receipt["state_sha256"]
                == deployment.sha(work / "terraform.tfstate")
                and receipt["rollout_sha256"]
                == deployment.sha(work / "rollout-complete.json")
                and receipt["database_query_sha256"]
                == files.digest(files.regular(query, private=True))
                and files.regular(query_recovery, private=True)
                == files.regular(query, private=True),
                "Completed Bitwarden state or receipt drifted; no redeployment",
            )
            phase = "verify"
        else:
            files.require(
                phase != "verify",
                "There is no completed Bitwarden installation to verify",
            )
        hold = work / "BITWARDEN-CD-HOLD.json"
        marker = {"phase": phase, "binding": binding, "automatic_retry": False}
        files.write_new(hold, files.encoded(marker))
        if phase == "plan":
            files.require(
                not any(
                    (work / name).exists()
                    for name in (
                        "plan.json",
                        "applied.json",
                        "terraform.tfstate",
                        "started.json",
                    )
                ),
                "Existing Bitwarden state needs explicit review; no adoption or replanning",
            )
            result = deployment.execute("plan", site)
            deployment.check_merge_create_plan(
                json.loads(files.regular(work / "guest.tfplan.json", private=True)),
                cfg["site"]["node"],
                vmid,
            )
        else:
            result = (
                deployment.execute(phase, site, approved)
                if phase == "deploy"
                else deployment.execute("verify", site)
            )
        files.require(
            result.get("vmid") == vmid
            and (phase == "plan" or result.get("status") == "passed"),
            "The shared installer did not complete this exact Bitwarden phase",
        )
        if phase != "plan":
            raw_query = files.regular(query, private=True)
            files.require(
                json.loads(raw_query)
                == migration.database_query_record(
                    cfg, migration.read_json(destination / "stack.json", private=True)
                ),
                "The retained account query from this guest did not produce matching evidence",
            )
            if phase == "verify":
                files.require(
                    files.regular(query_recovery, private=True) == raw_query
                    and receipt["database_query_sha256"] == files.digest(raw_query),
                    "Verified database query proof drifted from the completed installation",
                )
        if phase == "deploy":
            files.write_new(query_recovery, raw_query)
            files.require(
                files.regular(query_recovery, private=True) == raw_query,
                "NAS database query proof readback differs",
            )
            receipt = {
                "status": "passed",
                "binding": binding,
                "plan_sha256": approved,
                "state_sha256": deployment.sha(work / "terraform.tfstate"),
                "rollout_sha256": deployment.sha(work / "rollout-complete.json"),
                "database_query_sha256": files.digest(raw_query),
            }
            files.write_new(complete, files.encoded(receipt))
            files.write_new(recovery, files.encoded(receipt))
            files.require(
                files.regular(complete, private=True)
                == files.regular(recovery, private=True),
                "NAS completion readback differs",
            )
        files.require(
            files.regular(hold, private=True) == files.encoded(marker),
            "Bitwarden phase hold ownership changed",
        )
        hold.unlink()
        files.sync(work)
        return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("plan", "deploy", "verify"), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--runtime-file", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.phase, args.config, runtime_file=args.runtime_file)))
    except Exception:
        raise SystemExit(
            "Bitwarden CD held; inspect retained private inputs, saved plan and receipts"
        ) from None


if __name__ == "__main__":
    main()
