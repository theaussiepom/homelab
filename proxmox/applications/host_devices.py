"""Runner-side client for the separately registered, bounded host-device capability."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
import host_device_helper as helper
from commands import quiet
from private_io import private_directory, regular, require, write_new, encoded


def policy(cfg):
    return helper.validate(
        {
            "schema": helper.SCHEMA,
            "node": cfg["site"]["node"],
            "vmid": cfg["guest"]["vmid"],
            "hostname": cfg["guest"]["hostname"],
            "mac": cfg["app"]["mac"].lower(),
            "device": helper.device_spec(cfg["guest"]["serial_device"]["path"]),
        }
    )


def invoke(cfg, action, operation):
    selected = policy(cfg)
    paths = cfg["paths"]
    key, hosts = (Path(paths[name]) for name in ("host_device_key", "host_known_hosts"))
    for path in (key, hosts):
        private_directory(path.parent)
        regular(path, private=True)
    host = urlsplit(cfg["site"]["api_endpoint"]).hostname
    require(host and not host.startswith("-"), "Select the reviewed host endpoint")
    command = [
        "ssh",
        "-F",
        "/dev/null",
        "-i",
        str(key),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ClearAllForwardings=yes",
        "-T",
        "-o",
        "UserKnownHostsFile=" + str(hosts),
        "-o",
        "ConnectTimeout=10",
        "root@" + host,
        action,
    ]
    private_directory(operation)
    log = operation / ("host-device-" + action + ".log")
    require(
        not log.exists() and not log.is_symlink(),
        "Preserve an existing capability invocation; no automatic replay",
    )
    quiet(
        command,
        os.environ.copy(),
        log,
        input_bytes=helper.encoded(selected),
        timeout=180,
    )
    answer = helper.decode(regular(log, private=True, limit=16384))
    require(
        set(answer) == {"schema", "vmid", "policy_sha256", "helper_sha256", "changed"}
        and answer["schema"] == helper.SCHEMA
        and answer["vmid"] == selected["vmid"]
        and type(answer["changed"]) is bool
        and answer["policy_sha256"]
        == hashlib.sha256(helper.encoded(selected)).hexdigest()
        and answer["helper_sha256"] == helper.implementation_digest()
        and (action != "check" or answer["changed"] is False),
        "Capability response differs from its registered policy",
    )
    return answer


def check(cfg, operation):
    if cfg["guest"].get("serial_device"):
        invoke(cfg, "check", operation)


def attach(cfg, operation):
    if not cfg["guest"].get("serial_device"):
        return False
    result = invoke(cfg, "attach", operation)
    write_new(operation / "host-device.json", encoded(result))
    return result["changed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packet = json.loads(regular(args.packet))
    cfg = json.loads(packet["files"]["site.json"])
    write_new(args.output, helper.encoded(policy(cfg)))


if __name__ == "__main__":
    main()
