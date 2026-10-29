"""Invoke preparation or one application using the selected guest SSH trust."""

import os
from pathlib import Path
import re
import shlex
from guest_contract import SOURCE, phases, required_network_interfaces, archive_inputs
import proxmox_guest
from commands import quiet
from private_io import require, private_directory, write, read_json


def ansible_environment(cfg, environment=None):
    """Keep every application path on the same exact pinned SSH trust options."""
    environment = os.environ.copy() if environment is None else environment
    environment.update(
        {
            "ANSIBLE_CONFIG": str(SOURCE / "ansible" / "ansible.cfg"),
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_SSH_ARGS": "-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile="
            + shlex.quote(cfg["paths"]["known_hosts"]),
        }
    )
    return environment


def run_phase(cfg, site, work, operation, expected, phase):
    """Reuse guarded packages/configuration tasks, with restoration excluded."""
    from deployment_inputs import binding

    require(binding(cfg, site) == expected, "Approved inputs changed before Ansible")
    require(phase in phases(cfg), "Select a current preparation or application phase")
    proxmox_guest.dhcp_admission(cfg)
    proxmox_guest.guest_trust(cfg, work)
    phase_work = operation / phase
    private_directory(phase_work, create=True)
    app = dict(cfg["app"], render_dir=str(phase_work / "rendered"), start_services=True)
    preparation = phase == "preparation"
    if not preparation and "stack_config" in app:
        app["image_archives"] = archive_inputs(
            read_json(Path(app["stack_config"]), private=True)
        )
    if not preparation:
        app["health_checks"] = cfg["app"]["service_health_checks"][phase]
    if preparation:
        app["start_services"] = False
    write(
        phase_work / "variables.json",
        {
            "app": app,
            "network_ready_interfaces": required_network_interfaces(cfg),
            **({"application_service": phase} if not preparation else {}),
            "preparation_capabilities": cfg["deployment"]["capabilities"],
        },
    )
    write(
        phase_work / "inventory.json",
        {
            "application": {
                "hosts": {
                    app["hostname"]: {
                        "ansible_host": app["address"],
                        "ansible_user": "root",
                    }
                }
            }
        },
    )
    command = [
        "ansible-playbook",
        "-i",
        str(phase_work / "inventory.json"),
        "--private-key",
        cfg["paths"]["private_key"],
        str(
            SOURCE
            / ("ansible/preparation.yml" if preparation else "ansible/reconcile.yml")
        ),
        "--extra-vars",
        "@" + str(phase_work / "variables.json"),
    ]
    quiet(command, ansible_environment(cfg), phase_work / "application.log")
    require(binding(cfg, site) == expected, "Approved inputs changed during Ansible")
    text = (phase_work / "application.log").read_text()
    counts = re.findall(r"changed=(\d+)", text)
    require(counts, "Ansible did not produce its completion recap")
    return {"status": "passed", "changed": any(int(n) for n in counts)}
