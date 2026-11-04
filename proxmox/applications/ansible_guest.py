"""The shared pinned SSH environment for the Ansible component caller."""
import os
from pathlib import Path
import shlex

SOURCE=Path(__file__).resolve().parent


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
