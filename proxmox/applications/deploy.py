#!/usr/bin/env python3
"""Reconcile one reviewed guest through infrastructure, preparation and applications."""
import argparse
import json
import os
from pathlib import Path
import ansible_guest
import commands
import deployment_inputs
from deployment_state import DeploymentAttempt, bootstrap_closed
import guest_contract
import proxmox_guest
from private_io import require

PHASES = {"infrastructure", "preparation"} | {
    p for b in guest_contract.BLUEPRINTS.values() for p in b["applications"]
}


def run(
    phase, packet, *, inputs=Path("/var/lib/homelab-inputs/ordinary"), environment=None
):
    require(phase in PHASES, "Select a current deployment phase")
    bootstrap_closed()
    cfg, site = deployment_inputs.prepare(packet, inputs, environment)
    phases = guest_contract.phases(cfg)
    require(
        phase == "infrastructure" or phase in phases,
        "Select this guest application phase",
    )
    expected = deployment_inputs.binding(cfg, site)
    with DeploymentAttempt(cfg, expected, phases) as attempt:
        if attempt.completed(commands.is_ancestor):
            return {
                "status": "passed",
                "vmid": cfg["guest"]["vmid"],
                "changed": False,
                "target_contacted": False,
            }
        if phase == "infrastructure":
            attempt.begin_infrastructure()
            result = proxmox_guest.infrastructure(
                cfg, site, attempt.work, attempt.operation, expected
            )
            attempt.infrastructure_complete(result)
        else:
            ready = attempt.begin_phase(phase)
            result = ansible_guest.run_phase(
                cfg, site, attempt.work, attempt.operation, expected, phase
            )
            result = dict(result, changed=attempt.phase_complete(phase, result, ready))
        return {"status": "passed", "vmid": cfg["guest"]["vmid"], **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=sorted(PHASES), required=True)
    parser.add_argument("--packet", type=Path, required=True)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        print(json.dumps(run(args.phase, args.packet)))
    except Exception:
        raise SystemExit(
            "Deployment held; preserve private inputs, state and all attempt evidence. No automatic replay or restore."
        ) from None


if __name__ == "__main__":
    main()
