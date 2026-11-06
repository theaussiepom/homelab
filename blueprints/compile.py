#!/usr/bin/env python3
"""Compile explicit component JSON/YAML sites to versioned deployment packets.

The fixed guest-bundle authored API is available only at its immutable older pins.
This compiler performs no credential reads or native operations.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'proxmox/applications'))
sys.path.insert(0,str(ROOT/'blueprints'))
from authored_config import read, site_path

PIN=re.compile(r"^\s*uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/([a-z-]+\.yml)@([0-9a-f]{40})\s*$",re.M)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def workflow_selection(path, workflow):
    text = path.read_text()
    pins = PIN.findall(text)
    if workflow == "deploy.yml":
        pins += re.findall(r"^  HOMELAB_STACK_SOURCE: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/(deploy\.yml)@([0-9a-f]{40})\s*$", text, re.M)
    require(
        len(pins) == 1 and pins[0][1] == workflow,
        "Use one immutable workflow selection",
    )
    return {"repository": pins[0][0], "revision": pins[0][2]}


def check_revision(path, revision):
    actual = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    require(
        actual == revision, "Checked out source differs from the workflow selection"
    )


def parse_disabled(value):
    """An omitted/blank workflow input disables no guests."""
    from component_workflows import disabled_json
    return disabled_json(value)


def resolve_plan(stack_root, site_source, disabled=None, *, admit=False):
    """Resolve one explicit component site, with no fixed guest catalogue."""
    from component_plan import resolve
    return resolve(stack_root, site_source, disabled, admit=admit)


def workflow_disabled(text):
    from component_workflows import workflow_disabled as selected
    return selected(text)


def lower_plan(plan):
    from component_packet import lower_plan as lower
    return lower(plan)


def compile_site(stack_root, site_source, disabled=None, *, admit=False):
    return lower_plan(resolve_plan(stack_root, site_source, disabled, admit=admit))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack", type=Path, required=True)
    site = parser.add_mutually_exclusive_group(required=True)
    site.add_argument("--site", type=Path)
    site.add_argument("--site-root", type=Path)
    parser.add_argument("--guest")
    parser.add_argument(
        "--disabled",
        default="[]",
        help="JSON guest names to exclude; default [] runs all",
    )
    parser.add_argument("--admit", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    disabled = parse_disabled(args.disabled)
    selected = site_path(args.site_root) if args.site_root is not None else args.site
    packets = compile_site(args.stack, selected, disabled, admit=args.admit)
    if args.check:
        print("All component guests compile offline; no credentials or targets accessed.")
    else:
        require(args.guest and args.output, "Supply a guest and new packet output")
        require(args.guest in packets, "Select an authored component guest")
        if args.admit:
            require(
                packets[args.guest]["enabled"],
                "Keep disabled guests outside deployment admission",
            )
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(encoded(packets[args.guest]).decode())



if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        from component_errors import ComponentError
        raise SystemExit(str(error) if isinstance(error, ComponentError) else
                         'Component compilation refused; no credentials or targets accessed.') from None
