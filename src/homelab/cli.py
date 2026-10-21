from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import core
from .render import installer_answer, render


def main() -> int:
    parser = argparse.ArgumentParser(description="Shared operator/CI draft tooling")
    parser.add_argument("command", choices=["validate", "render", "plan", "approve", "apply", "verify", "guard-plan", "disk-check", "recovery-check", "installer-answer"])
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--target", choices=["synthetic", "pve"], default="synthetic")
    parser.add_argument("--change-class", choices=["routine", "initial"], default="routine")
    parser.add_argument("--root-password-hash-file", type=Path)
    args = parser.parse_args()
    try:
        catalog = core.read_json(args.catalog) if args.catalog else None
        if args.command in ("validate", "render", "plan", "approve", "apply", "verify", "installer-answer") and catalog is None:
            raise core.Refusal("--catalog is required")
        if args.command == "validate":
            result = core.validate_catalog(catalog)
            result["unresolved_field_count"] = len(result.pop("unresolved_fields"))
        elif args.command == "render":
            if not args.out:
                raise core.Refusal("--out is required")
            result = render(catalog, args.out)
        elif args.command in ("plan", "approve", "apply", "verify"):
            if not args.workspace:
                raise core.Refusal("--workspace is required")
            if args.target != "synthetic":
                raise core.Refusal("PVE execution held under I14: backend/locks/history/approval/filter adapters not qualified")
            result = {"plan": core.synthetic_plan, "approve": core.synthetic_approve,
                      "apply": core.synthetic_apply, "verify": core.synthetic_verify}[args.command](catalog, args.workspace)
        elif args.command == "guard-plan":
            if not args.input:
                raise core.Refusal("--input is required")
            result = core.guard_tofu_plan(core.read_json(args.input), args.change_class)
        elif args.command == "disk-check":
            if not args.input or not args.expected:
                raise core.Refusal("--input and --expected are required")
            result = core.disk_preflight(core.read_json(args.expected), core.read_json(args.input))
        elif args.command == "recovery-check":
            if not args.input or not args.workspace:
                raise core.Refusal("--input and --workspace are required")
            result = core.verify_recovery_files(core.read_json(args.input), args.workspace)
        elif args.command == "installer-answer":
            if not args.root_password_hash_file or not args.out:
                raise core.Refusal("--root-password-hash-file and --out are required")
            mode = args.root_password_hash_file.stat().st_mode & 0o777
            if mode & 0o077:
                raise core.Refusal("root hash input must be private")
            answer = installer_answer(catalog, args.root_password_hash_file.read_text().strip())
            # Exclusive creation preserves earlier media inputs.
            with args.out.open("x") as stream:
                args.out.chmod(0o600)
                stream.write(answer)
            result = {"answer_written": True, "target": "synthetic", "native_parser_tested": False,
                      "boot_or_erase_authorized": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (core.Refusal, ValueError, OSError, KeyError, TypeError) as exc:
        # Refusal strings never include input values or raw provider/secret data.
        message = str(exc) if isinstance(exc, core.Refusal) else "invalid/missing local input"
        print(json.dumps({"refused": True, "reason": message}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
