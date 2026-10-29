#!/usr/bin/env python3
"""Measure Python sources and optionally enforce line and branch coverage per file."""

import argparse
from contextlib import chdir
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

import coverage

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "framework": "tools",
    "blueprints": "blueprints",
    "applications": "proxmox/applications",
}
SUITES = {
    "framework": ["pytest", "-q", "tests"],
    "blueprints": ["unittest", "discover", "-s", "blueprints"],
    "applications": ["unittest", "discover", "-s", "proxmox/applications/tests"],
}
EXTRA_SUITES = {
    "bootstrap": ["unittest", "discover", "-s", "proxmox/bootstrap/tests"],
    "installer": ["unittest", "discover", "-s", "proxmox/iso/tests"],
    "network-recovery": ["pytest", "-q", "services/network-recovery"],
    "source-tooling": [
        "pytest",
        "-q",
        ".github/scripts",
        ".githooks",
    ],
}


def production_sources(root, stack=None, site=None):
    """Inventory repository code, including unexecuted scripts and local edits."""
    inventory = {}
    for repo in (root, stack, site):
        if repo is None:
            continue
        files = subprocess.check_output(
            [
                "git",
                "-C",
                str(repo),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            text=True,
        ).splitlines()
        for name in sorted(set(files)):
            path = (repo / name).resolve()
            if (
                not path.is_file()
                or "tests" in Path(name).parts
                or path.name.startswith("test_")
            ):
                continue
            if path.suffix == ".py" or (
                path.suffix == ""
                and path.is_file()
                and path.read_bytes().startswith(
                    (b"#!/usr/bin/env python", b"#!/usr/bin/python")
                )
            ):
                prefixes = {
                    "proxmox/applications/": "applications",
                    "proxmox/bootstrap/": "bootstrap",
                    "proxmox/iso/": "installer",
                    "services/network-recovery/": "network-recovery",
                    "services/database-backup/": "database-backup",
                }
                component = next(
                    (
                        group
                        for prefix, group in prefixes.items()
                        if name.startswith(prefix)
                    ),
                    name.split("/")[0],
                )
                inventory[path] = repo.name + "/" + component
    return inventory


def counts(rows):
    def metric(covered, total):
        numerator = sum(row[covered] for row in rows)
        denominator = sum(row[total] for row in rows)
        return {
            "covered": numerator,
            "total": denominator,
            "percent": round(100 * numerator / denominator, 2) if denominator else None,
        }

    return {
        "lines": metric("covered_lines", "num_statements"),
        "branches": metric("covered_branches", "num_branches"),
    }


def coverage_failures(files, minimum):
    """Compare exact counts, so rounded percentages cannot hide an uncovered path."""
    if minimum is None:
        return []
    if not math.isfinite(minimum) or not 0 <= minimum <= 100:
        raise ValueError("Coverage minimum must be between zero and 100")
    return [
        {"file": name, "metric": metric, **counts}
        for name, row in files.items()
        for metric in ("lines", "branches")
        if (counts := row[metric])["total"]
        and counts["covered"] * 100 < minimum * counts["total"]
    ]


def measure(root, output, suites, stack=None, site=None, whole=False, fail_under=None):
    coverage_failures({}, fail_under)
    root, output = root.resolve(), output.resolve()
    stack = stack.resolve() if stack else None
    site = site.resolve() if site else None
    whole = whole or any(suite in EXTRA_SUITES for suite in suites)
    if "site" in suites and (site is None or not (site / "tests").is_dir()):
        raise ValueError("Supply the private site checkout for site tests")
    if "stack" in suites and (stack is None or not (stack / "tests").is_dir()):
        raise ValueError("Supply the selected stack checkout for stack tests")
    groups = set(suites) & SOURCES.keys()
    inventory = {
        path: group
        for group in sorted(groups)
        for path in (root / SOURCES[group]).rglob("*.py")
        if "tests" not in path.relative_to(root / SOURCES[group]).parts
        and not path.name.startswith("test_")
        and "__pycache__" not in path.parts
    }
    if whole:
        inventory = production_sources(root, stack, site)
    else:
        inventory.update(
            production_sources(
                None,
                stack if "stack" in suites else None,
                site if "site" in suites else None,
            )
        )
    source_paths = (
        [p for p in (root, stack, site) if p is not None]
        if whole
        else [root / SOURCES[group] for group in sorted(groups)]
        + ([stack] if "stack" in suites else [])
        + ([site] if "site" in suites else [])
    )
    components = set(inventory.values())
    if not inventory:
        raise ValueError("No production Python sources in the selected scope")
    output.mkdir(parents=True, exist_ok=False)
    config = output / "coverage.ini"
    config.write_text(
        "[run]\nbranch = True\nparallel = True\npatch = subprocess\ncore = ctrace\nsource =\n"
        + "".join(f"    {path}\n" for path in source_paths)
        + "omit =\n    */tests/*\n    */test_*.py\n[report]\nprecision = 2\n"
    )
    data_file = output / ".coverage"
    environment = dict(
        os.environ,
        PYTHONDONTWRITEBYTECODE="1",
        COVERAGE_RCFILE=str(config),
        COVERAGE_FILE=str(data_file),
        HOMELAB_FRAMEWORK=str(root),
    )
    if stack:
        environment["HOMELAB_STACK"] = str(stack)
    if whole or "stack" in suites:
        environment["PYTHONPATH"] = str(root / "proxmox/iso/src")
        if not environment.get("GITLEAKS_BIN"):
            scanner = subprocess.run(
                ["git", "-C", str(root), "config", "--get", "hooks.gitleaksPath"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            environment["GITLEAKS_BIN"] = scanner or shutil.which("gitleaks") or ""
    results = []
    for suite in suites:
        args = (
            ["unittest", "discover", "-s", str(stack / "tests")]
            if suite == "stack"
            else (
                ["pytest", "-q", str(site / "tests")]
                if suite == "site"
                else SUITES[suite] if suite in SUITES else EXTRA_SUITES[suite]
            )
        )
        if args[0] == "pytest":
            # Keep pytest away from unrelated retained temporary evidence, and
            # keep its synthetic fixture files outside the published reports.
            scratch = output.parent / ("." + output.name + "-" + suite + "-pytest")
            scratch.mkdir(exist_ok=False)
            args = [*args, "--basetemp=" + str(scratch)]
        command = [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "--context=" + suite,
            "-m",
            *args,
        ]
        with (output / (suite + ".txt")).open("w") as log:
            result = subprocess.run(
                command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT
            )
        results.append(
            {"suite": suite, "exit_code": result.returncode, "command": command}
        )
    with chdir(root):
        measured = coverage.Coverage(
            config_file=str(config), data_file=str(data_file), data_suffix=False
        )
        measured.combine(strict=True)
        data = measured.get_data()
        if not data.has_arcs():
            raise RuntimeError("Branch measurement did not produce data")
        # Discoverable modules alone are insufficient: include unexecuted scripts
        # and namespace directories in the denominator as well.
        data.touch_files([str(path) for path in inventory])
        measured.save()
        measured.json_report(
            outfile=str(output / "coverage.json"), include=[str(p) for p in inventory]
        )
        measured.xml_report(
            outfile=str(output / "coverage.xml"), include=[str(p) for p in inventory]
        )
        measured.html_report(
            directory=str(output / "html"), include=[str(p) for p in inventory]
        )
    raw = json.loads((output / "coverage.json").read_text())
    files = {
        os.path.relpath((root / name).resolve(), root): {
            "component": inventory[(root / name).resolve()],
            **counts([row["summary"]]),
            "missing_lines": row["missing_lines"],
            "missing_branches": row["missing_branches"],
        }
        for name, row in raw["files"].items()
    }
    snapshot = hashlib.sha256()
    for path in sorted(inventory):
        snapshot.update(os.path.relpath(path, root).encode() + b"\0")
        snapshot.update(hashlib.sha256(path.read_bytes()).digest())
    revision = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    lock = root / "requirements.lock.txt"
    summary = {
        "schema": "homelab-python-coverage-v1",
        "python": platform.python_version(),
        "coverage": coverage.__version__,
        "framework_revision": (
            revision.stdout.strip()
            if revision.returncode == 0
            else os.environ.get("GITHUB_SHA")
        ),
        "source_sha256": snapshot.hexdigest(),
        "requirements_sha256": (
            hashlib.sha256(lock.read_bytes()).hexdigest() if lock.is_file() else None
        ),
        "framework_worktree_dirty": (
            bool(status.stdout) if status.returncode == 0 else None
        ),
        "enforcement": fail_under is not None,
        "fail_under": fail_under,
        "coverage_failures": coverage_failures(files, fail_under),
        "source_files": len(inventory),
        "suites": results,
        "tests_passed": all(result["exit_code"] == 0 for result in results),
        "scope": (
            {name: name for name in sorted(components)}
            if whole
            else {name: SOURCES.get(name, name) for name in sorted(components)}
        ),
        "whole_repositories": whole,
        "excluded": ["test code", "JavaScript, Ansible, shell and OpenTofu"]
        + ([] if whole else ["components outside the selected scope"]),
        "totals": counts([row["summary"] for row in raw["files"].values()]),
        "components": {
            group: counts(
                [
                    row["summary"]
                    for name, row in raw["files"].items()
                    if inventory[(root / name).resolve()] == group
                ]
            )
            for group in sorted(components)
        },
        "files": files,
    }
    summary["coverage_passed"] = not summary["coverage_failures"]
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    def fraction(metric):
        percent = "n/a" if metric["percent"] is None else f"{metric['percent']:.2f}%"
        return f"{percent} ({metric['covered']}/{metric['total']})"

    lines = [
        "# Python coverage"
        + (
            " (report only)"
            if fail_under is None
            else f" (minimum {fail_under:g}% per file)"
        ),
        "",
        "Suites: "
        + ", ".join(suites)
        + ". Tests "
        + (
            "passed."
            if summary["tests_passed"]
            else "FAILED; measurement is incomplete."
        ),
        "",
        "| Component | Lines | Branches |",
        "| --- | ---: | ---: |",
    ]
    for group, metrics in {**summary["components"], "TOTAL": summary["totals"]}.items():
        lines.append(
            f"| {group} | {fraction(metrics['lines'])} | {fraction(metrics['branches'])} |"
        )
    if summary["coverage_failures"]:
        lines += ["", "Files below the required minimum:", ""]
        lines += [
            f"- {failure['file']}: {failure['metric']} "
            f"{failure['covered']}/{failure['total']}"
            for failure in summary["coverage_failures"]
        ]
    lines += [
        "",
        (
            "No coverage threshold or failure gate."
            if fail_under is None
            else "Line and branch coverage gate "
            + ("passed." if summary["coverage_passed"] else "FAILED.")
        )
        + " Unexecuted production files are included.",
        "",
        "Scope: " + ", ".join(summary["scope"].values()) + ".",
        "Excluded: " + ", ".join(summary["excluded"]) + ".",
        "",
    ]
    markdown = "\n".join(lines)
    (output / "summary.md").write_text(markdown)
    print(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as target:
            target.write(markdown)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite", action="append", choices=[*SUITES, *EXTRA_SUITES, "stack", "site"]
    )
    parser.add_argument("--stack", type=Path)
    parser.add_argument("--site", type=Path)
    parser.add_argument("--fail-under", type=float)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Measure all Python code in the supplied repositories",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    suites = args.suite or [
        *SUITES,
        *(EXTRA_SUITES if args.all else []),
        *(["stack"] if args.stack else []),
        *(["site"] if args.site else []),
    ]
    if len(set(suites)) != len(suites):
        parser.error("Select each test suite once")
    summary = measure(
        ROOT, args.output, suites, args.stack, args.site, args.all, args.fail_under
    )
    raise SystemExit(0 if summary["tests_passed"] and summary["coverage_passed"] else 1)


if __name__ == "__main__":
    main()
