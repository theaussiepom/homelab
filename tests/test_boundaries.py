from pathlib import Path
import json
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_public_ci_cannot_choose_private_runner_or_privileged_pr_context():
    workflow = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert "pull_request_target" not in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}
    for job_name, job in workflow["jobs"].items():
        assert job["runs-on"] == "ubuntu-24.04"
        assert job.get("permissions", {}) == (
            {"contents": "read", "security-events": "write"}
            if job_name == "analyze"
            else {}
        )
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch("[0-9a-f]{40}", step["uses"].split("@")[1])
            assert "${{ secrets." not in json.dumps(step)
    assert (
        "tools/measure_coverage.py --all"
        in (ROOT / ".github/workflows/ci.yml").read_text()
    )


def test_public_checks_share_one_entry_and_independent_jobs_have_no_dependencies():
    workflow = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert workflow["name"] == "Validate HomeLab"
    assert set(workflow["on"]) == {
        "pull_request",
        "push",
        "schedule",
        "workflow_dispatch",
    }
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["on"]["schedule"] == [{"cron": "21 5 * * 1"}]
    # PRs supersede older PR checks; every main push still gets its own safety scan.
    assert workflow["concurrency"] == {
        "group": "validation-${{ github.event.pull_request.number || github.run_id }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }
    assert {
        p.name
        for p in (ROOT / ".github/workflows").iterdir()
        if p.suffix in {".yml", ".yaml"}
    } == {"ci.yml", "guest-phase.yml"}
    reusable = yaml.load(
        (ROOT / ".github/workflows/guest-phase.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(reusable["on"]) == {"workflow_call"}
    assert reusable["permissions"] == {"contents": "read"}
    caller = next(
        step
        for step in reusable["jobs"]["run"]["steps"]
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert caller["with"]["fetch-depth"] == "0"
    assert (
        reusable["jobs"]["run"]["env"]["HOMELAB_DEPLOYMENT_WORKFLOW"]
        == "${{ github.workflow_ref }}"
    )
    assert "github.event.repository.private == true" in reusable["jobs"]["run"]["if"]
    assert "github.event_name == 'push'" in reusable["jobs"]["run"]["if"]
    assert (
        "!contains(fromJSON(inputs.disabled || '[]'), inputs.guest)"
        in reusable["jobs"]["run"]["if"]
    )
    assert reusable["on"]["workflow_call"]["inputs"]["disabled"] == {
        "type": "string",
        "required": "false",
        "default": "[]",
    }
    jobs = workflow["jobs"]
    assert set(jobs) == {
        "blueprints",
        "changes",
        "monitoring",
        "applications",
        "iso-unit",
        "python",
        "validate",
        "source-safety",
        "dependency-review",
        "analyze",
        "build-and-boot",
    }
    for name in ("monitoring", "applications", "iso-unit", "python", "source-safety"):
        assert (
            jobs[name]["if"]
            == "github.event_name == 'push' || github.event_name == 'pull_request'"
        )
        assert "needs" not in jobs[name]
    assert "needs" not in jobs["monitoring"]
    assert any(
        "monitoring_fixture.py" in step.get("run", "")
        for step in jobs["monitoring"]["steps"]
    )
    assert jobs["dependency-review"]["if"] == "github.event_name == 'pull_request'"
    assert jobs["analyze"]["if"] == "github.event_name != 'workflow_dispatch'"
    assert "needs" not in jobs["analyze"]
    assert jobs["changes"]["outputs"] == {"iso": "${{ steps.paths.outputs.iso }}"}
    checkout = jobs["changes"]["steps"][0]
    assert checkout["with"] == {"fetch-depth": "0", "persist-credentials": "false"}
    assert (
        jobs["changes"]["steps"][1]["run"]
        == 'python3 .github/scripts/ci_changes.py >> "$GITHUB_OUTPUT"'
    )
    assert jobs["build-and-boot"]["needs"] == "changes"
    assert jobs["build-and-boot"]["if"] == "needs.changes.outputs.iso == 'true'"


def test_iso_ci_reuses_docker_commands_and_reports_only_bounded_test_evidence(tmp_path):
    ci = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
    )
    unit = ci["jobs"]["iso-unit"]
    assert unit["runs-on"] == "ubuntu-24.04"
    assert unit["defaults"]["run"]["working-directory"] == "proxmox/iso"
    assert any(step.get("run") == "make tools init unit" for step in unit["steps"])
    qualification = ci
    assert qualification["permissions"] == {"contents": "read"}
    assert "workflow_dispatch" in qualification["on"]
    job = qualification["jobs"]["build-and-boot"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["strategy"]["matrix"]["profile"] == ["fixture", "integration"]
    runs = [step.get("run", "") for step in job["steps"]]
    assert "make fetch fixture test-boot" in runs
    assert "make fetch build test-profile" in runs
    # Exercise the actual CI input generator in a fresh temporary checkout.
    generator = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Create invented integration inputs"
    )
    assert generator.startswith("python3 - <<'PY'\n") and generator.endswith("\nPY\n")
    source = generator.split("\n", 1)[1].rsplit("\nPY\n", 1)[0]
    fixtures = tmp_path / "config"
    fixtures.mkdir()
    for name in ("fixture-hardware.json", "fixture-site.json", "fixture-ssh.pub"):
        (fixtures / name).write_bytes((ROOT / "proxmox/iso/config" / name).read_bytes())
    subprocess.run([sys.executable, "-c", source], cwd=tmp_path, check=True)
    local = tmp_path / ".local"
    hardware = json.loads((local / "hardware.json").read_text())
    assert all(
        d["disk_serial"].startswith("CI-")
        for d in hardware["disk_members"] + hardware["protected_disks"]
    )
    assert (
        json.loads((local / "media-approval.json").read_text())[
            "production_boot_or_erase_authorized"
        ]
        is False
    )
    # An existing profile must never be overwritten by a CI setup convenience.
    before = {p.name: p.read_bytes() for p in local.iterdir()}
    replay = subprocess.run(
        [sys.executable, "-c", source], cwd=tmp_path, capture_output=True
    )
    assert replay.returncode != 0
    assert before == {p.name: p.read_bytes() for p in local.iterdir()}
    evidence = next(
        step
        for step in job["steps"]
        if step.get("name") == "Show build and boot evidence"
    )
    assert evidence["if"] == "always()"
    evidence_source = evidence["run"].split("\n", 1)[1].rsplit("\nPY\n", 1)[0]
    case = tmp_path / "build/vm-tests/unit"
    case.mkdir(parents=True)
    (case / "receipt.json").write_text("RECEIPT_FIXTURE")
    (case / "console.log").write_text("CONSOLE_FIXTURE")
    (case / "disk.raw").write_text("DO_NOT_LOG_DISK")
    (case / "image.iso").write_text("DO_NOT_LOG_ISO")
    reported = subprocess.run(
        [sys.executable, "-c", evidence_source],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "RECEIPT_FIXTURE" in reported.stdout and "CONSOLE_FIXTURE" in reported.stdout
    assert "DO_NOT_LOG_" not in reported.stdout
    assert "root-recovery-password.hash" not in reported.stdout
    for workflow in (ci,):
        assert "pull_request_target" not in workflow["on"]
        assert "${{ secrets." not in json.dumps(workflow)
        coverage_reports = {
            "blueprints": {
                "name": "coverage-blueprints",
                "path": "${{ runner.temp }}/blueprint-coverage",
                "retention-days": "14",
            },
            "applications": {
                "name": "coverage-applications",
                "path": "${{ runner.temp }}/application-coverage/report",
                "retention-days": "14",
            },
            "python": {
                "name": "coverage-framework",
                "path": "${{ runner.temp }}/framework-coverage",
                "retention-days": "14",
            },
        }
        for job_name, candidate in workflow["jobs"].items():
            assert candidate["runs-on"] == "ubuntu-24.04"
            for step in candidate["steps"]:
                if "uses" in step:
                    assert re.fullmatch("[0-9a-f]{40}", step["uses"].split("@")[1])
                if step.get("uses", "").startswith("actions/upload-artifact@"):
                    # Only report-only coverage may be uploaded. ISO images,
                    # disk/credential evidence and arbitrary paths stay forbidden.
                    assert job_name in coverage_reports
                    assert step["with"] == coverage_reports[job_name]
                    assert step["if"] == "always()"


def test_required_validation_gate_rejects_failures_cancellation_and_unexpected_skips(
    tmp_path,
):
    import os

    workflow = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
    )
    gate = workflow["jobs"]["validate"]
    assert gate["name"] == "Repository validation"
    assert set(gate["needs"]) == set(workflow["jobs"]) - {"validate"}
    assert gate["if"].startswith("always()")
    script = gate["steps"][0]["run"].split("\n", 1)[1].rsplit("\nPYCODE\n", 1)[0]
    for event, iso in [
        ("push", False),
        ("pull_request", False),
        ("pull_request", True),
    ]:
        results = {name: {"result": "success", "outputs": {}} for name in gate["needs"]}
        results["changes"]["outputs"]["iso"] = str(iso).lower()
        if event == "push":
            results["dependency-review"]["result"] = "skipped"
        if not iso:
            results["build-and-boot"]["result"] = "skipped"

        def run(value):
            return subprocess.run(
                [sys.executable, "-c", script],
                env=dict(os.environ, RESULTS=json.dumps(value), EVENT=event),
                capture_output=True,
            )

        assert run(results).returncode == 0
        for result in ("failure", "cancelled", "skipped"):
            for name in (
                "blueprints",
                "python",
                "applications",
                "monitoring",
                "iso-unit",
                "source-safety",
            ):
                broken = json.loads(json.dumps(results))
                broken[name]["result"] = result
                assert run(broken).returncode != 0, (name, result)
        if iso:
            results["build-and-boot"]["result"] = "skipped"
            assert run(results).returncode != 0
    python_job = workflow["jobs"]["python"]
    assert any(
        "--all --fail-under 100" in step.get("run", "") for step in python_job["steps"]
    )
