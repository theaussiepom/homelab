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
        if "uses" in job:
            assert job["uses"] == "./.github/workflows/" + job_name + ".yml"
            assert job_name in {"installer-disk-safety", "installer-config-validation"}
            assert "secrets" not in job
            continue
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
    } == {"ci.yml", "guest-phase.yml", "installer-disk-safety.yml", "installer-config-validation.yml"}
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
        "bitwarden-runtime",
        "retained-runtimes",
        "applications",
        "iso-unit",
        "python",
        "validate",
        "source-safety",
        "dependency-review",
        "analyze",
        "installer-disk-safety",
        "installer-config-validation",
    }
    for name in ("monitoring", "bitwarden-runtime", "retained-runtimes", "applications", "iso-unit", "python", "source-safety"):
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
    assert jobs["changes"]["name"] == "Detect installer changes"
    for name in ("installer-disk-safety", "installer-config-validation"):
        assert jobs[name]["needs"] == "changes"
        assert jobs[name]["if"] == "needs.changes.outputs.iso == 'true'"


def test_iso_ci_reuses_docker_commands_and_reports_only_bounded_test_evidence():
    ci = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    unit = ci["jobs"]["iso-unit"]
    assert unit["runs-on"] == "ubuntu-24.04"
    assert unit["defaults"]["run"]["working-directory"] == "proxmox/iso"
    assert any(step.get("run") == "make tools init unit" for step in unit["steps"])
    expected = {
        "installer-disk-safety": [
            {"case": "matching-check", "title": "Matching hardware"},
            {"case": "wrong-machine", "title": "Wrong machine"},
            {"case": "missing-member", "title": "Missing disk"},
            {"case": "ambiguous-member", "title": "Duplicate disk"},
            {"case": "cancel-install", "title": "Cancelled installation"}],
        "installer-config-validation": None,
    }
    for name, matrix in expected.items():
        source = (ROOT / (".github/workflows/" + name + ".yml")).read_text()
        workflow = yaml.load(source, Loader=yaml.BaseLoader)
        assert set(workflow["on"]) == {"workflow_call"}
        assert workflow["permissions"] == {"contents": "read"}
        assert "${{ secrets." not in source
        assert "continue-on-error" not in source
        assert "if: matrix." not in source
        assert workflow["on"]["workflow_call"]["outputs"]["qualified"]["value"] == "${{ jobs.complete.outputs.qualified }}"
        build, scenarios, gate = (workflow["jobs"][key] for key in ("build", "scenarios", "complete"))
        assert build["name"] == "Build test ISO"
        assert scenarios["needs"] == "build"
        assert scenarios["timeout-minutes"] == "10"
        if matrix:
            assert scenarios["strategy"] == {"fail-fast": "false", "matrix": {"include": matrix}}
            assert scenarios["name"] == "${{ matrix.title }}"
        else:
            assert "strategy" not in scenarios
            assert scenarios["env"]["CASE"] == "profile-wrong-machine"
            assert scenarios["name"] == "Wrong machine"
        assert gate["if"] == "always()" and set(gate["needs"]) == {"build", "scenarios"}
        script = gate["steps"][0]["run"]
        assert 'test "$BUILD" = success' in script and 'test "$SCENARIOS" = success' in script
        build_runs = [step.get("run", "") for step in build["steps"]]
        assert "make tools unit" in build_runs
        assert build_runs.count("make fetch " + ("fixture" if matrix else "build")) == 1
        assert any("custom-inputs" in run for run in build_runs) == (matrix is None)
        upload = next(step for step in build["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
        assert upload["uses"] == "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
        assert upload["with"] == {
            "name": name + "-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/installer-packet/", "retention-days": "1",
            "compression-level": "0", "if-no-files-found": "error"}
        download = next(step for step in scenarios["steps"] if step.get("uses", "").startswith("actions/download-artifact@"))
        assert download["uses"] == "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"
        assert download["with"] == {"artifact-ids": "${{ needs.build.outputs.artifact }}",
                                    "path": "${{ runner.temp }}/installer-packet", "digest-mismatch": "error"}
        runs = [step.get("run", "") for step in scenarios["steps"]]
        assert any("installer_ci.py restore" in run and '--manifest-sha "$MANIFEST_SHA" --image-sha "$IMAGE_SHA"' in run for run in runs)
        assert './scripts/run.sh test-case "$CASE"' in runs
        assert any('installer_ci.py verify --case "$CASE" --image-sha "$IMAGE_SHA"' in run for run in runs)
        assert next(i for i, run in enumerate(runs) if "installer_ci.py restore" in run) < runs.index('./scripts/run.sh test-case "$CASE"')
        for job in workflow["jobs"].values():
            assert job["runs-on"] == "ubuntu-24.04"
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch("[0-9a-f]{40}", step["uses"].split("@")[1])
        for job in (build, scenarios):
            evidence = next(step for step in job["steps"] if step.get("run") == "python3 proxmox/iso/scripts/installer_ci.py evidence")
            assert evidence["if"] == "always()"


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
        ("workflow_dispatch", True),
    ]:
        results = {name: {"result": "success", "outputs": {}} for name in gate["needs"]}
        results["changes"]["outputs"]["iso"] = str(iso).lower()
        if event == "push":
            results["dependency-review"]["result"] = "skipped"
        for name in ("installer-disk-safety", "installer-config-validation"):
            results[name] = {"result": "success" if iso else "skipped", "outputs": {"qualified": "true"} if iso else {}}
        if event == "workflow_dispatch":
            for name in ("monitoring", "bitwarden-runtime", "retained-runtimes", "applications", "iso-unit", "python", "source-safety", "analyze", "dependency-review"):
                results[name]["result"] = "skipped"

        def run(value):
            return subprocess.run(
                [sys.executable, "-c", script],
                env=dict(os.environ, RESULTS=json.dumps(value), EVENT=event, GITHUB_STEP_SUMMARY=str(tmp_path / "summary.md")),
                capture_output=True,
            )

        assert run(results).returncode == 0
        for selection in (None, "", "unknown"):
            broken = json.loads(json.dumps(results))
            broken["changes"]["outputs"]["iso"] = selection
            assert run(broken).returncode != 0
        for result in ("failure", "cancelled", "skipped"):
            for name in (
                "blueprints",
                "python",
                "applications",
                "monitoring",
                "iso-unit",
                "source-safety",
                "installer-disk-safety",
                "installer-config-validation",
            ):
                if results[name]["result"] == result:
                    continue
                broken = json.loads(json.dumps(results))
                broken[name]["result"] = result
                assert run(broken).returncode != 0, (name, result)
        if iso:
            for name in ("installer-disk-safety", "installer-config-validation"):
                for value in ("false", "", None):
                    broken = json.loads(json.dumps(results))
                    broken[name]["outputs"]["qualified"] = value
                    assert run(broken).returncode != 0
                broken = json.loads(json.dumps(results))
                del broken[name]
                assert run(broken).returncode != 0
        else:
            assert "no installer-relevant source changes" in (tmp_path / "summary.md").read_text()
    python_job = workflow["jobs"]["python"]
    assert any(
        "--all --fail-under 100" in step.get("run", "") for step in python_job["steps"]
    )


def test_coverage_stays_enforced_and_readable_without_report_artifact_uploads():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "upload-artifact" not in source
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    assert any("--all --fail-under 100" in step.get("run", "")
               for step in workflow["jobs"]["python"]["steps"])
    for job in ("python", "blueprints", "applications"):
        assert any("measure_coverage.py" in step.get("run", "") or "tests/check.sh" in step.get("run", "")
                   for step in workflow["jobs"][job]["steps"])
    application = workflow["jobs"]["applications"]
    assert any("cat" in step.get("run", "") and "summary.md" in step.get("run", "")
               for step in application["steps"])
    assert "--test-coverage-lines=100 --test-coverage-branches=100 --test-coverage-functions=100" in source
