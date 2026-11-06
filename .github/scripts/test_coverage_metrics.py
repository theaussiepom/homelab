"""Check measurement against known code paths, including a real child Python."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "coverage_metrics", ROOT / "tools/measure_coverage.py"
)
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


def documentation_collection(directory, required):
    """Use real unittest discovery from this independently collected CI harness."""
    import subprocess
    import sys

    script = '''import json,sys,unittest
from pathlib import Path
directory=Path(sys.argv[1]).resolve()
required=json.loads(sys.argv[2])
sys.path.insert(0,str(directory))
def cases(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from cases(item)
        else:yield item
for name in required:
    loader=unittest.TestLoader()
    named=loader.loadTestsFromName(name)
    if loader.errors or not named.countTestCases():
        raise SystemExit('DOC_COLLECTION: missing or empty '+name)
    selected=list(cases(named))
    for case in selected:
        method=getattr(case,case._testMethodName)
        if (getattr(case,'__unittest_skip__',False) or getattr(method,'__unittest_skip__',False)
                or getattr(method,'__unittest_expecting_failure__',False)):
            raise SystemExit('DOC_COLLECTION: skipped or expected failure '+case.id())
    discovered=loader.discover(str(directory),pattern=name.split('.')[0]+'.py')
    if loader.errors or not {case.id() for case in selected} <= {case.id() for case in cases(discovered)}:
        raise SystemExit('DOC_COLLECTION: not discovered '+name)
print('Documentation collection: '+str(len(required))+' required cases/classes present')
'''
    return subprocess.run(
        [sys.executable, '-c', script, str(directory), json.dumps(required)],
        cwd=directory, capture_output=True, text=True, timeout=30,
    )


def test_documentation_conformance_remains_in_normal_discovery():
    required = [
        'test_component_documentation.DocumentationContracts.test_personalised_walkthrough_executes_printed_commands_and_inspects_effects',
        'test_component_documentation.DocumentationContracts.test_personalised_alternative_decisions_and_typed_extraction_preserve_bindings',
        'test_component_documentation.DocumentationContracts.test_personalised_refusals_report_documented_cidr_and_memory_failures',
        'test_component_documentation.DocumentationContracts.test_network_nic_documentation_conformance',
        'test_documentation_conformance.DocumentationConformanceMechanism',
        'test_component_reference_examples.ReferenceExamples.test_network_nic_variants_and_exact_refusals',
        'test_component_reference_examples.ReferenceExamples.test_unused_network_context_is_only_checked_when_consumed',
        'test_documentation_navigation.DocumentationNavigation',
        'test_documentation_navigation.NavigationMechanism',
    ]
    result = documentation_collection(ROOT / 'blueprints', required)
    assert result.returncode == 0, result.stdout + result.stderr


def test_documentation_collection_refuses_missing_empty_and_undiscoverable_cases(tmp_path):
    module = tmp_path / 'test_contract.py'
    module.write_text('import unittest\nclass Contract(unittest.TestCase):\n    def test_contract(self): pass\n')
    result = documentation_collection(tmp_path, ['test_contract.Contract'])
    assert result.returncode == 0, result.stderr
    module.write_text('import unittest\nclass Contract(unittest.TestCase): pass\n')
    for required in [['test_contract.Contract'], ['test_removed.Contract'], ['test_contract.Contract.test_removed']]:
        result = documentation_collection(tmp_path, required)
        assert result.returncode != 0
        assert 'DOC_COLLECTION' in result.stderr
    for decorator in ("unittest.skip('not required')", 'unittest.expectedFailure'):
        module.write_text('import unittest\nclass Contract(unittest.TestCase):\n    @' + decorator + '\n    def test_contract(self): pass\n')
        result = documentation_collection(tmp_path, ['test_contract.Contract'])
        assert result.returncode != 0
        assert 'skipped or expected failure' in result.stderr


def test_documentation_ci_runs_for_all_prs_and_producer_failures_reach_required_gate(tmp_path):
    import os
    import subprocess
    import sys
    import yaml

    workflow = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
    assert workflow['on']['pull_request'] in ('', None)
    assert workflow['on']['push'] == {'branches': ['main']}
    producer = workflow['jobs']['blueprints']
    assert 'if' not in producer and 'continue-on-error' not in producer
    for command in ('test_coverage_metrics.py', 'measure_coverage.py --suite blueprints'):
        step = next(step for step in producer['steps'] if command in step.get('run', ''))
        assert 'if' not in step and 'continue-on-error' not in step
    gate = workflow['jobs']['validate']
    assert gate['name'] == 'Repository validation'
    assert 'blueprints' in gate['needs'] and 'always()' in gate['if']
    script = gate['steps'][0]['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
    for state in ('success', 'failure', 'cancelled', 'skipped'):
        jobs = {name: {'result': 'success', 'outputs': {}} for name in gate['needs']}
        jobs['blueprints']['result'] = state
        jobs['changes']['outputs']['iso'] = 'false'
        for name in ('installer-disk-safety', 'installer-config-validation'):
            jobs[name]['result'] = 'skipped'
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True,
            env=dict(os.environ, RESULTS=json.dumps(jobs), EVENT='pull_request', GITHUB_STEP_SUMMARY=str(tmp_path / 'summary')))
        assert (result.returncode == 0) == (state == 'success'), result.stdout + result.stderr


def source_tree(root, failing=False):
    source = root / "tools/homelab"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("")
    (source / "core.py").write_text(
        "def choose(value):\n    if value:\n        return 1\n    return 2\n"
    )
    (source / "worker.py").write_text(
        "if __name__ == '__main__':\n    print('child executed')\n"
    )
    (source / "namespace").mkdir()
    (source / "namespace/unexecuted-helper.py").write_text(
        "def never():\n    return 42\n"
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_paths.py").write_text(
        "import subprocess,sys\nsys.path.insert(0,'tools')\nfrom homelab.core import choose\n"
        "def test_paths():\n"
        + (
            "    assert False\n"
            if failing
            else "    assert choose(True) == 1\n    subprocess.run([sys.executable,'tools/homelab/worker.py'],check=True)\n"
        )
    )


def test_real_subprocess_and_zero_coverage_files_are_measured(tmp_path, monkeypatch):
    # A standalone measurement must also work without GitHub summary output.
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    source_tree(tmp_path)
    result = metrics.measure(tmp_path, tmp_path / "report", ["framework"])
    assert result["tests_passed"] is True
    assert result["enforcement"] is False
    files = result["files"]
    assert files["tools/homelab/worker.py"]["lines"]["covered"] > 0
    assert (
        files["tools/homelab/namespace/unexecuted-helper.py"]["lines"]["covered"] == 0
    )
    assert files["tools/homelab/namespace/unexecuted-helper.py"]["lines"]["total"] > 0
    assert files["tools/homelab/core.py"]["branches"] == {
        "covered": 1,
        "total": 2,
        "percent": 50.0,
    }
    assert files["tools/homelab/core.py"]["missing_lines"]
    assert (tmp_path / "report/html/index.html").is_file()
    assert (tmp_path / "report/coverage.xml").is_file()


def test_test_failures_are_preserved_in_the_report(tmp_path):
    source_tree(tmp_path, failing=True)
    result = metrics.measure(tmp_path, tmp_path / "report", ["framework"])
    assert result["tests_passed"] is False
    assert result["suites"][0]["exit_code"] != 0
    assert (
        json.loads((tmp_path / "report/summary.json").read_text())["tests_passed"]
        is False
    )


def test_whole_repository_inventory_keeps_unexecuted_code_in_each_consumer(tmp_path):
    import subprocess

    root = tmp_path / "framework"
    root.mkdir()
    source_tree(root)
    stack, site = tmp_path / "stack", tmp_path / "site"
    for repo in (root, stack, site):
        repo.mkdir(exist_ok=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (stack / "guard.py").write_text("def guard():\n    return False\n")
    (site / "check").write_text("#!/usr/bin/env python3\nprint('unexecuted')\n")
    (site / "tests").mkdir()
    (site / "tests/test_fixture.py").write_text(
        "raise RuntimeError('test source is outside the denominator')\n"
    )
    (site / "notes.txt").write_text("not Python")
    inventory = metrics.production_sources(root, stack, site)
    assert stack / "guard.py" in inventory
    assert site / "check" in inventory
    assert site / "tests/test_fixture.py" not in inventory
    result = metrics.measure(
        root, tmp_path / "all-report", ["framework"], stack, site, whole=True
    )
    assert result["whole_repositories"] is True
    assert result["source_files"] == 6
    assert result["files"]["../stack/guard.py"]["lines"]["covered"] == 0
    assert result["files"]["../site/check"]["lines"]["covered"] == 0
    assert result["enforcement"] is False


def test_measurement_refuses_missing_inputs_empty_scope_and_existing_reports(tmp_path):
    import pytest

    source_tree(tmp_path)
    for suites, stack, site, match in [
        (["stack"], None, None, "stack checkout"),
        (["site"], None, None, "site checkout"),
        (["blueprints"], None, None, "No production"),
    ]:
        with pytest.raises(ValueError, match=match):
            metrics.measure(tmp_path, tmp_path / "report", suites, stack, site)
    output = tmp_path / "retained"
    output.mkdir()
    with pytest.raises(FileExistsError):
        metrics.measure(tmp_path, output, ["framework"])


def test_measurement_cli_selects_all_or_explicit_suites_without_thresholds(tmp_path):
    import sys
    from unittest.mock import patch
    import pytest

    for arguments in [
        ["--all", "--stack", "stack", "--site", "site"],
        ["--suite", "applications"],
    ]:
        with (
            patch.object(
                sys,
                "argv",
                ["coverage", *arguments, "--output", str(tmp_path / "report")],
            ),
            patch.object(
                metrics,
                "measure",
                return_value={"tests_passed": True, "coverage_passed": True},
            ) as measure,
            pytest.raises(SystemExit) as raised,
        ):
            metrics.main()
        assert raised.value.code == 0
        if "--all" in arguments:
            assert (
                "bootstrap" in measure.call_args.args[2]
                and "site" in measure.call_args.args[2]
            )
        else:
            assert measure.call_args.args[2] == ["applications"]
    with (
        patch.object(
            sys,
            "argv",
            [
                "coverage",
                "--suite",
                "framework",
                "--suite",
                "framework",
                "--output",
                str(tmp_path / "report"),
            ],
        ),
        pytest.raises(SystemExit) as raised,
    ):
        metrics.main()
    assert raised.value.code == 2


def test_site_scope_measures_its_checker_without_claiming_framework_coverage(
    tmp_path, monkeypatch
):
    import subprocess

    root, site = tmp_path / "framework", tmp_path / "site"
    root.mkdir()
    source_tree(root)
    site.mkdir()
    (site / "tests").mkdir()
    subprocess.run(["git", "init", "-q", str(site)], check=True)
    (site / "checker.py").write_text("def check():\n    return True\n")
    (site / "tests/test_site.py").write_text(
        "import runpy\nfrom pathlib import Path\ndef test_check():\n"
        "    module=runpy.run_path(str(Path(__file__).resolve().parents[1]/'checker.py'))\n"
        "    assert module['check']()\n"
    )
    step_summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    result = metrics.measure(root, tmp_path / "site-report", ["site"], site=site)
    assert result["tests_passed"] is True
    assert result["source_files"] == 1
    assert result["totals"]["lines"]["percent"] == 100
    assert set(result["components"]) == {"site/checker.py"}
    assert step_summary.read_text() == (tmp_path / "site-report/summary.md").read_text()
    assert "private-site checker" not in result["excluded"]


def test_stack_scope_includes_its_code_and_discovers_the_pinned_scanner(
    tmp_path, monkeypatch
):
    import subprocess

    root, stack = tmp_path / "framework", tmp_path / "stack"
    for repo in (root, stack):
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (root / "blueprints").mkdir()
    (root / "proxmox/applications").mkdir(parents=True)
    (root / "blueprints/unexecuted.py").write_text("def refuse():\n    return False\n")
    (stack / "guard.py").write_text("def check():\n    return True\n")
    (stack / "tests").mkdir()
    (stack / "tests/test_guard.py").write_text(
        "import runpy,unittest\nfrom pathlib import Path\nclass Guard(unittest.TestCase):\n"
        "    def test_guard(self):\n        self.assertTrue(runpy.run_path(str(Path(__file__).resolve().parents[1]/'guard.py'))['check']())\n"
    )
    monkeypatch.delenv("GITLEAKS_BIN", raising=False)
    result = metrics.measure(root, tmp_path / "stack-report", ["stack"], stack=stack)
    assert result["tests_passed"] is True
    assert result["files"]["../stack/guard.py"]["lines"]["percent"] == 100
    assert "blueprints/unexecuted.py" not in result["files"]


def test_missing_branch_data_is_a_measurement_failure_not_zero_percent_success(
    tmp_path,
):
    import pytest
    from unittest.mock import Mock, patch

    source_tree(tmp_path)
    collector = Mock()
    collector.get_data.return_value.has_arcs.return_value = False
    with (
        patch.object(metrics.coverage, "Coverage", return_value=collector),
        pytest.raises(RuntimeError, match="did not produce data"),
    ):
        metrics.measure(tmp_path, tmp_path / "broken-report", ["framework"])
    collector.json_report.assert_not_called()
    assert metrics.counts([])["branches"] == {"covered": 0, "total": 0, "percent": None}


def test_coverage_gate_uses_exact_counts_and_checks_each_file():
    import pytest

    complete = {"covered": 10, "total": 10, "percent": 100.0}
    rounded = {"covered": 99999, "total": 100000, "percent": 100.0}
    absent = {"covered": 0, "total": 0, "percent": None}
    files = {
        "complete.py": {"lines": complete, "branches": absent},
        "missed.py": {
            "lines": rounded,
            "branches": {"covered": 1, "total": 2, "percent": 50},
        },
    }
    assert metrics.coverage_failures(files, None) == []
    failures = metrics.coverage_failures(files, 100)
    assert [(f["file"], f["metric"]) for f in failures] == [
        ("missed.py", "lines"),
        ("missed.py", "branches"),
    ]
    assert metrics.coverage_failures(files, 50) == []
    for minimum in (-1, 101, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="minimum"):
            metrics.coverage_failures(files, minimum)


def test_enforced_coverage_writes_failure_evidence_even_when_tests_pass(tmp_path):
    source_tree(tmp_path)
    result = metrics.measure(
        tmp_path, tmp_path / "report", ["framework"], fail_under=100
    )
    assert result["tests_passed"] is True
    assert result["coverage_passed"] is False
    assert result["enforcement"] is True
    assert result["fail_under"] == 100
    assert result["coverage_failures"]
    assert "gate FAILED" in (tmp_path / "report/summary.md").read_text()


def test_coverage_cli_fails_for_tests_or_coverage_and_accepts_success(tmp_path):
    import sys
    import pytest
    from unittest.mock import patch

    for tests_passed, coverage_passed, expected in [
        (True, True, 0),
        (True, False, 1),
        (False, True, 1),
    ]:
        with (
            patch.object(
                sys,
                "argv",
                [
                    "coverage",
                    "--all",
                    "--fail-under",
                    "100",
                    "--output",
                    str(tmp_path / "report"),
                ],
            ),
            patch.object(
                metrics,
                "measure",
                return_value={
                    "tests_passed": tests_passed,
                    "coverage_passed": coverage_passed,
                },
            ) as measure,
            pytest.raises(SystemExit) as raised,
        ):
            metrics.main()
        assert raised.value.code == expected
        assert measure.call_args.args[-1] == 100
