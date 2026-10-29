"""Media command dispatch and vendor preparation use deterministic native readback adapters."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ROOT / "src"))
import build_single_usb


def load(name):
    spec = importlib.util.spec_from_file_location(
        "media_" + name.replace("-", "_"), ROOT / "scripts" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fetch", [False, True])
def test_vendor_inputs_are_verified_before_extract_and_cached_reuse(tmp_path, fetch):
    module = load("prepare-vendor.py")
    iso = b"fixture iso"
    helper = b"fixture helper"
    runtime = b"fixture runtime"
    startup = b"fixture startup"
    build = tmp_path / "build"
    (build / "vendor").mkdir(parents=True)
    binary = build / "assistant-root/usr/bin/proxmox-auto-install-assistant"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(helper)
    if not fetch:
        (build / "vendor/proxmox-ve_9.2-1.iso").write_bytes(iso)
    commands = []

    def execute(argv, **kwargs):
        commands.append(argv)
        stdout = b""
        if argv[0] == "xorriso":
            Path(argv[-1]).write_bytes(b"vendor source")
        elif argv[0] == "unsquashfs":
            if "-pf" in argv:
                Path(argv[argv.index("-pf") + 1]).write_bytes(b"vendor pseudo metadata")
            else:
                stdout = (
                    runtime if argv[-1].endswith("proxmox-auto-installer") else startup
                )
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(module.core, "ISO_SHA256", hashlib.sha256(iso).hexdigest()),
        patch.object(
            module.core, "ASSISTANT_SHA256", hashlib.sha256(helper).hexdigest()
        ),
        patch.object(
            module.core, "RUNTIME_SHA256", hashlib.sha256(runtime).hexdigest()
        ),
        patch.object(
            build_single_usb, "STARTUP_SHA", hashlib.sha256(startup).hexdigest()
        ),
        patch.object(module.subprocess, "run", side_effect=execute),
        patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(iso)),
        patch.object(sys, "argv", ["prepare", *(["--fetch"] if fetch else [])]),
    ):
        module.main()
        assert module.verify_derived(build)
        commands.clear()
        module.main()
        assert not any(args[0] == "xorriso" or "-pf" in args for args in commands)
        (build / "vendor.squashfs").write_bytes(b"changed source")
        with pytest.raises(module.core.Refusal, match="changed"):
            module.main()


@pytest.mark.parametrize(
    "action",
    [
        "fixture",
        "build-production",
        "test-boot",
        "test-profile",
        "qualify",
        "unit",
        "invalid",
    ],
)
def test_workflow_dispatches_only_documented_build_and_test_actions(action):
    module = load("workflow.py")
    with (
        patch.object(sys, "argv", ["workflow", action]),
        patch.object(module, "run") as execute,
        patch.object(module, "qualify") as qualify,
        patch.object(module, "unit") as unit,
    ):
        if action == "invalid":
            with pytest.raises(ValueError):
                module.main()
        else:
            module.main()
        if action == "test-boot":
            assert execute.call_count == 5
        if action == "build-production":
            assert execute.call_count == 3
        if action == "qualify":
            qualify.assert_called_once()
        if action == "unit":
            unit.assert_called_once()


@pytest.mark.parametrize("passed", [True, False])
def test_unit_receipts_report_current_source_and_preserve_failure(tmp_path, passed):
    module = load("workflow.py")
    (tmp_path / "evidence").mkdir()
    suite = Mock()
    result = Mock(testsRun=7)
    result.wasSuccessful.return_value = passed
    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(module.unittest.defaultTestLoader, "discover", return_value=suite),
        patch.object(module.unittest, "TextTestRunner") as runner,
    ):
        runner.return_value.run.return_value = result
        if passed:
            module.unit()
        else:
            with pytest.raises(SystemExit):
                module.unit()
    receipt = json.loads((tmp_path / "evidence/source-tests.json").read_text())
    assert receipt["passed"] is passed and receipt["tests_run"] == 7


@pytest.mark.parametrize("failure", ["image", "missing-receipt", "failed-receipt"])
def test_qualification_refuses_stale_image_or_missing_and_failed_boot_evidence(
    tmp_path, failure
):
    module = load("workflow.py")
    (tmp_path / "evidence").mkdir()

    def save(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    images = {}
    for env in ("fixture", "production"):
        image = tmp_path / f"build/single-usb-{env}/Proxmox-9.2-1-{env}.iso"
        image.parent.mkdir(parents=True)
        image.write_bytes(env.encode())
        images[env] = module.sha(image)
        save(image.parent / "build-receipt.json", {"sha256": images[env]})
    with patch.object(module, "ROOT", tmp_path):
        save(
            tmp_path / "evidence/source-tests.json",
            {"passed": True, "source_sha256": module.source_digest(), "tests_run": 1},
        )
        for case in (
            "matching-check",
            "wrong-machine",
            "missing-member",
            "ambiguous-member",
            "cancel-install",
            "profile-wrong-machine",
        ):
            if failure == "missing-receipt" and case == "matching-check":
                continue
            env = "production" if case == "profile-wrong-machine" else "fixture"
            save(
                tmp_path / f"build/vm-tests/{case}-fixture/receipt.json",
                {
                    "result": "checked",
                    "expected": "checked",
                    "no_target_disk_writes": failure != "failed-receipt",
                    "reason_matches": True,
                    "local_vm_exit": 0,
                    "image_sha256": images[env],
                },
            )
        if failure == "image":
            (
                tmp_path / "build/single-usb-fixture/Proxmox-9.2-1-fixture.iso"
            ).write_bytes(b"changed")
        with pytest.raises(
            ValueError,
            match={
                "image": "Image changed",
                "missing-receipt": "Missing boot test",
                "failed-receipt": "Boot test did not pass",
            }[failure],
        ):
            module.qualify()
        assert not (tmp_path / "evidence/media-acceptance.json").exists()


def test_workflow_command_wrapper_preserves_native_status_and_argv():
    module = load("workflow.py")
    with patch.object(module.subprocess, "run") as command:
        module.run(Path("/synthetic/step"), "argument")
        command.assert_called_once_with(
            [sys.executable, "/synthetic/step", "argument"], check=True
        )
