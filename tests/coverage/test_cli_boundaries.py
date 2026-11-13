"""Public command help and refusal paths never reach native mutations."""

import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "proxmox/applications"))
sys.path.insert(0, str(ROOT / "proxmox/iso/src"))


@pytest.mark.parametrize(
    "name",
    [
        ".github/scripts/source_safety.py",
        "tools/measure_coverage.py",
        "services/network-recovery/recovery.py",
        "services/network-recovery/install.py",
        "proxmox/applications/deploy.py",
        "proxmox/applications/automation-health.py",
        "proxmox/applications/bitwarden.py",
        "proxmox/applications/ingress_routing.py",
        "proxmox/applications/monitoring.py",
        "proxmox/applications/monitoring_database.py",
        "proxmox/applications/monitoring/install-collections.py",
        "proxmox/iso/scripts/boot_test.py",
        "proxmox/iso/scripts/write-usb.py",
        "proxmox/iso/src/launch.py",
        "proxmox/iso/src/thunderbolt.py",
    ],
)
def test_help_is_available_without_network_or_native_commands(name, capsys):
    with (
        patch.object(sys, "argv", [name, "--help"]),
        patch("subprocess.run") as command,
    ):
        with pytest.raises(SystemExit) as result:
            runpy.run_path(str(ROOT / name), run_name="__main__")
        assert result.value.code == 0
        assert "usage:" in capsys.readouterr().out
        command.assert_not_called()


@pytest.mark.parametrize(
    "name,boundary",
    [
        ("proxmox/iso/scripts/fetch-assistant.py", "pathlib.Path.mkdir"),
        ("proxmox/iso/scripts/verify_metadata.py", "subprocess.run"),
    ],
)
def test_vendor_cli_keeps_preparation_failure_without_external_mutation(name, boundary):
    with patch(
        boundary, side_effect=FileNotFoundError("synthetic unavailable input")
    ) as stopped:
        with pytest.raises(FileNotFoundError):
            runpy.run_path(str(ROOT / name), run_name="__main__")
        stopped.assert_called_once()


def test_password_cli_preserves_an_existing_hash_without_prompting():
    with (
        patch.object(Path, "exists", return_value=True),
        patch("getpass.getpass") as prompt,
        patch("subprocess.run") as command,
    ):
        with pytest.raises(SystemExit, match="will not overwrite"):
            runpy.run_path(
                str(ROOT / "proxmox/iso/scripts/password-hash.py"), run_name="__main__"
            )
        prompt.assert_not_called()
        command.assert_not_called()


def test_first_boot_cli_refuses_an_unexpected_network_target_before_mutation():
    with (
        patch.object(Path, "is_symlink", return_value=True),
        patch("os.replace") as write,
    ):
        with pytest.raises(ValueError, match="Unexpected network"):
            runpy.run_path(
                str(ROOT / "proxmox/iso/src/first_boot.py"), run_name="__main__"
            )
        write.assert_not_called()


def test_workflow_cli_refuses_unknown_actions_without_external_execution():
    with (
        patch.object(sys, "argv", ["workflow", "unsupported"]),
        patch("subprocess.run") as command,
    ):
        with pytest.raises(ValueError, match="Unsupported workflow"):
            runpy.run_path(
                str(ROOT / "proxmox/iso/scripts/workflow.py"), run_name="__main__"
            )
        command.assert_not_called()


def test_routing_cli_checks_private_files_and_reads_back_the_reserved_policy(
    tmp_path, capsys
):
    sys.path.insert(0, str(ROOT / "proxmox/applications/tests"))
    import test_ingress_routing as cases
    import ingress_routing as routing

    case = cases.IngressRoutingTests()
    case.setUp()
    try:
        routing.run(case.settings, apply=True)
        case.writes.clear()
        config = tmp_path / "config"
        config.write_text(json.dumps(case.settings))
        config.chmod(0o600)

        def command(args, **kwargs):
            assert args[:2] == ["ip", "-4"] and kwargs["timeout"] == 10
            return subprocess.CompletedProcess(args, 0, case.command(args[2:]), "")

        with (
            patch.object(sys, "argv", ["routing", "--config", str(config)]),
            patch("subprocess.run", side_effect=command),
        ):
            runpy.run_path(
                str(ROOT / "proxmox/applications/ingress_routing.py"),
                run_name="__main__",
            )
            assert json.loads(capsys.readouterr().out)["status"] == "passed"
            assert not case.writes
            config.chmod(0o644)
            with pytest.raises(SystemExit, match="Ingress routing held"):
                runpy.run_path(
                    str(ROOT / "proxmox/applications/ingress_routing.py"),
                    run_name="__main__",
                )
    finally:
        case.doCleanups()


def test_scanner_cli_stops_on_unsupported_platform_before_downloading(tmp_path):
    with (
        patch.object(sys, "argv", ["scanner", str(tmp_path)]),
        patch("platform.system", return_value="unsupported"),
        patch("urllib.request.urlopen") as network,
    ):
        with pytest.raises(KeyError):
            runpy.run_path(
                str(ROOT / ".github/scripts/install_gitleaks.py"), run_name="__main__"
            )
        network.assert_not_called()


def test_tool_installer_cli_requires_matching_archive_before_writing():
    pin = {"url": "https://fixture.invalid/tool", "sha256": "0" * 64}
    with (
        patch.object(Path, "read_text", return_value=json.dumps({"opentofu": pin})),
        patch("urllib.request.urlopen", return_value=io.BytesIO(b"changed archive")),
        patch.object(Path, "write_bytes") as write,
    ):
        with pytest.raises(SystemExit):
            runpy.run_path(
                str(ROOT / "proxmox/bootstrap/docker/install-tools.py"),
                run_name="__main__",
            )
        write.assert_not_called()


def test_database_cli_rejects_missing_credential_before_host_operations():
    with (
        patch.object(
            sys,
            "argv",
            ["database", "--hba-sha256", "a" * 64, "--address", "198.18.1.2"],
        ),
        patch.object(sys, "stdin", io.StringIO("")),
        patch("subprocess.run") as command,
    ):
        with pytest.raises(SystemExit, match="Preserve its evidence"):
            runpy.run_path(
                str(ROOT / "proxmox/applications/monitoring_database.py"),
                run_name="__main__",
            )
        command.assert_not_called()


def test_automation_cli_hides_failure_and_never_retries_beyond_its_bound():
    with (
        patch.object(sys, "argv", ["health", "node_red"]),
        patch(
            "http.client.HTTPConnection", side_effect=OSError("private fixture detail")
        ),
        patch("time.monotonic", side_effect=[0, 181]),
        patch("time.sleep") as sleep,
    ):
        with pytest.raises(
            SystemExit, match="private values were not printed"
        ) as error:
            runpy.run_path(
                str(ROOT / "proxmox/applications/automation-health.py"),
                run_name="__main__",
            )
        assert "private fixture detail" not in str(error.value)
        sleep.assert_not_called()
