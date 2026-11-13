"""Recovery hooks retain receipts and artifacts across bounded command failures."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "services/database-backup" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "route,scenario",
    [
        ("nas", "success"),
        ("s3", "success"),
        ("nas", "empty-users"),
        ("nas", "large"),
        ("nas", "drift"),
        ("nas", "missing"),
        ("nas", "symlink"),
        ("nas", "nested-symlink"),
        ("s3", "prefix"),
        ("s3", "metadata"),
    ],
)
def test_recovery_bundle_uses_synthetic_capture_and_protected_receipts(
    tmp_path, route, scenario
):
    module = load("recovery-bundle.py")
    source = tmp_path / "capture"
    source.mkdir()
    (source / "config").write_text("synthetic settings")
    if scenario == "large":
        (source / "config").write_bytes(b"x" * (32 * 1024**2 + 1))
    (source / "subdirectory").mkdir()
    manifest = tmp_path / "recovery-source/manifest.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps(
            {
                "sources": [{"label": "service", "container_path": str(source)}],
                "deployment_metadata": {"fixture": True},
            }
        )
    )
    if scenario == "missing":
        (source / "config").unlink()
        source.rmdir() if not list(source.iterdir()) else None
        manifest.write_text(
            json.dumps(
                {
                    "sources": [
                        {"label": "missing", "container_path": str(tmp_path / "absent")}
                    ],
                    "deployment_metadata": {},
                }
            )
        )
    if scenario == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(source)
        manifest.write_text(
            json.dumps(
                {
                    "sources": [{"label": "link", "container_path": str(alias)}],
                    "deployment_metadata": {},
                }
            )
        )
    if scenario == "nested-symlink":
        (source / "link").symlink_to(source / "config")
    destination = tmp_path / "backup/database-recovery/configs"
    destination.mkdir(parents=True)
    old = destination / "recovery-configs_old.tar.zst"
    old.write_bytes(b"old")
    os.utime(old, (0, 0))
    retained = destination / "failed.partial"
    retained.write_bytes(b"failed evidence")

    def path(value):
        value = str(value)
        return (
            tmp_path / value.lstrip("/")
            if value.startswith(("/backup/", "/recovery-source/"))
            else Path(value)
        )

    calls = []

    def checked(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "mariadb-dump":
            assert "--system=users" in argv and "MYSQL_PWD" in kwargs["env"]
            assert not any("synthetic-password" in a for a in argv)
            kwargs["stdout"].write(
                b"" if scenario == "empty-users" else b"-- users and grants"
            )
            return b""
        if argv[0] == "zstd" and "-c" in argv:
            kwargs["stdout"].write(Path(argv[-1]).read_bytes())
            return b""
        if argv[0] == "zstd":
            return b""
        assert argv[0] == "aws"
        if "head-object" in argv:
            archive = next(destination.glob("recovery-configs_s3_*.tar.zst"))
            return json.dumps(
                {
                    "ContentLength": archive.stat().st_size,
                    "Metadata": {
                        "sha256": (
                            "changed"
                            if scenario == "metadata"
                            else hashlib.sha256(archive.read_bytes()).hexdigest()
                        )
                    },
                }
            ).encode()
        return b""

    env = {
        "DB01_PASS": "synthetic-password",
        "DB01_HOST": "fixture",
        "DB01_USER": "fixture",
        "DB10_S3_KEY_ID": "fixture",
        "DB10_S3_KEY_SECRET": "fixture",
        "DB10_S3_HOST": "objects.invalid",
        "DB10_S3_BUCKET": "fixture",
        "DB10_S3_PATH": ".." if scenario == "prefix" else "/config/",
    }
    hook = [
        "0",
        "mysql",
        "mariadb",
        "phpmyadmin",
        "start",
        "finish",
        "elapsed",
        "backup.sql.zst",
        "size",
        "checksum",
        "0",
    ]
    original_read = Path.read_bytes

    def source_read(member):
        data = original_read(member)
        if scenario == "drift" and member == source / "config":
            member.write_bytes(data + b"changed")
        return data

    with (
        patch.object(Path, "read_bytes", source_read),
        patch.object(module, "Path", side_effect=path),
        patch.object(module, "checked", side_effect=checked),
        patch.object(module.os, "umask"),
        patch.dict(module.os.environ, env),
        patch.object(module.sys, "argv", ["hook", route, *hook]),
    ):
        if scenario == "success":
            module.main()
        else:
            with pytest.raises(SystemExit):
                module.main()
    receipt = json.loads(next(destination.glob("receipt-*.json")).read_text())
    assert receipt["status"] == ("complete" if scenario == "success" else "failed")
    assert receipt["secret_values_emitted"] is False
    assert retained.read_bytes() == b"failed evidence"
    if scenario == "success":
        assert receipt["config_file_count"] == 1 and receipt["users_export_complete"]
        assert not old.exists()
        assert any("--system=users" in a for a in calls)
    for p in destination.glob("receipt-*.json"):
        assert p.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("argv", [["hook", "invalid"], ["hook", "nas", *["1"] * 11]])
def test_recovery_hook_rejects_failed_or_unrecognized_context(argv):
    module = load("recovery-bundle.py")
    with (
        patch.object(module.os, "umask"),
        patch.object(module.sys, "argv", argv),
        pytest.raises(RuntimeError),
    ):
        module.main()


def test_checked_command_does_not_publish_private_diagnostics():
    module = load("recovery-bundle.py")
    with patch.object(
        module.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout=b"ok"),
    ):
        assert module.checked(["fixture"]) == b"ok"
    with (
        patch.object(
            module.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=7, stdout=b"private"),
        ),
        pytest.raises(RuntimeError, match="rc_7"),
    ):
        module.checked(["fixture"])


@pytest.mark.parametrize(
    "scope",
    ["both", "postgresql", "recovery", "influxdb", "failed-influx", "failed-read"],
)
def test_s3_readback_main_records_scope_and_failure_without_restore(tmp_path, scope):
    module = load("verify-s3-download.py")
    root = tmp_path / "backup/database-recovery/s3-verification"
    root.mkdir(parents=True)

    def path(value):
        value = str(value)
        return (
            tmp_path / value.lstrip("/") if value.startswith("/backup") else Path(value)
        )

    class Destination:
        def __init__(self, job):
            self.job = job
            self.checksum = "md5"

        def objects(self):
            if scope == "failed-read":
                raise RuntimeError("synthetic_read_refused")
            name = {
                "08": "pgsql_all_fixture.sql.zst",
                "10": "recovery-configs_s3_20261029T000000Z.tar.zst",
                "06": "influx2_all_fixture.tar.zst",
            }[self.job]
            return [{"Key": "prefix/" + name, "LastModified": "2026-10-29T00:00:00Z"}]

    selected = (
        "influxdb"
        if scope == "failed-influx"
        else "both" if scope == "failed-read" else scope
    )
    with (
        patch.object(module, "Path", side_effect=path),
        patch.object(module, "Destination", Destination),
        patch.object(module, "verify", return_value={"verified": True}),
        patch.object(module.os, "umask"),
        patch.dict(
            module.os.environ,
            {"DB06_NAME": "partial" if scope == "failed-influx" else "ALL"},
        ),
        patch(
            "sys.argv",
            ["verify", "--scope", selected, "--not-before", "2026-10-28T00:00:00Z"],
        ),
    ):
        if scope.startswith("failed"):
            with pytest.raises(SystemExit):
                module.main()
        else:
            module.main()
    output = next(root.iterdir())
    receipt = json.loads(
        (
            output / ("failed.json" if scope.startswith("failed") else "verified.json")
        ).read_text()
    )
    assert (
        receipt["s3_write_operations"] is False
        and receipt["restore_test_performed"] is False
    )
    assert receipt["status"] == (
        "failed" if scope.startswith("failed") else "verified_downloads"
    )
