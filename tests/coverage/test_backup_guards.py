"""Backup admission and readback are tested against local synthetic command edges."""

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock
import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "services/database-backup" / name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARGS = ["-h", "db.invalid", "-p", "5432", "-U", "homelab_backup"]
CAPABILITIES = {
    "name": "homelab_backup",
    "version": 16,
    "superuser": False,
    "createdb": False,
    "createrole": False,
    "replication": False,
    "bypassrls": True,
    "login": True,
    "read_all_data": True,
    "read_authid": True,
    "connect_all": True,
}


@pytest.mark.parametrize(
    "arguments", [[], ARGS + ["-h", "other"], ARGS[:-1], ARGS[:-1] + ["postgres"]]
)
def test_pg_connection_contract_rejects_ambiguous_or_privileged_input(arguments):
    with pytest.raises(RuntimeError):
        load("pg-dumpall-guard.py").connection_args(arguments)


@pytest.mark.parametrize(
    "scenario", ["valid", "query-failed", "capability-drift", "unsupported-object"]
)
def test_pg_preflight_checks_every_database_and_uses_only_native_read_queries(scenario):
    module = load("pg-dumpall-guard.py")
    caps = dict(CAPABILITIES)
    if scenario == "capability-drift":
        caps["superuser"] = True
    responses = [
        caps,
        ["postgres", "application"],
        {
            "large_objects": 0,
            "subscriptions": 0,
            "user_mappings": 0,
            "foreign_tables": 0,
        },
        {"large_objects": 0},
    ]
    if scenario == "unsupported-object":
        responses[2]["foreign_tables"] = 1

    def execute(argv, **kwargs):
        assert argv[0] == module.PSQL and kwargs["env"]["PGCONNECT_TIMEOUT"] == "10"
        return SimpleNamespace(
            returncode=1 if scenario == "query-failed" else 0,
            stdout=json.dumps(responses.pop(0)),
        )

    with patch.object(module.subprocess, "run", side_effect=execute) as process:
        if scenario == "valid":
            module.preflight(ARGS)
            assert process.call_count == 4
        else:
            with pytest.raises(RuntimeError):
                module.preflight(ARGS)


@pytest.mark.parametrize("help_args", [["--help"], ["--version"], ["-V"], ["-?"], ARGS])
def test_pg_exec_preserves_native_argv_after_admission(help_args):
    module = load("pg-dumpall-guard.py")
    with (
        patch.object(module.sys, "argv", ["guard", *help_args]),
        patch.object(module, "preflight") as check,
        patch.object(module.os, "execv") as execute,
    ):
        module.main()
    assert check.call_count == (
        0 if help_args[0].startswith("--") or help_args[0] in ("-V", "-?") else 1
    )
    execute.assert_called_once_with(module.NATIVE, [module.NATIVE, *help_args])


@pytest.fixture
def destination():
    module = load("verify-s3-download.py")
    env = {
        "DB10_S3_BUCKET": "fixture",
        "DB10_S3_PATH": "backups/config",
        "DB10_S3_HOST": "objects.invalid",
        "DB10_S3_KEY_ID": "fixture-id",
        "DB10_S3_KEY_SECRET": "fixture-secret",
    }
    with patch.dict(module.os.environ, env, clear=True):
        yield module, module.Destination("10")


@pytest.mark.parametrize(
    "change",
    [
        {"DB10_S3_PROTOCOL": "http"},
        {"DB10_S3_BUCKET": ""},
        {"DB10_S3_PATH": "../invalid"},
        {"DB10_S3_PATH": ""},
    ],
)
def test_s3_destination_never_weakens_tls_or_prefix(change):
    module = load("verify-s3-download.py")
    with (
        patch.dict(
            module.os.environ,
            {
                "DB10_S3_HOST": "objects.invalid",
                "DB10_S3_BUCKET": "fixture",
                "DB10_S3_PATH": "prefix",
                **change,
            },
            clear=True,
        ),
        pytest.raises(RuntimeError),
    ):
        module.Destination("10")


def test_s3_listing_filters_nested_keys_and_suppresses_command_errors(destination):
    module, target = destination
    with patch.object(
        target,
        "call",
        return_value={
            "Contents": [
                {"Key": "backups/config/a"},
                {"Key": "backups/config/nested/b"},
            ]
        },
    ):
        assert target.objects() == [{"Key": "backups/config/a"}]
    with patch.object(
        module.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"")
    ):
        assert target.call(["list-buckets"]) == {}
    with (
        patch.object(
            module.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=1, stdout=b"private"),
        ),
        pytest.raises(RuntimeError, match="s3_read_failed"),
    ):
        target.call(["list-buckets"])


@pytest.mark.parametrize(
    "scenario", ["success", "oversize", "capacity", "exists", "length", "etag"]
)
def test_s3_download_binds_etag_and_refuses_local_or_remote_drift(
    tmp_path, destination, scenario
):
    module, target = destination
    output = tmp_path / "download"
    head = {"ContentLength": 4, "ETag": "fixture-etag"}
    if scenario == "exists":
        output.write_bytes(b"keep")

    def call(args, **kwargs):
        if args[0] == "head-object":
            return head
        assert "--if-match" in args and args[-2] == "fixture-etag"
        output.write_bytes(b"bad" if scenario == "length" else b"data")
        return {"ETag": "other" if scenario == "etag" else "fixture-etag"}

    with (
        patch.object(target, "call", side_effect=call),
        patch.object(
            module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(
                free=0 if scenario == "capacity" else 2 * 1024**3
            ),
        ),
    ):
        if scenario == "success":
            assert target.download("backups/config/a", output, 10) == head
            assert output.stat().st_mode & 0o777 == 0o600
        else:
            with pytest.raises(RuntimeError):
                target.download(
                    "backups/config/a", output, 3 if scenario == "oversize" else 10
                )
    if scenario == "exists":
        assert output.read_bytes() == b"keep"


@pytest.mark.parametrize(
    "scenario",
    ["valid", "algorithm", "sidecar", "filename", "digest", "metadata", "compression"],
)
def test_verified_download_requires_checksum_compression_and_optional_metadata(
    tmp_path, scenario
):
    module = load("verify-s3-download.py")
    data = b"synthetic archive"
    digest = hashlib.sha256(data).hexdigest()
    target = Mock()

    def download(key, path, limit):
        if key.endswith(".sha256"):
            path.write_text(
                "invalid"
                if scenario == "sidecar"
                else (
                    ("0" * 64 if scenario == "digest" else digest)
                    + "  "
                    + ("wrong" if scenario == "filename" else "archive.zst")
                )
            )
        else:
            path.write_bytes(data)
        return {
            "Metadata": {"sha256": "different" if scenario == "metadata" else digest},
            "LastModified": "2026-10-29T00:00:00Z",
        }

    target.download.side_effect = download
    with patch.object(
        module.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=1 if scenario == "compression" else 0),
    ):
        if scenario == "valid":
            result = module.verify(
                target,
                {"Key": "prefix/archive.zst"},
                tmp_path,
                "verified.zst",
                "sha256",
                1000,
                True,
            )
            assert result["sha256"] == digest and result["tls_certificate_verification"]
            assert (tmp_path / "verified.zst").read_bytes() == data
        else:
            with pytest.raises(RuntimeError):
                module.verify(
                    target,
                    {"Key": "prefix/archive.zst"},
                    tmp_path,
                    "verified.zst",
                    "crc" if scenario == "algorithm" else "sha256",
                    1000,
                    True,
                )


def test_time_selection_is_offset_aware_and_filename_order_breaks_ties(tmp_path):
    module = load("verify-s3-download.py")
    since = module.utc("2026-10-29T00:00:00Z")
    objects = [
        {"Key": "prefix/a.zst", "LastModified": "2026-10-29T01:00:00+01:00"},
        {"Key": "prefix/b.zst", "LastModified": "2026-10-29T00:00:00Z"},
    ]
    assert module.select(objects, r".*\.zst", since)["Key"] == "prefix/b.zst"
    with pytest.raises(RuntimeError):
        module.select(objects, r".*\.sql", since)
    with pytest.raises(RuntimeError):
        module.utc("2026-10-29T00:00:00")
    path = tmp_path / "receipt"
    module.private_json(path, {"safe": True})
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        module.private_json(path, {})


@pytest.mark.parametrize(
    "scenario", ["valid", "digest", "section", "failure-marker", "sidecar"]
)
def test_native_backup_hook_patch_refuses_drift_and_propagates_failure(scenario):
    module = load("patch-native-hooks.py")
    sidecar = "                    silent run_as_user ${play_fair} aws ${PARAM_AWS_ENDPOINT_URL} s3 cp ${temporary_directory}/*.${checksum_extension} s3://${backup_job_s3_bucket}/${backup_job_s3_path}/ ${s3_ssl} ${s3_ca_cert} ${backup_job_s3_extra_opts}\n"
    marker = "                    master_exit_code=1\n"
    text = (
        "before\n"
        + marker * 2
        + sidecar
        + module.BEGIN
        + "old hook implementation\n"
        + module.END
        + "after\n"
    )
    if scenario == "section":
        text += module.BEGIN
    if scenario == "failure-marker":
        text = text.replace(marker, "changed failure marker\n", 1)
    if scenario == "sidecar":
        text = text.replace(sidecar, "changed sidecar\n")
    raw = text.encode()
    with patch.object(
        module,
        "EXPECTED_SHA256",
        "0" * 64 if scenario == "digest" else hashlib.sha256(raw).hexdigest(),
    ):
        if scenario == "valid":
            result = module.patch(raw).decode()
            assert "old hook implementation" not in result
            assert (
                "|| post_script_exit=$?" in result and "|| move_exit_code=$?" in result
            )
            assert result.count(marker + "                    exitcode_backup=1\n") == 2
            assert result.endswith(module.END + "after\n")
        else:
            with pytest.raises(RuntimeError):
                module.patch(raw)


def test_native_pg_cli_rejects_bad_connection_without_running_native_dump(capsys):
    import runpy
    import sys

    with (
        patch.object(sys, "argv", ["pg-dumpall-guard", "-h"]),
        patch("os.execv") as execute,
    ):
        with pytest.raises(SystemExit) as result:
            runpy.run_path(
                str(ROOT / "services/database-backup/pg-dumpall-guard.py"),
                run_name="__main__",
            )
        assert result.value.code == 1
        assert json.loads(capsys.readouterr().err)["status"] == "backup_blocked"
        execute.assert_not_called()


def test_s3_cli_refuses_invalid_time_before_creating_verification_directories(capsys):
    import runpy
    import sys

    with (
        patch.object(sys, "argv", ["verify-s3-download", "--not-before", "invalid"]),
        patch.object(Path, "mkdir") as create,
    ):
        with pytest.raises(SystemExit) as result:
            runpy.run_path(
                str(ROOT / "services/database-backup/verify-s3-download.py"),
                run_name="__main__",
            )
        assert result.value.code == 1
        assert json.loads(capsys.readouterr().out)["status"] == "failed"
        create.assert_not_called()
