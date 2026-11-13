"""Host adapters require exact readback and never replace existing authority."""

import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_access
import host_template
import host_cd_access
import host_api
import test_host_api as api_cases
import test_host_template as template_cases
import test_reconcile_access as reconcile_cases
import test_host_access as grant_cases


class HostReadbackEdges(unittest.TestCase):
    def test_node_readiness_is_bound_to_the_mounted_local_cluster_identity(self):
        local = Path("/etc/pve/local")
        node = Path("/etc/pve/nodes/pve")
        for mounted in (True, False):
            with (
                patch.object(host_access.os.path, "ismount", return_value=mounted),
                patch.object(Path, "is_dir", return_value=True),
                patch.object(
                    Path, "resolve", lambda path: node if path == local else path
                ),
            ):
                self.assertEqual(host_access.node_ready("pve"), mounted)
                self.assertEqual(host_template.node_ready("pve"), mounted)

    def test_cd_identity_is_minted_once_verified_and_drift_is_held(self):
        state = {"tokens": [], "acl": []}
        emitted = []
        calls = []

        def execute(args):
            calls.append(args)
            if args[1:4] == ["user", "token", "add"]:
                state["tokens"] = [
                    {"tokenid": host_cd_access.TOKEN, "privsep": 1, "expire": 0}
                ]
                return {"value": "synthetic"}
            if args[1:3] == ["acl", "modify"]:
                state["acl"] = [
                    {
                        "ugid": host_cd_access.IDENTITY,
                        "path": "/",
                        "roleid": "Administrator",
                        "propagate": 1,
                        "type": "token",
                    }
                ]
                return None
            return state["tokens"] if args[1:3] == ["user", "token"] else state["acl"]

        with (
            patch.object(host_cd_access.socket, "gethostname", return_value="pve"),
            patch.object(host_cd_access.os.path, "ismount", return_value=True),
            patch.object(
                Path,
                "resolve",
                lambda path: (
                    Path("/etc/pve/nodes/pve")
                    if path == Path("/etc/pve/local")
                    else path
                ),
            ),
        ):
            self.assertEqual(
                host_cd_access.provision("pve", execute=execute, emit=emitted.append)[
                    "status"
                ],
                "ready",
            )
            self.assertEqual(emitted[0]["status"], "credential_created_acl_pending")
            calls.clear()
            self.assertEqual(
                host_cd_access.provision("pve", verify=True, execute=execute)["status"],
                "ready",
            )
            self.assertFalse(any("add" in c or "modify" in c for c in calls))
            state["tokens"][0]["privsep"] = 0
            with self.assertRaises(ValueError):
                host_cd_access.provision("pve", verify=True, execute=execute)
            state["tokens"][0]["privsep"] = 1

            def command(args, **kwargs):
                return subprocess.CompletedProcess(
                    args, 0, json.dumps(execute(args)), ""
                )

            with (
                patch.object(
                    sys,
                    "argv",
                    ["host-cd", json.dumps({"node": "pve", "verify": True})],
                ),
                patch.object(host_cd_access.subprocess, "run", side_effect=command),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                runpy.run_path(str(Path(host_cd_access.__file__)), run_name="__main__")
                self.assertEqual(json.loads(output.getvalue())["status"], "ready")
        with (
            patch.object(host_cd_access.socket, "gethostname", return_value="other"),
            self.assertRaises(ValueError),
        ):
            host_cd_access.provision("pve", execute=execute)

    def test_api_cli_and_unusable_source_or_destination_never_expand_the_rule(self):
        case = api_cases.HostApiTests()
        case.setUp()
        try:
            for address in ("127.0.0.1", "0.0.0.0", "169.254.1.1"):
                with self.subTest(address=address), self.assertRaises(RuntimeError):
                    host_api.ensure_rule(
                        dict(case.request, guest_address=address), case.host.execute
                    )
            with self.assertRaisesRegex(RuntimeError, "destination"):
                host_api.ensure_rule(
                    dict(case.request, guest_address="198.18.25.2"), case.host.execute
                )

            def command(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, case.host.execute(args), "")

            with (
                patch.object(sys, "argv", ["host-api", json.dumps(case.request)]),
                patch.object(host_api.subprocess, "run", side_effect=command),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                runpy.run_path(str(Path(host_api.__file__)), run_name="__main__")
                self.assertEqual(
                    json.loads(output.getvalue().splitlines()[-1])["status"], "stored"
                )
        finally:
            case.doCleanups()

    def test_template_path_stream_and_published_bytes_are_each_verified(self):
        for scenario in ("node", "path", "overflow", "readback"):
            case = template_cases.HostTemplateTests()
            case.setUp()
            try:
                with (
                    self.subTest(scenario=scenario),
                    patch.object(
                        host_template.socket,
                        "gethostname",
                        return_value="other" if scenario == "node" else "pve",
                    ),
                    patch.object(host_template, "node_ready", return_value=True),
                ):
                    target = (
                        "relative.tar.zst" if scenario == "path" else str(case.target)
                    )
                    data = case.data + b"x" if scenario == "overflow" else case.data
                    original = host_template.digest
                    with (
                        patch.object(
                            host_template,
                            "digest",
                            side_effect=(
                                (lambda path: "0" * 64)
                                if scenario == "readback"
                                else original
                            ),
                        ),
                        self.assertRaises(RuntimeError),
                    ):
                        host_template.store(
                            case.request, io.BytesIO(data), execute=lambda args: target
                        )
                    if scenario == "readback":
                        self.assertEqual(case.target.read_bytes(), case.data)
            finally:
                case.doCleanups()

    def test_reconciliation_refuses_corrupted_post_write_metadata_acl_or_permissions(
        self,
    ):
        for scenario in ("metadata", "acl", "scope", "privileges"):
            case = reconcile_cases.ReconcileTests()
            case.setUp()
            written = [False]

            def execute(args):
                result = case.execute(args)
                if args[:3] == ["pveum", "acl", "modify"]:
                    written[0] = True
                if (
                    written[0]
                    and args[:4] == ["pveum", "user", "token", "list"]
                    and scenario == "metadata"
                ):
                    result[0]["expire"] += 1
                if (
                    written[0]
                    and args[:3] == ["pveum", "acl", "list"]
                    and scenario == "acl"
                ):
                    result[0]["propagate"] = 1
                if args[:4] == ["pveum", "user", "token", "permissions"]:
                    if scenario == "scope":
                        result["/"] = {"Sys.Modify": 1}
                    if scenario == "privileges":
                        result["/vms/900"] = {"VM.Audit": 0}
                return result

            with (
                self.subTest(scenario=scenario),
                patch.object(host_access.socket, "gethostname", return_value="pve"),
                patch.object(host_access, "node_ready", return_value=True),
                patch.object(host_access.time, "time", return_value=1000),
                self.assertRaises(RuntimeError),
            ):
                host_access.reconcile(case.request, execute, apply=True)
            self.assertFalse(any("delete" in c or "add" in c for c in case.host.calls))

    def test_grant_requires_explicit_selection_built_in_roles_and_uses_the_host_ca(
        self,
    ):
        for scenario in ("selection", "role", "ca"):
            case = grant_cases.HostAccessTests()
            case.setUp()
            if scenario == "selection":
                case.request["download_template"] = "yes"

            def execute(args):
                if scenario == "role" and args[:3] == ["pveum", "role", "list"]:
                    return []
                return case.execute(args)

            with (
                self.subTest(scenario=scenario),
                patch.object(host_access.socket, "gethostname", return_value="pve"),
                patch.object(host_access, "node_ready", return_value=True),
                patch.object(host_access.time, "time", return_value=1000),
                patch.object(Path, "read_text", return_value="synthetic host CA"),
            ):
                if scenario == "ca":
                    self.assertEqual(
                        host_access.grant(case.request, execute, ca_pem=None)["ca_pem"],
                        "synthetic host CA",
                    )
                else:
                    with self.assertRaises(RuntimeError):
                        host_access.grant(case.request, execute, ca_pem="synthetic")

    def test_workstation_cli_configuration_uses_the_existing_backup_lock(self):
        import bootstrap

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "HANDOVER.json").write_text("{}")
            with (
                patch.object(
                    sys,
                    "argv",
                    ["workstation", "--configuration", str(work), "fixture"],
                ),
                patch(
                    "subprocess.run", return_value=subprocess.CompletedProcess([], 7)
                ),
                self.assertRaises(SystemExit) as result,
            ):
                runpy.run_path(
                    str(bootstrap.HERE / "workstation.py"), run_name="__main__"
                )
            self.assertEqual(result.exception.code, 7)

    def test_host_access_cli_prints_ready_only_after_exact_grants_and_metadata(self):
        case = grant_cases.HostAccessTests()
        case.setUp()
        original = Path.read_text

        def read(path, *args, **kwargs):
            return (
                "synthetic public CA"
                if str(path) == "/etc/pve/pve-root-ca.pem"
                else original(path, *args, **kwargs)
            )

        def command(args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps(case.execute(args)), ""
            )

        with (
            patch.object(sys, "argv", ["host-access", json.dumps(case.request)]),
            patch.object(host_access.socket, "gethostname", return_value="pve"),
            patch.object(host_access.os.path, "ismount", return_value=True),
            patch.object(Path, "is_dir", return_value=True),
            patch.object(
                Path,
                "resolve",
                lambda path: (
                    Path("/etc/pve/nodes/pve")
                    if path == Path("/etc/pve/local")
                    else path
                ),
            ),
            patch.object(host_access.time, "time", return_value=1000),
            patch.object(Path, "read_text", read),
            patch.object(host_access.subprocess, "run", side_effect=command),
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            runpy.run_path(str(Path(host_access.__file__)), run_name="__main__")
            self.assertEqual(
                json.loads(output.getvalue().splitlines()[-1])["status"], "ready"
            )
            self.assertEqual(
                len(
                    [
                        call
                        for call in case.calls
                        if call[:4] == ["pveum", "user", "token", "add"]
                    ]
                ),
                1,
            )
