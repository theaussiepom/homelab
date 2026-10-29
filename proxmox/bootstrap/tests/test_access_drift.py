"""Credential updates refuse drift before a write or a replacement token."""

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_access
import test_reconcile_access as reconcile_cases
import test_host_access as grant_cases


class AccessDriftTests(unittest.TestCase):
    def test_reconcile_refuses_invalid_saved_scope_expiry_and_guest_identity(self):
        for scenario in (
            "saved",
            "negative",
            "far-future",
            "expired",
            "metadata",
            "propagating",
            "missing-owner",
            "wrong-owner",
            "config",
        ):
            case = reconcile_cases.ReconcileTests()
            case.setUp()
            request = case.request
            if scenario == "saved":
                request["expected"]["status"] = "pending"
            if scenario == "negative":
                request["expires_at"] = -1
            if scenario == "far-future":
                request["expires_at"] = 40000000
            if scenario == "expired":
                request["expires_at"] = 999
            if scenario == "metadata":
                case.expiry += 1
            if scenario == "propagating":
                request["expected"]["grants"][0]["propagate"] = True
            if scenario == "missing-owner":
                case.rows.clear()
            if scenario == "wrong-owner":
                case.rows[0]["name"] = "other"

            def execute(args):
                result = case.execute(args)
                if scenario == "config" and any(
                    arg.endswith("/lxc/900/config") for arg in args
                ):
                    result["hostname"] = "other"
                return result

            with (
                self.subTest(scenario=scenario),
                patch.object(host_access.socket, "gethostname", return_value="pve"),
                patch.object(host_access, "node_ready", return_value=True),
                patch.object(host_access.time, "time", return_value=1000),
            ):
                with self.assertRaises(RuntimeError):
                    host_access.reconcile(request, execute, apply=True)
            self.assertFalse(
                any(
                    c[:3] == ["pveum", "acl", "modify"] or "add" in c or "delete" in c
                    for c in case.host.calls
                )
            )

    def test_reconcile_cannot_silently_remove_previously_saved_grants(self):
        case = reconcile_cases.ReconcileTests()
        case.setUp()
        case.saved["grants"].append(
            {"path": "/vms/6102", "roles": "PVEVMAdmin", "propagate": False}
        )
        case.host.acls.append(
            {
                "path": "/vms/6102",
                "roleid": "PVEVMAdmin",
                "type": "token",
                "ugid": case.saved["token_id"],
                "propagate": 0,
            }
        )
        with self.assertRaisesRegex(RuntimeError, "remove earlier"):
            case.reconcile(True)
        self.assertFalse(
            any(c[:3] == ["pveum", "acl", "modify"] for c in case.host.calls)
        )

    def test_wrong_host_and_narrow_interface_schema_refuse_before_reading_tokens(self):
        case = reconcile_cases.ReconcileTests()
        case.setUp()
        with patch.object(host_access.socket, "gethostname", return_value="unrelated"):
            with self.assertRaisesRegex(RuntimeError, "selected ready"):
                host_access.reconcile(case.request, case.execute, True)
        self.assertEqual(case.host.calls, [])
        request = copy.deepcopy(case.request)
        request["applications"][0]["interfaces"][0]["extra"] = "undeclared"
        with self.assertRaisesRegex(RuntimeError, "bridge and VLAN"):
            host_access.declared_grants(request)

    def test_grant_refuses_missing_effective_privileges_and_exact_acl_drift(self):
        for scenario in ("privilege", "propagation", "acl"):
            case = grant_cases.HostAccessTests()
            case.setUp()

            def execute(args):
                result = case.execute(args)
                if args[:4] == ["pveum", "user", "token", "permissions"]:
                    if scenario == "privilege":
                        result["/vms/900"].pop("VM.Allocate")
                    if scenario == "propagation":
                        result["/vms/900"]["VM.Allocate"] = 1
                    if scenario == "acl":
                        case.acls[0]["propagate"] = 1
                return result

            with (
                self.subTest(scenario=scenario),
                patch.object(host_access.socket, "gethostname", return_value="pve"),
                patch.object(host_access, "node_ready", return_value=True),
                patch.object(host_access.time, "time", return_value=1000),
            ):
                with self.assertRaises(RuntimeError):
                    host_access.grant(
                        case.request, execute, case.emitted.append, ca_pem="synthetic"
                    )
            self.assertEqual(case.emitted[0]["status"], "token_created_grants_pending")
            self.assertFalse(any("delete" in call for call in case.calls))
