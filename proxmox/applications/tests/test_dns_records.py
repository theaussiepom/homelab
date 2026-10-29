"""Generated records and DNS answers share one explicit hostname/address contract."""

import io
import json
from pathlib import Path
import runpy
import socket
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_records as dns


class DnsRecordTests(unittest.TestCase):
    def test_only_owned_hostnames_change_while_unrelated_aliases_are_preserved(self):
        old = [
            "192.168.100.240 BROKER.MQTT. retained.alias",
            "198.18.40.99 retained.example",
            "192.168.100.240 broker.mqtt",
        ]
        expected = [
            "192.168.100.240 retained.alias",
            "198.18.40.99 retained.example",
            "198.18.40.21 broker.mqtt",
        ]
        self.assertEqual(
            dns.desired_hosts(old, {"broker.mqtt": "198.18.40.21"}), expected
        )
        self.assertEqual(
            dns.desired_hosts(expected, {"broker.mqtt": "198.18.40.21"}), expected
        )
        for value in (None, [None], ["broken"], ["not-an-ip name"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dns.desired_hosts(value, {})

    def test_supported_config_command_is_bounded_and_read_back_before_success(self):
        old = "[ 192.168.100.240 broker.mqtt, 198.18.40.99 retained.example ]\n"
        new = "[ 198.18.40.99 retained.example, 198.18.40.21 broker.mqtt ]\n"
        result = lambda value: SimpleNamespace(stdout=value)
        with patch.object(
            dns.subprocess,
            "run",
            side_effect=[result(old), result("ignored"), result(new)],
        ) as command:
            self.assertTrue(
                dns.reconcile(
                    {"broker.mqtt": "198.18.40.21"}, Path("/private/compose.yml")
                )
            )
        self.assertEqual(
            json.loads(command.call_args_list[1].args[0][-1]),
            ["198.18.40.99 retained.example", "198.18.40.21 broker.mqtt"],
        )
        self.assertEqual(command.call_count, 3)
        self.assertEqual(command.call_args.kwargs["timeout"], 30)
        with patch.object(dns.subprocess, "run", return_value=result(new)) as command:
            self.assertFalse(
                dns.reconcile(
                    {"broker.mqtt": "198.18.40.21"}, Path("/private/compose.yml")
                )
            )
        self.assertEqual(command.call_count, 1)
        with patch.object(dns.subprocess, "run", return_value=result("[ ]")):
            self.assertFalse(dns.reconcile({}, Path("/private/compose.yml")))
        for bad in ("not an array", "[ " + "x" * (1024 * 1024) + " ]"):
            with self.subTest(value=bad[:20]), patch.object(
                dns.subprocess, "run", return_value=result(bad)
            ), self.assertRaises(ValueError):
                dns.reconcile({}, Path("/private/compose.yml"))
        with patch.object(
            dns.subprocess, "run", side_effect=[result(old), result(""), result(old)]
        ), self.assertRaisesRegex(ValueError, "did not retain"):
            dns.reconcile({"broker.mqtt": "198.18.40.21"}, Path("/private/compose.yml"))

    def test_reconciliation_cli_reports_only_changed_status(self):
        with tempfile.TemporaryDirectory() as directory:
            records = Path(directory) / "records.json"
            records.write_text('{"broker.mqtt":"198.18.40.21"}')
            with patch.object(
                sys,
                "argv",
                [
                    "dns_records.py",
                    "reconcile",
                    "--records",
                    str(records),
                    "--compose",
                    "/private/compose.yml",
                ],
            ), patch.object(dns, "reconcile", return_value=True), patch(
                "sys.stdout", new_callable=io.StringIO
            ) as output:
                dns.main()
            self.assertEqual(json.loads(output.getvalue()), {"changed": True})

    def response(self, address="198.18.40.21"):
        question = b"\x06broker\x04mqtt\0\0\1\0\1"
        return (
            struct.pack("!6H", 0x4D51, 0x8180, 1, 1, 0, 0)
            + question
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton(address)
        )

    def client(self, response):
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.return_value = response
        return client

    def test_records_are_finite_literal_hostnames_and_addresses(self):
        self.assertEqual(
            dns.desired_hosts(
                [], {"z.example": "198.18.40.2", "a.example": "198.18.40.1"}
            ),
            ["198.18.40.1 a.example", "198.18.40.2 z.example"],
        )
        self.assertEqual(dns.desired_hosts([], {}), [])
        for value in (
            [],
            {"bare": "198.18.40.1"},
            {"bad\n.example": "198.18.40.1"},
            {"x" * 254 + ".example": "198.18.40.1"},
            {"a.example": "127.0.0.1"},
            {"a.example": "0.0.0.0"},
            {"a.example": "224.0.0.1"},
            {"a.example": "169.254.1.2"},
            {"a.example": "::1"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dns.validate(value)

    def test_probe_contacts_only_local_pihole_and_matches_exact_answers(self):
        client = self.client(self.response())
        with patch.object(dns.socket, "socket", return_value=client):
            self.assertEqual(
                dns.probe("broker.mqtt", "198.18.40.21"),
                {"read_only_dns_check": "passed"},
            )
        client.connect.assert_called_once_with(("127.0.0.1", 53))
        client.settimeout.assert_called_once_with(5)
        self.assertEqual(
            client.send.call_args.args[0][12:], b"\x06broker\x04mqtt\0\0\1\0\1"
        )

    def test_wrong_truncated_or_ambiguous_dns_answers_fail(self):
        valid = self.response()
        cases = [
            b"",
            self.response("198.18.40.99"),
            valid[:-1],
            valid[:12] + b"wrong" + valid[17:],
        ]
        for identity, flags, questions, answers in (
            (1, 0x8180, 1, 1),
            (0x4D51, 0x8380, 1, 1),
            (0x4D51, 0x8183, 1, 1),
            (0x4D51, 0x8180, 0, 1),
            (0x4D51, 0x8180, 1, 0),
            (0x4D51, 0x8180, 1, 65),
        ):
            cases.append(
                struct.pack("!6H", identity, flags, questions, answers, 0, 0)
                + valid[12:]
            )
        offset = len(valid) - 16
        cases += [
            valid[:offset] + b"\xc0\x01" + valid[offset + 2 :],
            valid[: offset + 2] + struct.pack("!HHIH", 28, 1, 60, 4) + valid[-4:],
        ]
        for response in cases:
            with self.subTest(response=response), patch.object(
                dns.socket, "socket", return_value=self.client(response)
            ), self.assertRaises((ValueError, struct.error)):
                dns.probe("broker.mqtt", "198.18.40.21")

    def test_standalone_probe_emits_only_the_read_only_result(self):
        with patch.object(
            dns.socket, "socket", return_value=self.client(self.response())
        ), patch.object(
            sys, "argv", ["dns_records.py", "probe", "broker.mqtt", "198.18.40.21"]
        ), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as output:
            runpy.run_path(str(Path(dns.__file__)), run_name="__main__")
        self.assertEqual(
            json.loads(output.getvalue()), {"read_only_dns_check": "passed"}
        )
