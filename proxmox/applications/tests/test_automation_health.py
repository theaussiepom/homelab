"""The probes authenticate privately, publish nothing and fail on open APIs."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "automation_health", Path(__file__).resolve().parents[1] / "automation-health.py"
)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class AutomationHealthTests(unittest.TestCase):
    def test_loopback_probes_never_follow_redirects(self):
        with self.assertRaises(ValueError):
            health.NoRedirect().redirect_request(
                None, None, 302, "Found", {}, "https://other.invalid/"
            )

    def test_mqtt_uses_retained_account_and_requires_anonymous_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "entries.json"
            path.write_text(
                json.dumps(
                    {
                        "data": {
                            "entries": [
                                {
                                    "domain": "mqtt",
                                    "data": {
                                        "username": "fixture-user",
                                        "password": "fixture-password",
                                    },
                                }
                            ]
                        }
                    }
                )
            )
            with patch.object(health, "connect", side_effect=[0, 5]) as connect:
                health.mqtt(path)
                self.assertEqual(
                    connect.call_args_list[0].args, ("fixture-user", "fixture-password")
                )
                self.assertEqual(connect.call_args_list[1].args, ())
            with (
                patch.object(health, "connect", side_effect=[0, 0]),
                self.assertRaises(ValueError),
            ):
                health.mqtt(path)

    def test_mqtt_packets_only_connect_and_disconnect_even_with_fragmented_reply(self):
        from unittest.mock import MagicMock

        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.recv.side_effect = [b"\x20", b"\x02\x00\x00"]
        with patch.object(health.socket, "create_connection", return_value=stream):
            self.assertEqual(health.connect("fixture-user", "fixture-password"), 0)
        sent = [call.args[0] for call in stream.sendall.call_args_list]
        self.assertEqual([packet[0] for packet in sent], [0x10, 0xE0])
        self.assertIn(b"fixture-user", sent[0])
        stream.recv.side_effect = [b"\x20\x02\x00", b""]
        with (
            patch.object(health.socket, "create_connection", return_value=stream),
            self.assertRaises(ValueError),
        ):
            health.connect()

    def test_http_probes_require_the_existing_login_boundaries(self):
        for service, replies in [
            ("homeassistant", [(200, b""), (401, b"")]),
            ("node_red", [(200, b'{"type":"strategy"}'), (401, b"")]),
        ]:
            with (
                self.subTest(service=service),
                patch.object(health, "http", side_effect=replies),
            ):
                health.probe(service)
            bad = list(replies)
            bad[-1] = (200, b"")
            with (
                self.subTest(service=service),
                patch.object(health, "http", side_effect=bad),
                self.assertRaises(ValueError),
            ):
                health.probe(service)

    def test_timeout_stops_without_retrying_an_application_action(self):
        with (
            patch.object(health, "probe", side_effect=ValueError("private detail")),
            patch.object(health.time, "monotonic", side_effect=[0, 181]),
            patch.object(health.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(ValueError, "Application probe did not pass"):
                health.run("mqtt")
            sleep.assert_not_called()


class ProbeBoundaryTests(unittest.TestCase):
    def test_mqtt_credentials_acknowledgements_and_multi_byte_packet_lengths(self):
        from unittest.mock import MagicMock

        for value in (None, "", "x" * 65536):
            with (
                self.subTest(value_type=type(value).__name__),
                self.assertRaises(ValueError),
            ):
                health.text(value)
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.recv.return_value = b"\x30\x02\x00\x00"
        with (
            patch.object(health.socket, "create_connection", return_value=stream),
            self.assertRaisesRegex(ValueError, "acknowledgement"),
        ):
            health.connect()
        stream.recv.return_value = b"\x20\x02\x00\x05"
        with patch.object(health.socket, "create_connection", return_value=stream):
            self.assertEqual(health.connect("u" * 128, "p"), 5)
        packet = stream.sendall.call_args.args[0]
        self.assertTrue(packet[1] & 128)

    def test_mqtt_selection_and_failed_existing_account_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "entries"
            for entries in (
                [],
                [{"domain": "mqtt", "data": {}}, {"domain": "mqtt", "data": {}}],
            ):
                path.write_text(json.dumps({"data": {"entries": entries}}))
                with self.assertRaisesRegex(ValueError, "integration"):
                    health.mqtt(path)
            path.write_text(
                json.dumps(
                    {
                        "data": {
                            "entries": [
                                {
                                    "domain": "mqtt",
                                    "data": {
                                        "username": "fixture",
                                        "password": "fixture",
                                    },
                                }
                            ]
                        }
                    }
                )
            )
            with (
                patch.object(health, "connect", return_value=4),
                self.assertRaisesRegex(ValueError, "authenticate"),
            ):
                health.mqtt(path)

    def test_http_response_size_status_and_error_are_bounded(self):
        from unittest.mock import MagicMock
        from urllib.error import HTTPError

        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b"ready"
        with patch.object(health, "build_opener", return_value=opener):
            self.assertEqual(health.http(80, "/"), (200, b"ready"))
        response.read.return_value = b"x" * 65537
        with (
            patch.object(health, "build_opener", return_value=opener),
            self.assertRaisesRegex(ValueError, "bound"),
        ):
            health.http(80, "/")
        opener.open.side_effect = HTTPError("http://127.0.0.1", 401, "Denied", {}, None)
        with patch.object(health, "build_opener", return_value=opener):
            self.assertEqual(health.http(80, "/"), (401, b""))

    def test_only_selected_service_probes_and_read_only_retry_run(self):
        with patch.object(health, "mqtt") as mqtt:
            health.probe("mqtt")
            mqtt.assert_called_once()
        with self.assertRaises(ValueError):
            health.probe("unsupported")
        with (
            patch.object(health, "http", return_value=(503, b"")),
            self.assertRaises(ValueError),
        ):
            health.probe("homeassistant")
        for response in ((503, b"{}"), (200, b'{"type":"credentials"}')):
            with (
                patch.object(health, "http", return_value=response),
                self.assertRaises(ValueError),
            ):
                health.probe("node_red")
        with (
            patch.object(health, "probe", side_effect=[ValueError("not yet"), None]),
            patch.object(health.time, "monotonic", side_effect=[0, 1]),
            patch.object(health.time, "sleep") as sleep,
        ):
            self.assertEqual(health.run("mqtt")["read_only_probe"], "passed")
            sleep.assert_called_once_with(2)


if __name__ == "__main__":
    unittest.main()
