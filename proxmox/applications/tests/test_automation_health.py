"""The probes authenticate privately, publish nothing and fail on open APIs."""

import importlib.util
import base64
import hashlib
from http.client import BadStatusLine, IncompleteRead
import io
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
    def test_selected_broker_probe_path_is_explicit_and_unavailable_to_other_modes(self):
        selected=Path('/opt/homelab-app/runtime/broker_a/mqtt-probe.json')
        with patch.object(health,'mqtt') as mqtt:
            health.probe('mqtt-broker',selected)
            mqtt.assert_called_once_with(selected,standalone=True)
        for service,path in [('node_red',selected),('mqtt',selected),
                ('mqtt-broker',Path('/tmp/mqtt-probe.json')),
                ('mqtt-broker',Path('/opt/homelab-app/runtime/../mqtt-probe.json')),
                ('mqtt-broker',Path('/opt/homelab-app/runtime/${ENV}/mqtt-probe.json'))]:
            with self.subTest(service=service),patch.object(health,'mqtt') as mqtt,self.assertRaises(ValueError):
                health.probe(service,path)
            mqtt.assert_not_called()

    def test_fresh_node_red_checks_only_qualified_local_ui_without_claiming_auth(self):
        with patch.object(health, 'http', return_value=(200, b'public UI')) as http:
            result = health.run('node_red-fresh')
            http.assert_called_once_with(1880, '/')
            self.assertEqual(result, {'service': 'node_red-fresh', 'read_only_probe': 'passed', 'scope': 'ui_only'})
        for status in (201, 301, 302, 401, 403, 500):
            with self.subTest(status=status), patch.object(health, 'http', return_value=(status, b'')), \
                    self.assertRaises(ValueError):
                health.probe('node_red-fresh')

    def test_fresh_homeassistant_allows_only_exact_onboarding_and_keeps_api_auth(self):
        with patch.object(health, 'local_response', side_effect=[(302, '/onboarding.html'),
                (200, None), (401, None)]) as response, patch.object(health, 'homeassistant_auth_challenge') as challenge:
            health.probe('homeassistant-fresh')
            self.assertEqual([row.args[0] for row in response.call_args_list], ['/', '/onboarding.html', '/api/'])
            challenge.assert_called_once_with()
        with patch.object(health, 'local_response', side_effect=[(200, None), (401, None)]), \
                patch.object(health, 'homeassistant_auth_challenge'):
            health.probe('homeassistant-fresh')
        for invalid in ((302, 'https://foreign.invalid/onboarding.html'), (302, '//foreign.invalid/'),
                        (302, '/other'), (301, '/onboarding.html'), (200, '/onboarding.html')):
            with self.subTest(response=invalid), patch.object(health, 'local_response', return_value=invalid), \
                    self.assertRaises(ValueError):
                health.probe('homeassistant-fresh')
        for responses in ([(302, '/onboarding.html'), (302, '/onboarding.html')],
                          [(302, '/onboarding.html'), (200, None), (200, None)]):
            with self.subTest(responses=responses), patch.object(health, 'local_response', side_effect=responses), \
                    self.assertRaises(ValueError):
                health.probe('homeassistant-fresh')

    def test_fresh_homeassistant_loopback_http_is_bounded_and_does_not_redirect(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status, response.getheader.return_value, response.read.return_value = 302, '/onboarding.html', b''
        with patch.object(health, 'HTTPConnection', return_value=connection) as http:
            self.assertEqual(health.local_response('/'), (302, '/onboarding.html'))
            http.assert_called_once_with('127.0.0.1', 8123, timeout=5)
            connection.request.assert_called_once_with('GET', '/')
            response.read.assert_called_once_with(65537)
            connection.close.assert_called_once_with()
        response.read.return_value = b'x' * 65537
        with patch.object(health, 'HTTPConnection', return_value=connection), self.assertRaises(ValueError):
            health.local_response('/api/')
        with self.assertRaises(ValueError):
            health.local_response('https://foreign.invalid/')

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

    def test_homeassistant_requires_challenge_without_unauthorized_REST_request(self):
        with (
            patch.object(health, "http", return_value=(200, b"")) as http,
            patch.object(health, "homeassistant_auth_challenge") as challenge,
        ):
            health.probe("homeassistant")
            http.assert_called_once_with(8123, "/")
            challenge.assert_called_once_with()
        with (
            patch.object(health, "http", return_value=(200, b"")),
            patch.object(health, "homeassistant_auth_challenge", side_effect=ValueError("open API")),
            self.assertRaises(ValueError),
        ):
            health.probe("homeassistant")

    def test_timeout_stops_without_retrying_an_application_action(self):
        with (
            patch.object(health, "probe", side_effect=ValueError("private detail")),
            patch.object(health.time, "monotonic", side_effect=[0, 181]),
            patch.object(health.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(ValueError, "Application probe did not pass"):
                health.run("mqtt")
            sleep.assert_not_called()

    def test_HTTP_protocol_errors_wait_for_readiness_but_keep_the_deadline(self):
        for error in [BadStatusLine("truncated status"), IncompleteRead(b"partial")]:
            with (
                self.subTest(error=type(error).__name__, outcome="ready"),
                patch.object(health, "probe", side_effect=[error, None]) as probe,
                patch.object(health.time, "monotonic", side_effect=[0, 1]),
                patch.object(health.time, "sleep") as sleep,
            ):
                self.assertEqual(health.run("homeassistant"),
                                 {"service": "homeassistant", "read_only_probe": "passed"})
                self.assertEqual(probe.call_count, 2)
                sleep.assert_called_once_with(2)
            with (
                self.subTest(error=type(error).__name__, outcome="deadline"),
                patch.object(health, "probe", side_effect=error),
                patch.object(health.time, "monotonic", side_effect=[0, 181]),
                patch.object(health.time, "sleep") as sleep,
            ):
                with self.assertRaisesRegex(ValueError, "Application probe did not pass"):
                    health.run("homeassistant")
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


class HomeAssistantChallengeTests(unittest.TestCase):
    def connection(self, payload=None, frame=None, headers=None, status=101):
        from unittest.mock import MagicMock

        value = {"type": "auth_required", "ha_version": "2026.10.0"}
        payload = json.dumps(value).encode() if payload is None else payload
        frame = bytes([0x81, len(payload)]) + payload if frame is None else frame
        key = base64.b64encode(b"k" * 16).decode()
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(),
            usedforsecurity=False,
        ).digest()).decode()
        values = {"Upgrade": "WebSocket", "Connection": "keep-alive, Upgrade",
                  "Sec-WebSocket-Accept": accept}
        values.update(headers or {})
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = status
        response.getheader.side_effect = lambda name, default=None: values.get(name, default)
        response.fp = io.BytesIO(frame)
        return connection

    def check(self, connection, succeeds):
        with (
            patch.object(health, "HTTPConnection", return_value=connection) as factory,
            patch.object(health.os, "urandom", side_effect=[b"k" * 16, b"m" * 4]),
        ):
            if succeeds:
                health.homeassistant_auth_challenge()
            else:
                with self.assertRaises(ValueError):
                    health.homeassistant_auth_challenge()
            factory.assert_called_once_with("127.0.0.1", 8123, timeout=5)
        connection.close.assert_called_once_with()
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("GET", "/api/websocket"))
        self.assertEqual(set(kwargs["headers"]), {
            "Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Key",
        })
        if succeeds:
            self.assertEqual(connection.sock.sendall.call_args.args[0],
                             b"\x88\x82mmmm" + bytes([3 ^ 109, 232 ^ 109]))
        else:
            connection.sock.sendall.assert_not_called()

    def test_initial_auth_required_is_bounded_and_only_a_close_frame_is_sent(self):
        self.check(self.connection(), True)
        payload = json.dumps({"type": "auth_required", "ha_version": "v" * 128}).encode()
        self.check(self.connection(frame=b"\x81\x7e" + len(payload).to_bytes(2, "big") + payload), True)

    def test_redirect_bad_upgrade_and_wrong_server_accept_refuse(self):
        for kwargs in ({"status": 302}, {"headers": {"Upgrade": "http"}},
                       {"headers": {"Connection": "close"}},
                       {"headers": {"Sec-WebSocket-Accept": "foreign"}}):
            with self.subTest(kwargs=kwargs):
                self.check(self.connection(**kwargs), False)

    def test_bad_frames_and_incomplete_or_oversized_challenges_refuse(self):
        for frame in (b"", b"\x81", b"\x01\x00", b"\x82\x00", b"\x81\x80",
                      b"\x81\x7f", b"\x81\x7e\x00", b"\x81\x7e\x10\x01",
                      b"\x81\x02x", b"\x81\x01x"):
            with self.subTest(frame=frame):
                self.check(self.connection(frame=frame), False)

    def test_open_API_invalid_type_or_missing_version_cannot_pass(self):
        for value in ([], {}, {"type": "auth_ok", "ha_version": "v"},
                      {"type": "auth_required"}, {"type": "auth_required", "ha_version": 1},
                      {"type": "auth_required", "ha_version": ""}):
            with self.subTest(value=value):
                self.check(self.connection(payload=json.dumps(value).encode()), False)

    def test_repeated_real_HTTP_upgrades_never_make_failed_login_requests(self):
        import http.client
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        original = http.client.HTTPConnection
        counts = {"failed_auth": 0, "challenges": 0, "closes": 0}
        closed = threading.Condition()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/api/":
                    counts["failed_auth"] += 1
                    status = 401
                elif counts["failed_auth"] >= 3:
                    status = 403
                else:
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    accept = base64.b64encode(hashlib.sha1(
                        (self.headers["Sec-WebSocket-Key"] +
                         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(),
                        usedforsecurity=False,
                    ).digest()).decode()
                    self.send_header("Sec-WebSocket-Accept", accept)
                    self.end_headers()
                    data = b'{"type":"auth_required","ha_version":"2026.10.0"}'
                    self.wfile.write(bytes([0x81, len(data)]) + data)
                    self.wfile.flush()
                    counts["challenges"] += 1
                    close = self.rfile.read(8)
                    if len(close) == 8 and close[:2] == b"\x88\x82" and bytes(
                            close[6 + i] ^ close[2 + i] for i in range(2)) == b"\x03\xe8":
                        with closed:
                            counts["closes"] += 1
                            closed.notify_all()
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with patch.object(health, "HTTPConnection", side_effect=lambda *a, **k:
                                  original("127.0.0.1", server.server_port, timeout=5)):
                    for _ in range(30):
                        health.homeassistant_auth_challenge()
                with closed:
                    self.assertTrue(closed.wait_for(lambda: counts["closes"] == 30, timeout=2))
                self.assertEqual(counts, {"failed_auth": 0, "challenges": 30, "closes": 30})
                for _ in range(3):
                    client = original("127.0.0.1", server.server_port, timeout=5)
                    client.request("GET", "/api/")
                    self.assertEqual(client.getresponse().status, 401)
                    client.close()
                with patch.object(health, "HTTPConnection", side_effect=lambda *a, **k:
                                  original("127.0.0.1", server.server_port, timeout=5)):
                    with self.assertRaises(ValueError):
                        health.homeassistant_auth_challenge()
                self.assertEqual(counts["failed_auth"], 3)
                self.assertEqual(counts["challenges"], 30)
            finally:
                server.shutdown()
                worker.join()


if __name__ == "__main__":
    unittest.main()
