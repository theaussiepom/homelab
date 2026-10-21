import base64
import hashlib
import socket
import threading
import unittest
from unittest.mock import patch

import probe


class HandshakeTests(unittest.TestCase):
    def check(self, protocol, response):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        self.addCleanup(server.close)
        port = server.getsockname()[1]
        def serve():
            client, _ = server.accept()
            with client:
                request = client.recv(4096)
                client.sendall(response(request))
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = probe.exchange({'address': '127.0.0.1', 'port': port, 'protocol': protocol})
        thread.join(2)
        return result

    def test_http_success(self):
        result = self.check('http', lambda _: b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        self.assertTrue(result['healthy'])

    def test_http_error_not_healthy(self):
        result = self.check('http', lambda _: b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n')
        self.assertFalse(result['healthy'])

    def test_valid_websocket_handshake(self):
        def response(request):
            key = next(line.split(': ', 1)[1] for line in request.decode().split('\r\n') if line.startswith('Sec-WebSocket-Key:'))
            accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
            return b'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'
        self.assertTrue(self.check('websocket', response)['healthy'])

    def test_invalid_accept_rejected(self):
        self.assertFalse(self.check('websocket', lambda _: b'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: fake\r\n\r\n')['healthy'])

    def test_refused_socket_reports_failed_observation(self):
        with patch.object(probe, 'check_one', side_effect=ConnectionRefusedError):
            self.assertEqual(probe.observe({'probes': [{'name': 'down'}]})[0]['healthy'], False)

    def test_header_injection_rejected(self):
        with self.assertRaises(ValueError):
            probe.exchange({'address': '127.0.0.1', 'port': 80, 'protocol': 'http', 'path': '/\r\nInjected: x'})


if __name__ == '__main__':
    unittest.main()
