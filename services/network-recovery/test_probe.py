import base64
import hashlib
import io
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

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
            return b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'
        self.assertTrue(self.check('websocket', response)['healthy'])

    def test_invalid_accept_rejected(self):
        self.assertFalse(self.check('websocket', lambda _: b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fake\r\n\r\n')['healthy'])

    def test_refused_socket_reports_failed_observation(self):
        with patch.object(probe, 'check_one', side_effect=ConnectionRefusedError):
            self.assertEqual(probe.observe({'probes': [{'name': 'down'}]})[0]['healthy'], False)

    def test_header_injection_rejected(self):
        with self.assertRaises(ValueError):
            probe.exchange({'address': '127.0.0.1', 'port': 80, 'protocol': 'http', 'path': '/\r\nInjected: x'})


class ResponseBoundaryTests(unittest.TestCase):
    key = base64.b64encode(b'a' * 16).decode()
    accept = base64.b64encode(hashlib.sha1(
        (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()

    def exchange(self, response, protocol='http', address='127.0.0.1', fragment=2048):
        stream = io.BytesIO(response)
        client = MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = lambda size: stream.read(min(size, fragment))
        with patch.object(probe.socket, 'create_connection', return_value=client), patch.object(probe.os, 'urandom', return_value=b'a' * 16):
            result = probe.exchange({'address': address, 'port': 80, 'protocol': protocol})
        return result, client

    def websocket(self, headers=None, version='HTTP/1.1'):
        if headers is None:
            headers = ['Upgrade: websocket', 'Connection: Upgrade', 'Sec-WebSocket-Accept: ' + self.accept]
        return (version + ' 101 Switching Protocols\r\n' + '\r\n'.join(headers) + '\r\n\r\n').encode()

    def test_malformed_status_lines_and_headers_are_rejected(self):
        for response in [b'garbage 200\r\n\r\n', b'HTTP/1.1 20 OK\r\n\r\n',
                         b'HTTP/2.0 200 OK\r\n\r\n', b'HTTP/1.1 600 Invalid\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nmissing-colon\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nX-Value: bad\x00value\r\n\r\n']:
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.exchange(response)

    def test_websocket_requires_all_upgrade_headers_and_unambiguous_accept(self):
        valid = ['Upgrade: websocket', 'Connection: Upgrade', 'Sec-WebSocket-Accept: ' + self.accept]
        cases = [valid[:i] + valid[i + 1:] for i in range(3)]
        cases += [['Upgrade: h2c', *valid[1:]], [valid[0], 'Connection: keep-alive', valid[2]],
                  [*valid, 'Sec-WebSocket-Accept: ' + self.accept],
                  [*valid, 'Sec-WebSocket-Accept: wrong'],
                  [*valid, 'Sec-WebSocket-Extensions: permessage-deflate'],
                  [*valid, 'Sec-WebSocket-Protocol: unrequested']]
        for headers in cases:
            with self.subTest(headers=headers):
                self.assertFalse(self.exchange(self.websocket(headers), 'websocket')[0]['healthy'])
        self.assertFalse(self.exchange(self.websocket(version='HTTP/1.0'), 'websocket')[0]['healthy'])

    def test_header_case_connection_tokens_and_fragmented_responses(self):
        response = self.websocket(['uPgRaDe: WebSocket', 'Connection: keep-alive',
                                   'cOnNeCtIoN: uPgRaDe', 'Sec-WebSocket-Accept: ' + self.accept])
        for fragment in (1, 2, 7, 2048):
            with self.subTest(fragment=fragment):
                self.assertTrue(self.exchange(response, 'websocket', fragment=fragment)[0]['healthy'])
        self.assertTrue(self.exchange(b'HTTP/1.0 200 OK\r\n\r\n')[0]['healthy'])

    def test_header_size_limit_and_eof_are_enforced(self):
        prefix = b'HTTP/1.1 200 OK\r\nX-Pad: '
        bounded = prefix + b'x' * (16384 - len(prefix) - 4) + b'\r\n\r\n'
        self.assertTrue(self.exchange(bounded)[0]['healthy'])
        for response in (bounded[:-4] + b'x\r\n\r\n', b'HTTP/1.1 200 OK\r\n', b''):
            with self.subTest(length=len(response)), self.assertRaises(ValueError):
                self.exchange(response)

    def test_ipv6_host_authority_is_bracketed(self):
        result, client = self.exchange(b'HTTP/1.1 200 OK\r\n\r\n', address='::1')
        self.assertTrue(result['healthy'])
        self.assertIn(b'Host: [::1]:80\r\n', client.sendall.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
