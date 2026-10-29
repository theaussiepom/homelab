"""Read-only application probes; never publish MQTT or log private credentials."""
import argparse
import json
from pathlib import Path
import socket
import struct
import time
from urllib.error import HTTPError
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Local service probes must not follow a redirect')


def text(value):
    if not isinstance(value, str):
        raise ValueError('Missing retained MQTT credential')
    raw = value.encode('utf-8')
    if not raw or len(raw) > 65535:
        raise ValueError('Missing or oversized retained MQTT credential')
    return struct.pack('!H', len(raw)) + raw


def connect(username=None, password=None):
    payload = text('homelab-cd-' + str(time.time_ns()))
    flags = 2
    if username is not None:
        flags |= 0xC0
        payload += text(username) + text(password)
    body = b'\x00\x04MQTT\x04' + bytes([flags]) + b'\x00\x0a' + payload
    length = len(body); encoded = bytearray()
    while True:
        digit = length % 128; length //= 128
        encoded.append(digit | (128 if length else 0))
        if not length:
            break
    with socket.create_connection(('127.0.0.1', 1883), timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(b'\x10' + encoded + body)
        reply = b''
        while len(reply) < 4:
            part = stream.recv(4 - len(reply))
            if not part:
                raise ValueError('The broker closed without a complete CONNACK')
            reply += part
        if reply[:3] != b'\x20\x02\x00':
            raise ValueError('Unexpected broker acknowledgement')
        if reply[3] == 0:
            stream.sendall(b'\xe0\x00')
        return reply[3]


def mqtt(path=Path('/srv/homelab/data/homeassistant/config/.storage/core.config_entries')):
    entries = json.loads(path.read_text())['data']['entries']
    selected = [row['data'] for row in entries if row['domain'] == 'mqtt']
    if len(selected) != 1:
        raise ValueError('Restore the selected existing MQTT integration')
    credentials = selected[0]
    if connect(credentials.get('username'), credentials.get('password')) != 0:
        raise ValueError('The retained MQTT account cannot authenticate')
    if connect() not in (4, 5):
        raise ValueError('The broker did not reject anonymous access')


def http(port, path):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(f'http://127.0.0.1:{port}{path}', timeout=5) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError('Local service probe response exceeds its bound')
            return response.status, body
    except HTTPError as response:
        return response.code, b''


def probe(service):
    if service == 'mqtt':
        mqtt()
    elif service == 'homeassistant':
        if http(8123, '/')[0] != 200 or http(8123, '/api/')[0] != 401:
            raise ValueError('HA web/API login boundary is not ready')
    elif service == 'node_red':
        status, body = http(1880, '/auth/login')
        if status != 200 or json.loads(body).get('type') != 'strategy' or http(1880, '/flows')[0] != 401:
            raise ValueError('Node-RED native strategy or API login boundary differs')
    else:
        raise ValueError('Select one automation service')


def run(service):
    deadline = time.monotonic() + 180
    while True:
        try:
            probe(service)
            return {'service': service, 'read_only_probe': 'passed'}
        except (OSError, ValueError, KeyError, TypeError):
            if time.monotonic() >= deadline:
                raise ValueError('Application probe did not pass; inspect its private logs') from None
            time.sleep(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service', choices=('mqtt', 'homeassistant', 'node_red'))
    try:
        print(json.dumps(run(parser.parse_args().service)))
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Automation service verification held; private values were not printed') from None
