"""Read-only application probes; never publish MQTT or log private credentials."""
import argparse
import base64
import hashlib
from http.client import HTTPConnection, HTTPException
import json
import ipaddress
import os
from pathlib import Path
import re
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


def mqtt(path=Path('/srv/homelab/data/homeassistant/config/.storage/core.config_entries'), *, standalone=False):
    value = json.loads(path.read_text())
    if standalone:
        if not isinstance(value, dict) or set(value) != {'username', 'password'}:
            raise ValueError('Use only the retained broker probe account')
        credentials = value
    else:
        entries = value['data']['entries']
        selected = [row['data'] for row in entries if row['domain'] == 'mqtt']
        if len(selected) != 1:
            raise ValueError('Restore the selected existing MQTT integration')
        credentials = selected[0]
    if connect(credentials.get('username'), credentials.get('password')) != 0:
        raise ValueError('The retained MQTT account cannot authenticate')
    if connect() not in (4, 5):
        raise ValueError('The broker did not reject anonymous access')


def http(port, path, address='127.0.0.1'):
    """Probe one bounded local HTTP response without a proxy or redirects."""
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(f'http://{address}:{port}{path}', timeout=5) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError('Local service probe response exceeds its bound')
            return response.status, body
    except HTTPError as response:
        return response.code, b''


def homeassistant_auth_challenge():
    """Check the API's initial challenge without submitting a failed login."""
    key = base64.b64encode(os.urandom(16)).decode('ascii')
    connection = HTTPConnection('127.0.0.1', 8123, timeout=5)
    try:
        connection.request('GET', '/api/websocket', headers={
            'Upgrade': 'websocket', 'Connection': 'Upgrade',
            'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key,
        })
        response = connection.getresponse()
        accept = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii'),
            usedforsecurity=False,
        ).digest()).decode('ascii')
        if (response.status != 101
                or response.getheader('Upgrade', '').lower() != 'websocket'
                or 'upgrade' not in {part.strip().lower() for part in response.getheader('Connection', '').split(',')}
                or response.getheader('Sec-WebSocket-Accept') != accept):
            raise ValueError('HA WebSocket upgrade differs')

        def receive(size):
            data = response.fp.read(size)
            if len(data) != size:
                raise ValueError('Incomplete HA authentication challenge')
            return data

        header = receive(2)
        if header[0] != 0x81 or header[1] & 0x80 or header[1] == 127:
            raise ValueError('Unexpected HA authentication frame')
        size = int.from_bytes(receive(2), 'big') if header[1] == 126 else header[1]
        if size > 4096:
            raise ValueError('HA authentication challenge exceeds its bound')
        challenge = json.loads(receive(size))
        if (not isinstance(challenge, dict) or challenge.get('type') != 'auth_required'
                or not isinstance(challenge.get('ha_version'), str)
                or not challenge['ha_version']):
            raise ValueError('HA API must require authentication')
        mask = os.urandom(4)
        connection.sock.sendall(b'\x88\x82' + mask + bytes(
            value ^ mask[index] for index, value in enumerate(b'\x03\xe8')
        ))
    finally:
        connection.close()


def local_response(path):
    """Inspect one fixed loopback response without following any redirect."""
    if path not in {'/', '/onboarding.html', '/api/'}:
        raise ValueError('Select a fixed fresh HA readiness path')
    connection = HTTPConnection('127.0.0.1', 8123, timeout=5)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        if len(response.read(65537)) > 65536:
            raise ValueError('Local service probe response exceeds its bound')
        return response.status, response.getheader('Location')
    finally:
        connection.close()


def homeassistant_fresh():
    """Qualify vendor onboarding or owned repeat readiness, never follow it."""
    status, location = local_response('/')
    if status == 302 and location == '/onboarding.html':
        if local_response('/onboarding.html') != (200, None):
            raise ValueError('Fresh HA onboarding page is not ready')
    elif status != 200 or location is not None:
        raise ValueError('Fresh HA must use its exact local onboarding boundary')
    if local_response('/api/')[0] != 401:
        raise ValueError('Fresh HA must refuse unauthenticated API access')
    homeassistant_auth_challenge()


def selected_probe(service, mqtt_probe):
    if mqtt_probe is not None and not (service=='mqtt-broker' and isinstance(mqtt_probe,(str,Path))
            and re.fullmatch(r'/opt/homelab-app/runtime(?:/[a-z0-9_-]+)*/mqtt-probe\.json',str(mqtt_probe))):
        raise ValueError('Select only the owned broker probe input')
    return Path('/opt/homelab-app/runtime/mqtt-probe.json') if mqtt_probe is None else Path(mqtt_probe)


def web_address(service, address):
    """Validate the optional concrete address for Node-RED probes only."""
    if address is None:
        return None
    if service not in ('node_red','node_red-fresh'):
        raise ValueError('Select an explicit address only for the Node-RED web probe')
    value=ipaddress.IPv4Address(address)
    if str(value)!=address or value.is_unspecified or value.is_loopback or value.is_multicast or value.is_link_local:
        raise ValueError('Select the assigned Node-RED IPv4 web address')
    return str(value)


def probe(service, mqtt_probe=None, address=None):
    """Check the selected service boundary without submitting login credentials."""
    selected=selected_probe(service,mqtt_probe)
    address=web_address(service,address)
    web_options={} if address is None else {'address':address}
    if service == 'mqtt':
        mqtt()
    elif service == 'mqtt-broker':
        mqtt(selected, standalone=True)
    elif service == 'homeassistant':
        if http(8123, '/')[0] != 200:
            raise ValueError('HA web/API login boundary is not ready')
        homeassistant_auth_challenge()
    elif service == 'homeassistant-fresh':
        homeassistant_fresh()
    elif service == 'node_red':
        status, body = http(1880, '/auth/login',**web_options)
        if status != 200 or json.loads(body).get('type') != 'strategy' or http(1880, '/flows',**web_options)[0] != 401:
            raise ValueError('Node-RED native strategy or API login boundary differs')
    elif service == 'node_red-fresh':
        if http(1880, '/',**web_options)[0] != 200:
            raise ValueError('Fresh Node-RED local UI is not ready')
    else:
        raise ValueError('Select one automation service')


def run(service, mqtt_probe=None, address=None):
    """Retry read-only probes to the fixed deadline, then report or refuse."""
    selected_probe(service,mqtt_probe)
    address=web_address(service,address)
    deadline = time.monotonic() + 180
    while True:
        try:
            if address is not None:
                probe(service,mqtt_probe,address=address)
            elif mqtt_probe is None:
                probe(service)
            else:
                probe(service,mqtt_probe)
            return {'service': service, 'read_only_probe': 'passed',
                    **({'scope': 'ui_only'} if service == 'node_red-fresh' else {})}
        except (OSError, ValueError, KeyError, TypeError, HTTPException):
            if time.monotonic() >= deadline:
                raise ValueError('Application probe did not pass; inspect its private logs') from None
            time.sleep(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service', choices=('mqtt', 'mqtt-broker', 'homeassistant', 'homeassistant-fresh', 'node_red', 'node_red-fresh'))
    parser.add_argument('--mqtt-probe',type=Path)
    parser.add_argument('--address')
    try:
        args=parser.parse_args()
        print(json.dumps(run(args.service,args.mqtt_probe,**({} if args.address is None else {'address':args.address}))))
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Automation service verification held; private values were not printed') from None
