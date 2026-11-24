"""Verify DNS source binding and failure behavior without a real network."""
import importlib.util
import runpy
import socket
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / 'ansible/files/pbs-dns-check.py'
SPEC = importlib.util.spec_from_file_location('pbs_dns_check', SCRIPT)
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)
SOURCE = '198.18.25.3'
SERVERS = ['198.18.25.11', '198.18.25.12']
RESOLV = 'search internal\n# nameserver 198.18.25.1\nnameserver 198.18.25.11 # primary\n' + (
    'nameserver 198.18.25.12\n')


def test_declared_resolvers_are_checked_on_each_transport_and_by_the_os():
    with (patch.object(DNS.Path, 'read_text', return_value=RESOLV),
          patch.object(DNS, 'query') as query,
          patch.object(DNS.socket, 'getaddrinfo', return_value=[('resolved',)]) as native):
        DNS.verify(SOURCE, SERVERS)
    assert query.call_args_list == [call(SOURCE, server, transport) for server in SERVERS
                                   for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM)]
    native.assert_called_once_with('deb.debian.org', 443, socket.AF_INET, socket.SOCK_STREAM)
    with (patch.object(DNS.Path, 'read_text', return_value='nameserver 198.18.25.1\n'),
          patch.object(DNS, 'query') as unchecked, pytest.raises(ValueError, match='differs')):
        DNS.verify(SOURCE, SERVERS)
    unchecked.assert_not_called()
    with (patch.object(DNS.Path, 'read_text', return_value=RESOLV), patch.object(DNS, 'query'),
          patch.object(DNS.socket, 'getaddrinfo', return_value=[]), pytest.raises(ValueError, match='no addresses')):
        DNS.verify(SOURCE, SERVERS)


def make_client(packets):
    transport = MagicMock()
    transport.__enter__.return_value = transport
    transport.recv.side_effect = packets
    return transport


@pytest.mark.parametrize('transport', [socket.SOCK_DGRAM, socket.SOCK_STREAM])
def test_dns_wire_checks_bind_to_the_management_address(transport):
    answer = struct.pack('!HHHHHH', 42, 0x8180, 1, 1, 0, 0)
    if transport == socket.SOCK_DGRAM:
        packets = [answer]
    else:
        packets = [b'\x00', b'\x0c', answer[:5], answer[5:]]
    client = make_client(packets)
    with (patch.object(DNS.secrets, 'randbits', return_value=42),
          patch.object(DNS.socket, 'socket', return_value=client)):
        DNS.query(SOURCE, SERVERS[0], transport)
    client.bind.assert_called_once_with((SOURCE, 0))
    client.connect.assert_called_once_with((SERVERS[0], 53))


@pytest.mark.parametrize(('transport', 'packets', 'failure'), [
    (socket.SOCK_STREAM, [b''], 'Short DNS'),
    (socket.SOCK_STREAM, [b'\x00\x01'], 'Invalid DNS frame'),
    (socket.SOCK_DGRAM, [struct.pack('!HHHH', 42, 0x8183, 1, 0)], 'Unsuccessful DNS'),
])
def test_malformed_dns_replies_stop_verification(transport, packets, failure):
    with (patch.object(DNS.secrets, 'randbits', return_value=42),
          patch.object(DNS.socket, 'socket', return_value=make_client(packets)),
          pytest.raises(ValueError, match=failure)):
        DNS.query(SOURCE, SERVERS[0], transport)


def test_script_reports_sanitized_result(capsys):
    def client(*args):
        answer = struct.pack('!HHHHHH', 42, 0x8180, 1, 1, 0, 0)
        packets = [answer] if args[1] == socket.SOCK_DGRAM else [b'\x00\x0c', answer]
        return make_client(packets)

    with (patch.object(sys, 'argv', [str(SCRIPT), SOURCE, *SERVERS]),
          patch.object(Path, 'read_text', return_value=RESOLV),
          patch.object(socket, 'socket', side_effect=client),
          patch.object(DNS.secrets, 'randbits', return_value=42),
          patch.object(socket, 'getaddrinfo', return_value=[('resolved',)])):
        runpy.run_path(str(SCRIPT), run_name='__main__')
    assert 'host resolution verified' in capsys.readouterr().out
    with (patch.object(sys, 'argv', [str(SCRIPT), SOURCE, *SERVERS]),
          patch.object(Path, 'read_text', return_value='internal'),
          pytest.raises(SystemExit, match='PBS configured DNS or Management DNS transport verification failed')):
        runpy.run_path(str(SCRIPT), run_name='__main__')
