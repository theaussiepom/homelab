"""Check the declared PBS resolver paths without changing host DNS."""

from pathlib import Path
import secrets
import socket
import struct
import sys


def configured_resolvers(text):
    """Read the resolver directives in order, without exposing other settings."""
    tokens = (line.split('#', 1)[0].split() for line in text.splitlines())
    return [row[1] for row in tokens if len(row) >= 2 and row[0] == 'nameserver']


def exact_read(client, length):
    result = bytearray()
    while len(result) < length:
        chunk = client.recv(length - len(result))
        if not chunk:
            raise ValueError('Short DNS response')
        result.extend(chunk)
    return result


def query(source, server, protocol):
    request_id = secrets.randbits(16)
    # Resolve the root NS record over both transports on each declared server.
    request = struct.pack('!HHHHHHBHH', request_id, 0x0100, 1, 0, 0, 0, 0, 2, 1)
    with socket.socket(socket.AF_INET, protocol) as client:
        client.settimeout(2)
        client.bind((source, 0))
        client.connect((server, 53))
        if protocol == socket.SOCK_DGRAM:
            client.sendall(request)
            response = client.recv(4096)
        else:
            client.sendall(struct.pack('!H', len(request)) + request)
            length, = struct.unpack('!H', exact_read(client, 2))
            if not 12 <= length <= 4096:
                raise ValueError('Invalid DNS frame')
            response = exact_read(client, length)
    received_id, flags, _, answers = struct.unpack_from('!HHHH', response)
    if received_id != request_id or flags & 0x820F != 0x8000 or answers == 0:
        raise ValueError('Unsuccessful DNS response')


def verify(source, expected):
    if configured_resolvers(Path('/etc/resolv.conf').read_text()) != expected:
        raise ValueError('Configured resolver list differs')
    for server in expected:
        for protocol in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            query(source, server, protocol)
    if not socket.getaddrinfo('deb.debian.org', 443, socket.AF_INET, socket.SOCK_STREAM):
        raise ValueError('System resolver returned no addresses')


if __name__ == '__main__':
    try:
        verify(sys.argv[1], sys.argv[2:])
    except (OSError, ValueError, struct.error):
        raise SystemExit('PBS configured DNS or Management DNS transport verification failed') from None
    print('PBS configured resolvers, Management DNS transport and host resolution verified')
