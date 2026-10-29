"""Owned DNS records and read-only checks of the selected local resolver."""

import ipaddress
import json
from pathlib import Path
import re
import socket
import struct
import subprocess


def validate(records):
    if not isinstance(records, dict):
        raise ValueError("Declare a hostname to IPv4 record map")
    for name, address in records.items():
        if (
            not isinstance(name, str)
            or len(name) > 253
            or "." not in name
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in name.split(".")
            )
        ):
            raise ValueError("Use literal DNS hostnames")
        ip = ipaddress.IPv4Address(address)
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
            raise ValueError("Use a usable service IPv4 address")
    return records


def desired_hosts(existing, records):
    """Replace only owned hostnames, preserving unrelated aliases and addresses."""
    validate(records)
    if not isinstance(existing, list) or not all(
        isinstance(row, str) for row in existing
    ):
        raise ValueError("Read the current Pi-hole host array before reconciliation")
    result = []
    for row in existing:
        fields = row.split()
        if len(fields) < 2:
            raise ValueError("Expected literal Pi-hole address and hostname entries")
        ipaddress.ip_address(fields[0])
        retained = [
            name for name in fields[1:] if name.rstrip(".").lower() not in records
        ]
        if len(retained) == len(fields) - 1:
            result.append(row)
        elif retained:
            result.append(fields[0] + " " + " ".join(retained))
    return result + [address + " " + name for name, address in sorted(records.items())]


def reconcile(records, compose):
    validate(records)
    command = [
        "docker",
        "compose",
        "-f",
        str(compose),
        "exec",
        "-T",
        "pihole",
        "pihole-FTL",
        "--config",
        "dns.hosts",
    ]

    def current():
        value = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=30
        ).stdout.strip()
        if (
            not value.startswith("[")
            or not value.endswith("]")
            or len(value) > 1024 * 1024
        ):
            raise ValueError("Unexpected Pi-hole host configuration readback")
        rows = value[1:-1].strip()
        return [row.strip() for row in rows.split(",")] if rows else []

    before = current()
    after = desired_hosts(before, records)
    if before == after:
        return False
    subprocess.run(
        [*command, json.dumps(after)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if current() != after:
        raise ValueError("Pi-hole did not retain the exact desired host records")
    return True


def probe(name, address):
    """Query Pi-hole directly; fallback DNS cannot hide a missing managed record."""
    validate({name: address})
    question = (
        b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\0\0\1\0\1"
    )
    query = struct.pack("!6H", 0x4D51, 0x100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.connect(("127.0.0.1", 53))
        client.send(query)
        response = client.recv(8192)
    identity, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
    if (
        identity != 0x4D51
        or flags & 0x820F != 0x8000
        or questions != 1
        or not 1 <= answers <= 64
        or response[12 : 12 + len(question)] != question
    ):
        raise ValueError("DNS response does not answer the selected service question")
    offset = 12 + len(question)
    found = set()
    for _ in range(answers):
        if response[offset : offset + 2] != b"\xc0\x0c":
            raise ValueError("Require direct answers for the selected service hostname")
        kind, record_class, _, length = struct.unpack(
            "!HHIH", response[offset + 2 : offset + 12]
        )
        offset += 12
        value = response[offset : offset + length]
        if len(value) != length:
            raise ValueError("Truncated DNS answer")
        if kind == record_class == 1 and length == 4:
            found.add(socket.inet_ntoa(value))
        offset += length
    if found != {address}:
        raise ValueError("DNS answers differ from the declared service address")
    return {"read_only_dns_check": "passed"}


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    query = commands.add_parser("probe")
    query.add_argument("hostname")
    query.add_argument("address")
    update = commands.add_parser("reconcile")
    update.add_argument("--records", type=Path, required=True)
    update.add_argument("--compose", type=Path, required=True)
    args = parser.parse_args()
    result = (
        probe(args.hostname, args.address)
        if args.operation == "probe"
        else {"changed": reconcile(json.loads(args.records.read_bytes()), args.compose)}
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
