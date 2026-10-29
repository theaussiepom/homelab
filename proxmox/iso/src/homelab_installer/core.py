"""Current media validation, bounded file I/O and exact device identity primitives."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

ISO_SHA256 = "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c"
# Reviewed public artifact identities; the operational receipts remain private.
ASSISTANT_SHA256 = "19c786bf633e9c10631932cc8bcf1920153776995a25002c5c2fa818e405183e"
RUNTIME_SHA256 = "e0c76415d3511ad018c0949c7a9e5df4a5e1751ba729a37472264904c971b03e"
PUBLIC_ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{64}\Z")
DEV = re.compile(r"/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class Refusal(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file(
    path: Path, *, protected: bool = False, limit: int = 4 * 1024**2
) -> bytes:
    # Final-component symlinks and nonregular files never supply an input.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "input must be a regular file")
        require(before.st_size <= limit, "input exceeds size limit")
        if protected:
            require(
                before.st_mode & 0o077 == 0,
                "protected input has group/other permissions",
            )
            require(before.st_uid == os.geteuid(), "protected input has another owner")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        after = os.fstat(fd)
        require(len(data) <= limit, "input exceeds size limit")
        require(
            (before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns),
            "input changed while reading",
        )
        return data
    finally:
        os.close(fd)


def decode_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    value = json.loads(
        data,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON value")),
    )
    require(type(value) is dict, "JSON root must be an object")
    return value


def exact(value: object, fields: set[str], label: str) -> dict:
    require(
        type(value) is dict and set(value) == fields,
        f"{label}: missing or unsupported fields",
    )
    return value


def integer(value, lower: int, upper: int, label: str) -> int:
    require(type(value) is int and lower <= value <= upper, f"{label}: invalid integer")
    return value


def literal(value, label: str, pattern=r"[A-Za-z0-9_.:+/-]{1,160}") -> str:
    require(
        type(value) is str and re.fullmatch(pattern, value) is not None,
        f"{label}: empty, nonliteral or unsupported value",
    )
    return value


def digest(value, label: str) -> str:
    require(
        type(value) is str and SHA.fullmatch(value) is not None and value != "0" * 64,
        f"{label}: missing digest",
    )
    return value


def identifier(value, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
        require(
            parsed.int != 0 and str(parsed) == value.lower(), f"{label}: invalid UUID"
        )
    except (ValueError, TypeError, AttributeError):
        raise Refusal(f"{label}: invalid UUID") from None
    return str(parsed)


def timestamp(value: str) -> datetime:
    try:
        require(
            type(value) is str and value.endswith("Z"), "timestamp must be UTC with Z"
        )
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise Refusal("invalid UTC timestamp") from None
    return result


def stamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def ssh_key(value: str) -> str:
    require(type(value) is str, "public key must be a string")
    parts = value.split()
    require(
        len(parts) in (2, 3) and parts[0] == "ssh-ed25519",
        "only Ed25519 public keys are accepted",
    )
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError):
        raise Refusal("invalid public key encoding") from None
    require(
        len(raw) == 51 and raw[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
        "invalid Ed25519 public key structure",
    )
    return " ".join(parts[:2])


def new_file(path: Path, data: bytes) -> None:
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as f:
        f.write(data)
