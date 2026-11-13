#!/usr/bin/env python3
"""Prompt privately and save only a SHA512crypt hash to the local input file."""
import getpass
import os
from pathlib import Path
import subprocess


def save_hash(path):
    if path.exists():
        raise SystemExit(
            "A password hash already exists. Review it; this command will not overwrite it."
        )
    first = getpass.getpass("Recovery password (save it in your password manager): ")
    second = getpass.getpass("Repeat the recovery password: ")
    if len(first) < 20 or first != second:
        raise SystemExit(
            "Use at least 20 characters and enter the same password twice."
        )
    result = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=first.encode() + b"\n",
        check=True,
        capture_output=True,
    )
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(fd, "wb") as target:
        target.write(result.stdout)
    print("Saved only the password hash in .local/root-recovery-password.hash.")


if __name__ == "__main__":
    save_hash(Path("/work/.local/root-recovery-password.hash"))
