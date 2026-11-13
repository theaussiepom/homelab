"""Bounded private SSH transfer for native guest-key custody; no command/log output."""
import os
import selectors
import subprocess
import time

import backup_controller
from private_io import encoded, require


def fetch(cfg, identity, *, create, launch=subprocess.Popen):
    require(type(create) is bool, 'Select explicit native key creation or readback')
    argv = backup_controller.command(cfg)
    argv[-1] = '/usr/bin/python3 /opt/homelab-backup/backup_client_key.py'
    process = launch(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH':'/usr/bin:/bin', 'HOME':'/nonexistent'}, start_new_session=True, bufsize=0)
    raw = bytearray(); deadline = time.monotonic() + 90
    try:
        process.stdin.write(encoded({'action':'create' if create else 'read', 'identity':identity}))
        process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'Native client-key transfer timed out; preserve enrollment')
                ready = selected.select(remaining)
                require(bool(ready), 'Native client-key transfer timed out; preserve enrollment')
                chunk = os.read(process.stdout.fileno(), 16385-len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= 16384, 'Oversized native client-key transfer; preserve enrollment')
        require(process.wait(timeout=max(0.01, deadline-time.monotonic())) == 0 and raw,
                'Native client-key transfer failed; preserve enrollment')
        return bytes(raw)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
