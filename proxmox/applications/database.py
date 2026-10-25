#!/usr/bin/env python3
"""Restore one new native database; a failed attempt leaves a persistent hold."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from restore import digest, restore

ROOT = Path('/opt/homelab-app')


def commands(cfg):
    """No shell, no password in process arguments; native DBs have separate users."""
    kind = cfg['kind']
    if kind == 'mariadb':
        return [['mariadb', '--protocol=socket', '--user=root', '--binary-mode']], 'mariadb'
    if kind == 'postgresql':
        if cfg['user'] != 'postgres':
            raise ValueError('PostgreSQL peer restore requires its postgres OS account')
        return [['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '--dbname=postgres']], 'postgresql'
    if kind == 'influxdb':
        # Token values are passed through the environment, never argv or stdout.
        required = ['influx_operator_token', 'influx_username', 'influx_password', 'influx_org', 'influx_bucket']
        if not all(isinstance(cfg.get(k), str) and cfg[k] for k in required):
            raise ValueError('Influx requires the original operator token and private setup inputs')
        return [['influx', 'setup', '--force'], ['influx', 'restore', '--full', str(ROOT / 'influx-backup')]], 'influxdb'
    raise ValueError('Choose a native MariaDB, PostgreSQL or InfluxDB guest')


def run(cfg, root=ROOT):
    if not cfg.get('exclusive_writer_confirmed'):
        raise ValueError('Starting the new database requires the selected exclusive-writer/cutover decision')
    restore_commands, service = commands(cfg)
    capture = root / 'database.capture'
    checksum = digest(capture)
    if checksum != cfg['capture']['sha256']:
        raise ValueError('Database capture checksum changed')
    receipt = root / 'database-restore.json'
    complete = {'state': 'complete', 'kind': cfg['kind'], 'sha256': checksum}
    if receipt.exists():
        if json.loads(receipt.read_text()) == complete:
            return False
        raise ValueError('Preserve the incomplete database restore; do not replay automatically')
    if cfg['kind'] == 'influxdb':
        restore(capture, root / 'influx-backup', root / 'influx-extract.json', checksum)
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'state': 'started', 'kind': cfg['kind'], 'sha256': checksum}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    environment = os.environ.copy()
    environment.update({'INFLUX_HOST': 'http://127.0.0.1:8086'})
    if cfg['kind'] == 'influxdb':
        environment.update({'INFLUX_TOKEN': cfg['influx_operator_token'],
                            'INFLUX_USERNAME': cfg['influx_username'], 'INFLUX_PASSWORD': cfg['influx_password'],
                            'INFLUX_ORG': cfg['influx_org'], 'INFLUX_BUCKET_NAME': cfg['influx_bucket']})
    subprocess.run(['systemctl', 'start', service], check=True, stdout=subprocess.DEVNULL)
    for command in restore_commands:
        with capture.open('rb') as stream:
            # SQL goes to stdin; Influx reads the checked native backup directory.
            subprocess.run(command, stdin=stream if cfg['kind'] != 'influxdb' else subprocess.DEVNULL,
                           env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'enable', service], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    complete_path = receipt.with_suffix('.complete')
    fd = os.open(complete_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(complete, stream)
        stream.flush()
        os.fsync(stream.fileno())
    complete_path.replace(receipt)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run only inside the selected new guest as root')
    try:
        print(json.dumps({'restored': run(json.loads(args.config.read_text()))}))
    except (ValueError, subprocess.CalledProcessError):
        raise SystemExit('Native restore held; preserve private receipts and inspect the selected guest') from None


if __name__ == '__main__':
    main()
