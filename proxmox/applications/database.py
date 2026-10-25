#!/usr/bin/env python3
"""Restore one new native database; a failed attempt leaves a persistent hold."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

from restore import digest, restore, sync_directory
from pg_clean import restore_clean

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
        if not re.fullmatch(r'2\.[0-8]\.[0-9]+', cfg.get('source_version', '')):
            raise ValueError('This restore path requires a matching pre-2.9 InfluxDB v2 capture')
        return [['influx', 'restore', '--full', str(ROOT / 'influx-backup')]], 'influxdb'
    raise ValueError('Choose a native MariaDB, PostgreSQL or InfluxDB guest')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not forward setup credentials away from the local selected service."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def influx_request(method, path, payload=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://127.0.0.1:8086' + path, method=method,
                                     data=None if payload is None else json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=5) as response:
        return json.load(response)


def setup_influx(cfg, request=influx_request):
    """The HTTP setup API avoids unsupported CLI env vars and password argv."""
    for attempt in range(30):
        try:
            status = request('GET', '/api/v2/setup')
            break
        except urllib.error.URLError:
            if attempt == 29:
                raise
            time.sleep(1)
    if status.get('allowed') is not True:
        raise ValueError('Influx target is already initialised; do not overwrite it')
    request('POST', '/api/v2/setup', {'username': cfg['influx_username'], 'password': cfg['influx_password'],
                                    'org': cfg['influx_org'], 'bucket': cfg['influx_bucket'],
                                    'token': cfg['influx_operator_token']})


def run(cfg, root=ROOT):
    if not cfg.get('exclusive_writer_confirmed'):
        raise ValueError('Starting the new database requires the selected exclusive-writer/cutover decision')
    restore_commands, service = commands(cfg)
    if cfg['kind'] == 'postgresql' and cfg['capture']['format'] != 'pg-dumpall-clean':
        raise ValueError('Use the existing selected clean pg_dumpall restore contract')
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
    sync_directory(root)
    environment = os.environ.copy()
    environment.update({'INFLUX_HOST': 'http://127.0.0.1:8086'})
    if cfg['kind'] == 'influxdb':
        environment.update({'INFLUX_TOKEN': cfg['influx_operator_token'], 'INFLUX_ORG': cfg['influx_org']})
    subprocess.run(['systemctl', 'start', service], check=True, stdout=subprocess.DEVNULL)
    if cfg['kind'] == 'influxdb':
        setup_influx(cfg)
    if cfg['kind'] == 'postgresql':
        restore_clean(capture, root)
    for command in ([] if cfg['kind'] == 'postgresql' else restore_commands):
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
    sync_directory(root)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run only inside the selected new guest as root')
    try:
        print(json.dumps({'restored': run(json.loads(args.config.read_text()))}))
    except (ValueError, OSError, subprocess.CalledProcessError):
        raise SystemExit('Native restore held; preserve private receipts and inspect the selected guest') from None


if __name__ == '__main__':
    main()
