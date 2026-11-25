"""Apply only declared native OIDC settings, with protected retry-safe success evidence."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from private_io import digest, encoded, read_json, regular, replace_receipt, require
import pegaprox_oidc_client as client


def files(app, values):
    configuration = {key: app['authentication_resolved'][key] for key in ('settings', 'oidc_endpoints')}
    if 'discovery_check' in app['authentication_resolved']:
        configuration['discovery_check'] = app['authentication_resolved']['discovery_check']
    for role in ('client_secret', 'management_token'):
        configuration[role] = values[role].decode('utf-8')
    client.validate(configuration)
    return [{'path': 'pegaprox-oidc.json', 'content': encoded(configuration),
             'uid': 0, 'gid': 0, 'mode': '0600'}]


def reconcile(config, compose, service):
    require(config.is_absolute() and config.name == 'pegaprox-oidc.json'
            and '..' not in config.parts and compose.is_absolute() and '..' not in compose.parts
            and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', service), client.ERROR)
    configuration = client.validate(read_json(config, private=True))
    receipt = config.with_name('pegaprox-oidc-applied.json')
    identity = {'compose': str(compose), 'service': service, 'configuration': str(config)}
    record = {'identity': identity, 'sha256': digest(encoded(configuration))}
    previous = None
    if receipt.exists() or receipt.is_symlink():
        previous = read_json(receipt, private=True)
        require(isinstance(previous, dict) and set(previous) == {'identity', 'sha256'}
                and previous['identity'] == identity and isinstance(previous['sha256'], str)
                and re.fullmatch('[0-9a-f]{64}', previous['sha256']), client.ERROR)
    # Static helper code is installed with this module. Private values travel only on stdin.
    code = regular(Path(__file__).with_name('pegaprox_oidc_client.py'), modes=(0o700,)).decode()
    result = subprocess.run(['docker', 'compose', '-f', str(compose), 'exec', '-T', service,
                             'python3', '-c', code],
        input=encoded({'configuration': configuration, 'applied': previous == record}),
        capture_output=True, timeout=100, check=False)
    require(result.returncode == 0, client.ERROR)
    status = json.loads(result.stdout)
    require(isinstance(status, dict) and set(status) == {'changed'} and type(status['changed']) is bool, client.ERROR)
    if previous != record:
        replace_receipt(receipt, record)
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--compose', required=True, type=Path)
    parser.add_argument('--service', required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(reconcile(args.config, args.compose, args.service)))
    except Exception:
        print(client.ERROR, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
