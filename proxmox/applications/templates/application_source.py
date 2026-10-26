"""Resolve only a fixed public source commit and a selected private input file."""
import argparse
import json
from pathlib import Path
import re

GUESTS = ('dns', 'mariadb', 'postgresql', 'influxdb', 'identity', 'ingress', 'automation')
STEPS = ('plan', 'deploy', 'apply', 'stage', 'start', 'verify')


def resolve(lock, guest, step, plan_hash=''):
    if lock.get('repository') != 'theaussiepom/homelab' or not re.fullmatch(r'[0-9a-f]{40}', lock.get('revision', '')):
        raise ValueError('Pin the reviewed public homelab commit, never a mutable branch')
    if guest not in GUESTS or step not in STEPS:
        raise ValueError('Select a listed guest and step')
    if step in ('apply', 'deploy') and not re.fullmatch(r'[0-9a-f]{64}', plan_hash):
        raise ValueError('Apply/deploy needs the exact reviewed plan fingerprint')
    return {'revision': lock['revision'], 'input_path': f'/var/lib/homelab-inputs/{guest}.json'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', required=True, choices=GUESTS)
    parser.add_argument('--step', required=True, choices=STEPS)
    parser.add_argument('--plan-sha256', default='')
    args = parser.parse_args()
    result = resolve(json.loads(Path('applications/source.json').read_text()), args.guest, args.step, args.plan_sha256)
    for key, value in result.items():
        print(f'{key}={value}')


if __name__ == '__main__':
    main()
