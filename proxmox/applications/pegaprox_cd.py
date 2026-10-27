#!/usr/bin/env python3
"""A clean PegaProx profile for the existing foundation CD protocol."""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile

import foundation_cd as shared
import pegaprox

SCHEMA = 'homelab-pegaprox-cd-v1'
HOLD_NAME = 'PEGAPROX-HOLD.json'
COMPLETE_NAME = 'pegaprox-complete.json'
BOOTSTRAP_SECRET = 'PEGAPROX_ADMIN_PASSWORD'


def runtime_secrets():
    """The bootstrap password never belongs to the permanent runtime inputs."""
    return {'db-key': 'PEGAPROX_DB_KEY'}


def check_bootstrap_password(value):
    shared.require(isinstance(value, str) and 8 <= len(value) <= 128
                   and not any(c in value for c in '\r\n\x00')
                   and any(c.isupper() for c in value) and any(c.islower() for c in value)
                   and any(c.isdigit() for c in value), 'Missing or invalid initial administrator secret')


def admit(value):
    shared.require(value.get('enabled') is True, 'PegaProx CD is disabled')
    shared.require(set(value) == {'schema', 'enabled', 'clean_install_confirmed', 'site_config'}
                   and value['schema'] == SCHEMA and value['clean_install_confirmed'] is True,
                   'Review the closed PegaProx clean-install selection before deployment')
    return copy.deepcopy(value['site_config'])


def bindings(bundles):
    value = json.loads(shared.regular(bundles / 'bindings.json'))
    shared.require(set(value) == {'site', 'guests'} and set(value['guests']) == {'pegaprox'},
                   'Select exactly one PegaProx guest')
    row = value['guests']['pegaprox']
    shared.require(isinstance(row, list) and len(row) == 2 and type(row[0]) is int
                   and row[0] >= 100 and row[0] not in {900, 4914, 4915, 4920}
                   and isinstance(row[1], str), 'Invalid PegaProx identity')
    return value['guests'], value['site']


def definition(name, bundles, inputs, state):
    guests, host = bindings(bundles)
    shared.require(name == 'pegaprox', 'Select the PegaProx profile')
    directory = bundles / name
    shared.require(directory.is_dir() and not directory.is_symlink()
                   and {p.name for p in directory.iterdir()} == {'site.json', 'stack.json'},
                   'Select exactly the PegaProx site and stack')
    files = {key: shared.regular(directory / key) for key in ('site.json', 'stack.json')}
    cfg, stack = json.loads(files['site.json']), json.loads(files['stack.json'])
    destination, work = inputs / 'pegaprox', state / str(guests[name][0])
    shared.require(cfg['site'] == host and cfg['guest']['vmid'] == cfg['app']['vmid'] == guests[name][0]
                   and cfg['guest']['hostname'] == cfg['app']['hostname'] == guests[name][1]
                   and cfg['app']['kind'] == stack['kind'] == name
                   and cfg['app']['clean_install_confirmed'] is True
                   and cfg['app']['stack_config'] == str(destination / 'stack.json')
                   and cfg['app']['pegaprox']['key_source'] == str(destination / 'db-key')
                   and cfg['paths']['state_root'] == str(state), 'PegaProx identity or fixed input path differs')
    pegaprox.validate_deployment(cfg, stack=stack)
    return cfg, stack, files, destination, work


def prepare(name, deployment, bundles, inputs, state, provider=None, environment=None):
    cfg, stack, files, directory, work = definition(name, bundles, inputs, state)
    environment = os.environ if environment is None else environment
    shared.private_directory(inputs)
    shared.require(not any((work / marker).exists() or (work / marker).is_symlink()
                           for marker in (*shared.HOLDS, HOLD_NAME, HOLD_NAME + '.pending')),
                   'Preserve the failed PegaProx rollout; no automatic retry')
    completed = (work / COMPLETE_NAME).exists() or (work / COMPLETE_NAME).is_symlink()
    if not completed:
        shared.require(not any((work / name).exists() or (work / name).is_symlink() for name in
                               ('applied.json', 'started.json', 'rollout-complete.json', 'terraform.tfstate',
                                'plan.json', 'guest.tfplan', 'guest.tfplan.json')),
                       'Existing PegaProx phase evidence needs review; no adoption or continuation')
        check_bootstrap_password(environment.get(BOOTSTRAP_SECRET))
    # This key is permanent. Repeats may read the retained input without a GitHub
    # secret; a supplied differing value is drift, never an automatic rotation.
    supplied = environment.get('PEGAPROX_DB_KEY')
    if directory.exists() or directory.is_symlink():
        shared.private_directory(directory)
        key = shared.regular(directory / 'db-key', private=True)
        if supplied:
            shared.require(key == supplied.encode(), 'Database-key drift requires separate review')
    else:
        shared.require(isinstance(supplied, str), 'Supply the separate database-key secret')
        key = supplied.encode()
    try:
        shared.require(len(base64.b64decode(key, altchars=b'-_', validate=True)) == 32,
                       'Use a base64-encoded 32-byte database key')
    except (ValueError, TypeError):
        raise ValueError('Invalid database-key secret') from None
    files['db-key'] = key
    manifest = {'schema': SCHEMA, 'guest': name,
                'policy': {'vmid': cfg['guest']['vmid'], 'policy': 'merge-create-only-v1'},
                'files': {key: shared.digest(value) for key, value in files.items()}}
    if directory.exists():
        shared.require({p.name for p in directory.iterdir()} == set(files) | {'prepared.json'}
                       and shared.regular(directory / 'prepared.json', private=True) == shared.encoded(manifest)
                       and all(shared.regular(directory / key, private=True) == value for key, value in files.items()),
                       'Existing PegaProx inputs changed; preserve them for review')
    else:
        shared.private_directory(directory, create=True)
        for key, value in files.items():
            shared.write_new(directory / key, value)
        deployment.validate(cfg)
        shared.write_new(directory / 'prepared.json', shared.encoded(manifest))
    deployment.validate(cfg)
    return cfg, directory / 'site.json', work, manifest


def run(deployment, bundles, inputs=shared.INPUTS, state=shared.STATE, environment=None):
    """Reuse the existing one-plan, create-only, verify-repeat and failure-hold code."""
    return shared.run('pegaprox', deployment, bundles, inputs, state, environment=environment,
                      profile=sys.modules[__name__])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        cfg = admit(json.loads(shared.regular(args.config)))
        stack = json.loads(shared.regular(args.config.parent / 'stack.json'))
        import deploy
        with tempfile.TemporaryDirectory(prefix='homelab-pegaprox-') as tmp:
            bundles = Path(tmp); directory = bundles / 'pegaprox'; directory.mkdir(mode=0o700)
            shared.write_new(directory / 'site.json', shared.encoded(cfg))
            shared.write_new(directory / 'stack.json', shared.encoded(stack))
            shared.write_new(bundles / 'bindings.json', shared.encoded({'site': cfg['site'],
                'guests': {'pegaprox': [cfg['guest']['vmid'], cfg['guest']['hostname']]}}))
            print(json.dumps(run(deploy, bundles)))
    except Exception:
        raise SystemExit('PegaProx CD stopped; inspect its private inputs and holds. No automatic replay.') from None


if __name__ == '__main__':
    main()
