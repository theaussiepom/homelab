"""Deploy one selected new foundation guest; completed runs only verify it."""
import argparse
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

import site_config

KINDS = site_config.KINDS
INPUTS = Path('/var/lib/homelab-inputs')
STATE = Path('/var/lib/homelab-applications')
PROVIDER = Path('/var/lib/homelab-bootstrap/service-discovery/token.json')
SECRETS = {
    'identity': {'secret_key': ('authentik-secret-key', 'AUTHENTIK_SECRET_KEY'),
                 'postgresql_password': ('postgresql-password', 'AUTHENTIK_POSTGRES_PASSWORD'),
                 'smtp_password': ('smtp-password', 'AUTHENTIK_SMTP_PASSWORD')},
    'db-tools': {'oauth_client_secret': ('oauth-client-secret', 'PGADMIN_OAUTH_SECRET')},
    'ingress': {'cloudflare_dns_token': ('cloudflare-dns-token', 'CLOUDFLARE_DNS_TOKEN'),
                'proxmox_token': ('proxmox-token', None)},
}
REQUIRED = {'identity': {'secret_key', 'postgresql_password'}, 'db-tools': {'oauth_client_secret'},
            'ingress': {'cloudflare_dns_token', 'proxmox_token'}}
HOLDS = ('HOLD.json', 'ROLLOUT-HOLD.json', 'CONTINUATION-HOLD.json', 'FOUNDATION-HOLD.json')
SCHEMA = 'homelab-foundation-rollout-v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def private_directory(path, create=False):
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'Expected an owned mode-0700 foundation directory')


def regular(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024 * 1024,
                'Expected a bounded regular foundation input')
        if private:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    'Expected an owned mode-0600 foundation input')
        value = stream.read(1024 * 1024 + 1)
    require(len(value) <= 1024 * 1024, 'Oversized foundation input')
    return value


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def write_marker(path, value):
    # Only our own held phase can be updated under the adapter lock. Never use
    # this helper to replace an input, public phase receipt or failed log.
    if path.exists() or path.is_symlink():
        regular(path, private=True)
    temporary = path.with_name(path.name + '.pending')
    write_new(temporary, encoded(value))
    os.replace(temporary, path)
    sync(path.parent)


def bindings(bundles):
    value = json.loads(regular(bundles / 'bindings.json'))
    require(set(value) == {'site', 'guests'} and set(value['guests']) == set(KINDS),
            'Expected the rendered site and exact foundation guest bindings')
    guests = value['guests']
    require(all(isinstance(row, list) and len(row) == 2 and type(row[0]) is int
                and row[0] >= 100 and row[0] not in {4914, 4915, 4920}
                and isinstance(row[1], str) for row in guests.values())
            and len({row[0] for row in guests.values()}) == len(KINDS), 'Invalid or colliding foundation identities')
    return guests, value['site']


def policy(bundles, name):
    guests, _ = bindings(bundles)
    value = json.loads(regular(bundles / 'rollout.json'))
    require(isinstance(value, dict) and set(value) == {'schema', 'targets'} and value['schema'] == SCHEMA
            and isinstance(value['targets'], dict) and set(value['targets']) == set(guests),
            'Select the closed foundation rollout policy')
    for target, selected in value['targets'].items():
        require(selected == {'vmid': guests[target][0], 'policy': 'merge-create-only-v1'},
                'Foundation policy permits only the three declared fresh guests')
    return {'schema': SCHEMA, 'target': name, **value['targets'][name]}


def definition(name, bundles, inputs, state):
    guests, site = bindings(bundles)
    require(name in guests, 'Select ingress, identity or db-tools')
    directory = bundles / name
    require(directory.is_dir() and not directory.is_symlink()
            and {path.name for path in directory.iterdir()} == {'site.json', 'stack.json'},
            'Track exactly the selected site and non-secret stack configuration')
    files = {name: regular(directory / name) for name in ('site.json', 'stack.json')}
    cfg, stack = json.loads(files['site.json']), json.loads(files['stack.json'])
    vmid, hostname = guests[name]
    destination = inputs / ('foundation-' + name)
    require(cfg['site'] == site and type(cfg['guest']['vmid']) is int and cfg['guest']['vmid'] == vmid
            and cfg['guest']['hostname'] == hostname and type(cfg['app']['vmid']) is int and cfg['app']['vmid'] == vmid
            and cfg['app']['hostname'] == hostname and cfg['app']['kind'] == name
            and cfg['app']['stack_config'] == str(destination / 'stack.json')
            and cfg['paths']['state_root'] == str(state) and stack['kind'] == name,
            'Select only the rendered foundation identity and private paths')
    return cfg, stack, files, destination, state / str(vmid)


def secret_inputs(name, stack, directory, environment, provider, identity):
    selected = stack['foundation']['secret_files']
    require(isinstance(selected, dict) and REQUIRED[name] <= set(selected)
            and set(selected) <= set(SECRETS[name]), 'Select only the fixed foundation secret names')
    result = {}
    for key, path in selected.items():
        filename, variable = SECRETS[name][key]
        require(path == str(directory / filename), 'Foundation secret path differs from its fixed private destination')
        if variable is None:
            value = json.loads(regular(provider, private=True))
            require(isinstance(value, dict) and set(value) == {'schema', 'identity', 'token'}
                    and value['schema'] == 'homelab-service-discovery-v1' and value['identity'] == identity
                    and isinstance(value['token'], str)
                    and re.fullmatch(re.escape(identity) + r'=[A-Za-z0-9-]+', value['token'])
                    and stack['foundation']['proxmox_token_id'] == identity,
                    'Use only the retained declared discovery credential')
            secret = value['token'].split('=', 1)[1]
        else:
            # variable comes only from the fixed mapping above, never Git input.
            secret = environment.get(variable)
        require(isinstance(secret, str) and 0 < len(secret.encode()) <= 65536 and secret.strip()
                and not any(char in secret for char in '\r\n\x00'),
                'A required foundation environment secret is missing or invalid')
        result[filename] = secret.encode()
    return result


def prepare(name, deployment, bundles, inputs=INPUTS, state=STATE, provider=PROVIDER, environment=None):
    guests, site = bindings(bundles)
    cfg, stack, files, directory, work = definition(name, bundles, inputs, state)
    require(not any((work / marker).exists() or (work / marker).is_symlink() for marker in HOLDS),
            'Preserve the failed foundation rollout; no automatic retry')
    require((work / 'foundation-complete.json').is_file()
            or not any((work / name).exists() or (work / name).is_symlink() for name in
                       ('applied.json', 'started.json', 'rollout-complete.json', 'terraform.tfstate', 'plan.json',
                        'guest.tfplan', 'guest.tfplan.json')),
            'Existing foundation phase receipts need review; no adoption or continuation')
    private_directory(inputs)
    selected_policy = policy(bundles, name)
    files.update(secret_inputs(name, stack, directory, os.environ if environment is None else environment, provider,
                               'root@pam!homelab-traefik-' + str(guests['ingress'][0])))
    if name == 'ingress':
        require(stack['foundation']['pve_ca_file'] == cfg['paths']['ca_file']
                and stack['foundation']['proxmox_url'].rstrip('/') == site['api_endpoint'].rstrip('/'),
                'Discovery must use the existing pinned host endpoint and CA')
    manifest = {'schema': SCHEMA, 'guest': name, 'policy': selected_policy,
                'files': {key: digest(value) for key, value in files.items()}}
    if directory.exists() or directory.is_symlink():
        private_directory(directory)
        require({path.name for path in directory.iterdir()} == set(files) | {'prepared.json'},
                'Incomplete or unexpected foundation inputs need review; no replacement')
        require(regular(directory / 'prepared.json', private=True) == encoded(manifest)
                and all(regular(directory / key, private=True) == value for key, value in files.items()),
                'Existing foundation inputs changed; preserve them for review')
    else:
        private_directory(directory, create=True)
        for key, value in files.items():
            write_new(directory / key, value)
        # Last file: a killed preparation leaves an incomplete folder, never an
        # apparently reusable bundle. Later runs refuse to fill its gaps.
        deployment.validate(cfg)
        write_new(directory / 'prepared.json', encoded(manifest))
    deployment.validate(cfg)
    return cfg, directory / 'site.json', work, manifest


def run(name, deployment, bundles, inputs=INPUTS, state=STATE, provider=PROVIDER, environment=None):
    guests, host = bindings(bundles)
    cfg, _, _, _, work = definition(name, bundles, inputs, state)
    private_directory(state)
    if not work.exists():
        private_directory(work, create=True)
    private_directory(work)
    lock_path = work / 'foundation.lock'
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cfg, site, work, manifest = prepare(name, deployment, bundles, inputs, state, provider, environment)
        hold, complete = work / 'FOUNDATION-HOLD.json', work / 'foundation-complete.json'
        binding = {'schema': SCHEMA, 'guest': name, 'vmid': guests[name][0],
                   'prepared_sha256': digest(encoded(manifest)), 'source_sha256': deployment.source_hash(),
                   'input_hashes': deployment.input_hashes(cfg)}
        if complete.exists() or complete.is_symlink():
            receipt = json.loads(regular(complete, private=True))
            public = json.loads(regular(work / 'rollout-complete.json', private=True))
            require(receipt.get('binding') == binding and receipt.get('status') == 'passed'
                    and receipt.get('public_receipt_sha256') == digest(encoded(public))
                    and public.get('status') == 'passed' and public.get('vmid') == guests[name][0]
                    and public.get('plan_sha256') == receipt.get('plan_sha256'),
                    'Completed foundation rollout or selected inputs differ; no redeployment')
            marker = dict(binding, step='verify', automatic_retry=False)
            write_marker(hold, marker)
            result = deployment.execute('verify', site)
            require(result.get('status') == 'passed' and result.get('vmid') == guests[name][0],
                    'Read-only foundation verification did not pass')
            require(json.loads(regular(hold, private=True)) == marker, 'Foundation hold ownership changed')
            hold.unlink(); sync(work)
            return result
        require(not any((work / filename).exists() or (work / filename).is_symlink() for filename in
                        ('applied.json', 'started.json', 'rollout-complete.json', 'terraform.tfstate', 'plan.json',
                         'guest.tfplan', 'guest.tfplan.json', 'FOUNDATION-HOLD.json.pending')),
                'Existing foundation phase receipts need review; no adoption or continuation')
        marker = dict(binding, step='plan', automatic_retry=False)
        write_marker(hold, marker)
        plan = deployment.execute('plan', site)
        require(json.loads(regular(work / 'plan.json', private=True)) == plan
                and plan.get('vmid') == guests[name][0] and plan.get('creates_guest') is True
                and plan.get('site_sha256') == digest(regular(site, private=True))
                and plan.get('source_sha256') == binding['source_sha256']
                and plan.get('input_hashes') == binding['input_hashes']
                and re.fullmatch(r'[0-9a-f]{64}', plan.get('plan_sha256', ''))
                and digest(regular(work / 'guest.tfplan', private=True)) == plan['plan_sha256']
                and digest(regular(work / 'guest.tfplan.json', private=True)) == plan.get('plan_json_sha256'),
                'The single saved foundation plan or its input binding differs')
        deployment.check_merge_create_plan(json.loads(regular(work / 'guest.tfplan.json', private=True)),
                                           host['node'], guests[name][0])
        marker = dict(binding, step='deploy', plan_sha256=plan['plan_sha256'], automatic_retry=False)
        write_marker(hold, marker)
        result = deployment.execute('deploy', site, plan['plan_sha256'])
        public = json.loads(regular(work / 'rollout-complete.json', private=True))
        require(result == public and result.get('status') == 'passed' and result.get('vmid') == guests[name][0]
                and result.get('plan_sha256') == plan['plan_sha256'],
                'The shared installer did not complete the selected foundation rollout')
        write_new(complete, encoded({'status': 'passed', 'binding': binding,
                  'plan_sha256': plan['plan_sha256'], 'public_receipt_sha256': digest(encoded(public))}))
        require(json.loads(regular(hold, private=True)) == marker, 'Foundation hold ownership changed')
        hold.unlink(); sync(work)
        return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', choices=KINDS, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve() / 'proxmox/applications'))
    deployment = importlib.import_module('deploy')
    try:
        require(args.source.resolve() / 'proxmox/applications' == Path(__file__).resolve().parent,
                'Use this same pinned implementation for rendering and deployment')
        with tempfile.TemporaryDirectory(prefix='homelab-foundation-') as temporary:
            bundles = Path(temporary) / 'bundle'
            site_config.write_bundle(site_config.read(args.config), bundles)
            print(json.dumps(run(args.guest, deployment, bundles=bundles)))
    except Exception:
        # Inputs and child exceptions may contain credentials. Deliberately do
        # not print their values, exception text, command output or tracebacks.
        raise SystemExit('Foundation CD held; preserve its private inputs, saved plan and phase receipts') from None


if __name__ == '__main__':
    main()
