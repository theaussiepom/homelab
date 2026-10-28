"""Apply one reviewed database network plan, or verify its exact applied overlay.

The original installer/source, installation inputs and receipts remain intact.
This helper owns only the selected saved-plan network update. It never restores
or stages data, activates database/client configuration or claims SQL acceptance.
A failure or interruption keeps its one-use claim and the guest's HOLD.json.
"""
import argparse
from contextlib import ExitStack
import fcntl
import fnmatch
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import database_network_maintenance as maintenance

SCHEMA = 'homelab-database-network-apply-v1'
OVERLAY_SCHEMA = 'homelab-database-network-overlay-v1'
require = maintenance.require
regular = maintenance.regular
encoded = maintenance.encoded
digest = maintenance.digest


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value):
    maintenance.write_new(path, value)
    sync(path.parent)


def private_directory(path, *, create=False):
    if create:
        path.mkdir(mode=0o700)
        sync(path.parent)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Use an owned mode-0700 maintenance directory')


def packet(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'vmid', 'request_sha256',
            'review_packet_sha256', 'apply_helper_sha256', 'allow_guest_restart'} and value['schema'] == SCHEMA,
            'Use the closed reviewed database network apply packet')
    require(type(value['vmid']) is int and value['vmid'] >= 100 and value['vmid'] not in {900, 4914, 4915, 4920}
            and all(isinstance(value[k], str) and re.fullmatch('[0-9a-f]{64}', value[k])
                    for k in ('request_sha256', 'review_packet_sha256', 'apply_helper_sha256')),
            'Bind the exact guest, saved review and helper source')
    require(value['allow_guest_restart'] is True, 'Explicitly permit possible provider guest restart; hotplug is unverified')
    require(value['apply_helper_sha256'] == digest(Path(__file__).read_bytes()), 'Apply helper source differs from the reviewed packet')
    return value


def copied_source_files(directory):
    require(not directory.is_symlink(), 'No alternate original or plan ToFu directory')
    result = {}
    for path in directory.rglob('*'):
        relative = path.relative_to(directory)
        if '.terraform' not in relative.parts and path.name != 'site.auto.tfvars.json':
            require(not fnmatch.fnmatch(path.name, '*.auto.tfvars*')
                    and path.name not in {'terraform.tfvars', 'terraform.tfvars.json'},
                    'Unreviewed automatic variable inputs are present')
        if '.terraform' in relative.parts or any(fnmatch.fnmatch(path.name, pattern)
                for pattern in ('*.tfstate*', '*.tfplan*', '*.auto.tfvars*')):
            continue
        require(not path.is_symlink(), 'Copied ToFu source contains a symlink')
        if path.is_file():
            result[str(relative)] = digest(path.read_bytes())
    require(result and '.terraform.lock.hcl' in result, 'Retain the original pinned provider lock file')
    return result


def load(deployment, installed_config_path, catalogue_path, plan_evidence, packet_path, expected_packet_sha256):
    require(isinstance(expected_packet_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_packet_sha256),
            'Supply the exact reviewed raw packet digest')
    packet_raw = regular(Path(packet_path))
    require(digest(packet_raw) == expected_packet_sha256, 'Apply packet bytes differ from their reviewed digest')
    selected = packet(json.loads(packet_raw))
    site, catalogue_path, plan_evidence = map(Path, (installed_config_path, catalogue_path, plan_evidence))
    cfg = json.loads(regular(site)); deployment.validate(cfg)
    require(cfg['guest']['vmid'] == selected['vmid'] and cfg['paths']['state_root'] == str(maintenance.STATE),
            'Use the original selected guest and authoritative state root')
    work = maintenance.STATE / str(selected['vmid'])
    private_directory(work)
    require(plan_evidence.parent == work and plan_evidence.name.startswith('database-network-plan-'),
            'Select this guest\'s exact saved plan evidence directory')
    private_directory(plan_evidence)
    request_raw = regular(plan_evidence / 'request.json'); review_raw = regular(plan_evidence / 'review-packet.json')
    require(digest(request_raw) == selected['request_sha256'] and digest(review_raw) == selected['review_packet_sha256'],
            'The original saved plan request/review changed')
    request, review = json.loads(request_raw), json.loads(review_raw)
    request_fields = {'schema', 'engine', 'phase', 'vmid', 'client_vmids', 'legacy_server_address', 'catalogue_sha256',
                      'original', 'helper_sha256', 'apply_supported', 'lifecycle_effects_verified'}
    require(set(request) == request_fields and request['schema'] == maintenance.SCHEMA
            and request['vmid'] == selected['vmid'] and request['apply_supported'] is False
            and request['lifecycle_effects_verified'] is False
            and set(review) == request_fields | {'status', 'plan_sha256', 'plan_json_sha256', 'candidate_guest_sha256',
                                                'observed_provider_refresh'}
            and {k: review[k] for k in request} == request and review['status'] == 'review_required',
            'Use the unchanged reviewed planning packet, not an apply or readiness assertion')
    helpers = [Path(maintenance.__file__), Path(maintenance.networks.__file__),
               Path(__file__).with_name('database_network_server.py')]
    require(request['helper_sha256'] == {p.name: digest(p.read_bytes()) for p in helpers},
            'The original plan checker/catalogue helper source changed')
    catalogue_raw = regular(catalogue_path, private=False)
    require(digest(catalogue_raw) == request['catalogue_sha256'], 'Database contract bytes changed')
    catalogue = json.loads(catalogue_raw)
    saved, shown = regular(plan_evidence / 'guest.tfplan'), regular(plan_evidence / 'guest.tfplan.json')
    require(digest(saved) == review['plan_sha256'] and digest(shown) == review['plan_json_sha256'],
            'The exact saved binary or JSON plan changed')
    options = {k: request[k] for k in ('phase', 'client_vmids', 'legacy_server_address')}
    checked = maintenance.check_plan(json.loads(shown), cfg, catalogue, request['engine'], **options)
    require(review['observed_provider_refresh'] == checked['observed_provider_refresh'],
            'The reviewed provider observation summary changed')
    candidate = checked['candidate_guest']
    require(digest(regular(plan_evidence / 'candidate-guest.json')) == review['candidate_guest_sha256']
            == digest(encoded(candidate)), 'The declared network overlay changed')
    require(copied_source_files(Path(deployment.SOURCE) / 'tofu') == copied_source_files(plan_evidence / 'tofu'),
            'Saved-plan ToFu files differ from the original commissioned source')
    attempt = work / ('database-network-apply-' + selected['review_packet_sha256'])
    return dict(cfg=cfg, site=site, catalogue_path=catalogue_path, catalogue_raw=catalogue_raw,
                plan=plan_evidence, work=work, request=request, review=review, candidate=candidate,
                selected=selected, packet_raw=packet_raw, packet_sha256=expected_packet_sha256,
                packet_path=Path(packet_path), request_raw=request_raw, review_raw=review_raw, attempt=attempt)


def refresh(deployment, context):
    c = context
    return load(deployment, c['site'], c['catalogue_path'], c['plan'], c['packet_path'], c['packet_sha256'])


def admission(deployment, context, *, completed=None):
    c = context; original, variables = maintenance.bindings(deployment, c['cfg'], c['site'], c['work'])
    if completed is None:
        require(original == c['request']['original'], 'Original state/source/inputs/completion changed after planning')
    else:
        expected = c['request']['original']
        require({k: v for k, v in original.items() if k not in {'files', 'state_serial'}}
                == {k: v for k, v in expected.items() if k not in {'files', 'state_serial'}}
                and {k: v for k, v in original['files'].items() if k != 'terraform.tfstate'}
                == {k: v for k, v in expected['files'].items() if k != 'terraform.tfstate'}
                and original['files']['terraform.tfstate'] == completed['state_sha256']
                and original['state_serial'] == completed['state_serial']
                and original['state_lineage'] == completed['state_lineage'],
                'Applied overlay state or original immutable installation bindings changed')
    variables = maintenance.candidate_variables(variables, c['candidate'])
    require(json.loads(regular(c['plan'] / 'tofu/site.auto.tfvars.json')) == variables,
            'Saved candidate variables differ from the original source and selected network overlay')
    require(regular(c['catalogue_path'], private=False) == c['catalogue_raw'], 'Catalogue drifted during admission')
    return original


def nas_root(cfg):
    """Same existing NAS authority checks as the commissioned state backup path."""
    mount = Path(cfg['paths']['backup_mount']).resolve()
    require(os.path.ismount(mount), 'The selected NAS mount is unavailable; no local fallback')
    rows = subprocess.check_output(['findmnt', '-rn', '-o', 'FSTYPE,SOURCE', '--target', str(mount)],
                                   text=True, timeout=10).strip().splitlines()
    actual = [row.split() for row in rows if row.split() and row.split()[0] in {'nfs', 'nfs4', 'cifs'}]
    require(len(actual) == 1 and len(actual[0]) == 2 and actual[0][1] == cfg['paths']['backup_source'],
            'NAS mount identity differs from the selected original backup source')
    destination = Path(cfg['paths']['backup_directory']) / str(cfg['guest']['vmid'])
    require(mount in destination.resolve().parents, 'Keep overlay custody below the selected NAS mount')
    private_directory(destination)
    return destination


def custody(context, name, value):
    c = context; write_new(c['attempt'] / name, value)
    remote = nas_root(c['cfg']) / c['attempt'].name
    private_directory(remote)
    write_new(remote / name, value)
    require(regular(c['attempt'] / name) == regular(remote / name) == value, 'Local/NAS maintenance custody differs')


def marker(context):
    return encoded({'schema': SCHEMA, 'vmid': context['selected']['vmid'], 'packet_sha256': context['packet_sha256'],
                    'review_packet_sha256': context['selected']['review_packet_sha256'], 'automatic_retry': False})


def no_holds(context):
    maintenance.no_holds(context['work'])


def environment(cfg):
    env = {k: v for k, v in os.environ.items() if not k.startswith('TF_CLI_ARGS')}
    env.update(TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1', TF_WORKSPACE='default',
               SSL_CERT_FILE=cfg['paths']['ca_file'], PROXMOX_VE_API_TOKEN=regular(Path(cfg['paths']['api_token'])).decode().strip())
    return env


def run_tofu(context, action, log, *, directory=None, output=None):
    c = context; command = ['tofu', '-chdir=' + str(directory or c['plan'] / 'tofu'), *action]
    maintenance.tofu(command, environment(c['cfg']), log, output)


def readonly_overlay(context, directory):
    """A fresh provider read/plan against the NEW candidate, never legacy NICs."""
    c = context; directory.mkdir(mode=0o700); sync(directory.parent)
    log = directory / 'verify.log'; write_new(log, b'')
    run_tofu(c, ['init', '-input=false', '-lockfile=readonly',
        '-backend-config=path=' + str(c['work'] / 'terraform.tfstate')], log)
    run_tofu(c, ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(directory / 'check.tfplan')], log)
    run_tofu(c, ['show', '-json', str(directory / 'check.tfplan')], log, output=directory / 'check.tfplan.json')
    value = json.loads(regular(directory / 'check.tfplan.json'))
    approved = json.loads(regular(c['plan'] / 'guest.tfplan.json'))
    expected = {row['address']: row['change']['after'] for row in approved['resource_changes']}
    rows = value.get('resource_changes', [])
    observations = maintenance.validate_provider_drift(value)
    require(len(rows) == len(expected) and {row.get('address') for row in rows} == set(expected)
            and not value.get('deferred_changes') and not value.get('errored'),
            'Review applied network drift, unknown resources or planning errors')
    for row in rows:
        change = row['change']
        if row['address'] == maintenance.RULES:
            maintenance.validate_rule_positions(change.get('before'))
            maintenance.validate_rule_positions(change.get('after'))
        require(change.get('actions') == ['no-op']
                and maintenance.provider_values_equal(row['address'],change.get('before'),change.get('after'))
                and maintenance.provider_values_equal(row['address'],change.get('after'),expected[row['address']])
                and not maintenance.unknown(change.get('after_unknown', {})) and not change.get('replace_paths')
                and not change.get('importing') and not row.get('previous_address') and row.get('mode', 'managed') == 'managed',
                'The applied network overlay is no longer an exact no-op; do not replan legacy inputs')
    return {'status': 'network_overlay_verified', 'vmid': c['selected']['vmid'],
            'plan_json_sha256': digest(regular(directory / 'check.tfplan.json')),
            'observed_provider_refresh': observations,
            'service_acceptance_verified': False, 'guest_lifecycle_observed': False}


def confirm_saved_plan(context, log):
    c = context; output = c['attempt'] / 'admitted-plan.json'
    run_tofu(c, ['show', '-json', str(c['plan'] / 'guest.tfplan')], log, output=output)
    require(json.loads(regular(output)) == json.loads(regular(c['plan'] / 'guest.tfplan.json')),
            'The actual saved binary plan differs from its reviewed JSON')


def locked(context):
    stack = ExitStack()
    try:
        for name in ('workflow.lock', 'deployment.lock'):
            lock = stack.enter_context(os.fdopen(os.open(context['work'] / name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+'))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return stack
    except BaseException:
        stack.close(); raise


def fail(context, error):
    c = context; captured = False; custody_error = None
    try:
        custody(c, 'failed-state.json', regular(c['work'] / 'terraform.tfstate')); captured = True
    except Exception as capture_error:
        custody_error = type(capture_error).__name__
    value = encoded({'status': 'held', 'error_type': type(error).__name__, 'automatic_retry': False,
                     'failed_state_custody': captured, 'custody_error_type': custody_error})
    write_new(c['attempt'] / ('failure-' + str(time.time_ns()) + '.json'), value)


def apply(deployment, installed_config_path, catalogue_path, plan_evidence, packet_path, expected_packet_sha256):
    c = load(deployment, installed_config_path, catalogue_path, plan_evidence, packet_path, expected_packet_sha256)
    with locked(c):
        c = refresh(deployment, c)
        no_holds(c); admission(deployment, c)
        require(not c['attempt'].exists() and not c['attempt'].is_symlink(), 'This saved network plan was already claimed; use verify only after success')
        private_directory(c['attempt'], create=True)
        write_new(c['work'] / 'HOLD.json', marker(c))
        write_new(c['attempt'] / 'claim.json', c['packet_raw'])
        try:
            deployment.backup(c['cfg'], c['work'] / 'terraform.tfstate', 'before-database-network-apply')
            remote = nas_root(c['cfg']) / c['attempt'].name
            private_directory(remote, create=True)
            write_new(remote / 'claim.json', c['packet_raw'])
            require(regular(remote / 'claim.json') == regular(c['attempt'] / 'claim.json'), 'NAS claim readback differs')
            for name, value in [('request.json', c['request_raw']), ('review-packet.json', c['review_raw']),
                ('guest.tfplan', regular(c['plan'] / 'guest.tfplan')), ('guest.tfplan.json', regular(c['plan'] / 'guest.tfplan.json')),
                ('state-before.json', regular(c['work'] / 'terraform.tfstate'))]:
                custody(c, name, value)
            admission(deployment, c)
            log = c['attempt'] / 'apply.log'; write_new(log, b'')
            run_tofu(c, ['init', '-input=false', '-lockfile=readonly',
                '-backend-config=path=' + str(c['work'] / 'terraform.tfstate')], log)
            confirm_saved_plan(c, log)
            c = refresh(deployment, c); admission(deployment, c)
            run_tofu(c, ['apply', '-input=false', '-lock-timeout=30s', str(c['plan'] / 'guest.tfplan')], log)
            state_raw = regular(c['work'] / 'terraform.tfstate'); state = json.loads(state_raw)
            require(state.get('lineage') == c['request']['original']['state_lineage'] and type(state.get('serial')) is int
                    and state['serial'] > c['request']['original']['state_serial'], 'Applied state lineage/serial differs')
            post = {'state_sha256': digest(state_raw), 'state_lineage': state['lineage'], 'state_serial': state['serial']}
            admission(deployment, c, completed=post)
            checked = readonly_overlay(c, c['attempt'] / 'verify-initial')
            c = refresh(deployment, c); admission(deployment, c, completed=post)
            custody(c, 'state-after.json', state_raw)
            deployment.backup(c['cfg'], c['work'] / 'terraform.tfstate', 'after-database-network-apply')
            overlay = {'schema': OVERLAY_SCHEMA, **checked, **post, 'packet_sha256': c['packet_sha256'],
                'request_sha256': c['selected']['request_sha256'], 'review_packet_sha256': c['selected']['review_packet_sha256'],
                'candidate_guest_sha256': c['review']['candidate_guest_sha256'], 'original': c['request']['original']}
            custody(c, 'overlay.json', encoded(overlay))
            require(regular(c['work'] / 'HOLD.json') == marker(c), 'Maintenance hold ownership changed')
            (c['work'] / 'HOLD.json').unlink(); sync(c['work'])
            return overlay
        except Exception as error:
            fail(c, error)
            raise


def verify(deployment, installed_config_path, catalogue_path, plan_evidence, packet_path, expected_packet_sha256):
    c = load(deployment, installed_config_path, catalogue_path, plan_evidence, packet_path, expected_packet_sha256)
    with locked(c):
        no_holds(c); private_directory(c['attempt'])
        require(regular(c['attempt'] / 'claim.json') == c['packet_raw'], 'Select only the exact completed claim')
        write_new(c['work'] / 'HOLD.json', marker(c))
        try:
            remote = nas_root(c['cfg']) / c['attempt'].name; private_directory(remote)
            require(regular(remote / 'claim.json') == c['packet_raw'], 'Completed claim custody differs')
            raw = regular(c['attempt'] / 'overlay.json')
            require(raw == regular(remote / 'overlay.json'), 'Completed overlay custody differs')
            overlay = json.loads(raw)
            require(overlay.get('schema') == OVERLAY_SCHEMA and overlay.get('status') == 'network_overlay_verified'
                    and overlay.get('packet_sha256') == c['packet_sha256']
                    and overlay.get('request_sha256') == c['selected']['request_sha256']
                    and overlay.get('review_packet_sha256') == c['selected']['review_packet_sha256']
                    and overlay.get('candidate_guest_sha256') == c['review']['candidate_guest_sha256']
                    and overlay.get('original') == c['request']['original'], 'Applied overlay belongs to a different reviewed operation')
            for name, expected in [('request.json', c['request_raw']), ('review-packet.json', c['review_raw']),
                ('guest.tfplan', regular(c['plan'] / 'guest.tfplan')), ('guest.tfplan.json', regular(c['plan'] / 'guest.tfplan.json'))]:
                require(regular(c['attempt'] / name) == regular(remote / name) == expected, 'Original plan custody changed')
            require(regular(c['attempt'] / 'state-after.json') == regular(remote / 'state-after.json')
                    and digest(regular(c['attempt'] / 'state-after.json')) == overlay['state_sha256']
                    and regular(c['attempt'] / 'state-before.json') == regular(remote / 'state-before.json')
                    and digest(regular(c['attempt'] / 'state-before.json')) == c['request']['original']['files']['terraform.tfstate'],
                    'Applied or prior state custody changed')
            c = refresh(deployment, c); admission(deployment, c, completed=overlay)
            directory = c['attempt'] / ('verify-' + str(time.time_ns()))
            result = readonly_overlay(c, directory)
            c = refresh(deployment, c); admission(deployment, c, completed=overlay)
            require(regular(c['work'] / 'HOLD.json') == marker(c), 'Verification hold ownership changed')
            (c['work'] / 'HOLD.json').unlink(); sync(c['work'])
            return {**result, 'packet_sha256': c['packet_sha256']}
        except Exception as error:
            fail(c, error)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('apply', 'verify'), required=True)
    parser.add_argument('--source', type=Path, required=True, help='Unchanged commissioned installer checkout')
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--catalogue', type=Path, required=True)
    parser.add_argument('--plan-evidence', type=Path, required=True)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--packet-sha256', required=True)
    args = parser.parse_args(); os.umask(0o077)
    try:
        require('deploy' not in sys.modules, 'Use a fresh process for the original installer')
        sys.modules.pop('site_config', None)
        sys.path.insert(0, str(args.source.resolve() / 'proxmox/applications'))
        deployment = importlib.import_module('deploy')
        require(Path(deployment.__file__).resolve() == args.source.resolve() / 'proxmox/applications/deploy.py',
                'Loaded installer differs from the original selected checkout')
        result = globals()[args.action](deployment, args.config, args.catalogue, args.plan_evidence, args.packet, args.packet_sha256)
        print(json.dumps({key: result[key] for key in ('status', 'vmid', 'packet_sha256', 'service_acceptance_verified')}))
    except Exception as error:
        raise SystemExit('Database network operation held (' + type(error).__name__ + '); preserve private evidence') from None


if __name__ == '__main__':
    main()
