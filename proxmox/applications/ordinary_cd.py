"""Ordinary per-guest deployment through the existing OpenTofu/Ansible engine.

Installation and migration receipts stay immutable. A missing guest is created
only from empty custody; existing guests keep their authoritative backend and
SSH identity. Application reconciliation never restores data. Failed operations
remain held, including interruptions between the two visible Actions steps.
"""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import deploy
import foundation_cd as files
from plan import check_plan

GUEST_ADAPTER_API = 1

KINDS = {'postgresql', 'mariadb', 'influxdb', 'identity', 'db-tools', 'automation'}
HOLDS = set(files.HOLDS) | {'ORDINARY-HOLD.json', 'SERVICE-VERIFY-HOLD.json', 'SERVICE-VERIFYING.json'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def prepare(packet_path, inputs=Path('/var/lib/homelab-inputs/ordinary'), environment=None, adapter=None):
    packet = json.loads(files.regular(packet_path))
    files.require(set(packet) == {'schema', 'enabled', 'kind', 'identity', 'files'}
                  and packet['schema'] == 'homelab-ordinary-deployment-v1'
                  and packet['enabled'] is True and (packet['kind'] in KINDS or
                      (adapter is not None and packet['kind'] == adapter.KIND == 'zigbee2mqtt'
                       and adapter.ADAPTER_API == GUEST_ADAPTER_API)),
                  'Review and explicitly enable this ordinary guest deployment')
    kind, identity = packet['kind'], packet['identity']
    files.require(isinstance(identity, str) and re.fullmatch('[0-9a-f]{64}', identity),
                  'Bind the reviewed ordinary input identity')
    destination = inputs / kind / identity
    payload = {name: value.encode() for name, value in packet['files'].items()}
    files.require('site.json' in payload and all(re.fullmatch(r'[a-z][a-z0-9_.-]{0,63}', n) for n in payload),
                  'Use bounded ordinary input file names')
    cfg = json.loads(payload['site.json'])
    initial_radio = False
    if adapter is not None and kind == 'zigbee2mqtt':
        import zigbee_cd
        initial_radio = (adapter is zigbee_cd and zigbee_cd.INITIAL_CAPTURE is True
                         and cfg['app'].get('radio_cd_mode') in zigbee_cd.MODES)
    files.require(cfg['app']['kind'] == kind and ('capture' not in cfg['app'] or initial_radio)
                  and 'ha_http' not in cfg['app'], 'Ordinary deployment cannot migrate or restore data')
    files.require(adapter is None or 'stack.json' in payload, 'The radio adapter requires its reviewed stack')
    if 'stack.json' in payload:
        stack = json.loads(payload['stack.json'])
        files.require(cfg['app']['stack_config'] == str(destination / 'stack.json'),
                      'Bind the ordinary stack to its private input directory')
        if adapter is not None:
            adapter.validate(cfg, stack)
        if kind == 'automation':
            env = os.environ if environment is None else environment
            secret = env.get('NODE_RED_API_TOKEN')
            files.require(isinstance(secret, str) and 0 < len(secret.encode()) <= 65536
                          and secret.strip() and not any(c in secret for c in '\r\n\x00'),
                          'Supply the existing Node-RED runtime token')
            values = stack['services']['node_red'].setdefault('environment', {})
            files.require('NODE_RED_API_TOKEN' not in values, 'Keep runtime tokens out of source')
            values['NODE_RED_API_TOKEN'] = secret
            payload['stack.json'] = encoded(stack)
        elif adapter is None:
            for name, raw in files.secret_inputs(kind, stack, destination, os.environ if environment is None else environment,
                                                 files.PROVIDER, '').items():
                files.require(name not in payload, 'Secret values must come from the existing runtime bindings')
                payload[name] = raw
    if kind == 'automation':
        for service in json.loads(payload['stack.json'])['services'].values():
            if 'archive' in service:
                archive=Path(service['archive'])
                files.require(archive.is_file() and not archive.is_symlink()
                              and deploy.sha(archive) == service['archive_sha256'],
                              'Preserve the original selected custom image archive before guest operations')
    manifest = encoded({'packet_sha256': deploy.sha(packet_path),
                        'files': {n: hashlib.sha256(raw).hexdigest() for n, raw in payload.items()}})
    for folder in (inputs.parent, inputs, inputs / kind):
        files.private_directory(folder, create=not folder.exists())
    if destination.exists() or destination.is_symlink():
        files.private_directory(destination)
        files.require({p.name for p in destination.iterdir()} == set(payload) | {'prepared.json'}
                      and files.regular(destination / 'prepared.json', private=True) == manifest
                      and all(files.regular(destination / n, private=True) == raw for n, raw in payload.items()),
                      'Ordinary inputs differ or preparation was interrupted; preserve them for review')
    else:
        files.private_directory(destination, create=True)
        for name, raw in payload.items():
            files.write_new(destination / name, raw)
        deploy.validate(cfg)
        files.write_new(destination / 'prepared.json', manifest)
    return cfg, destination / 'site.json'


def binding(cfg, site):
    return {'vmid': cfg['guest']['vmid'], 'site_sha256': deploy.sha(site),
            'source_sha256': deploy.source_hash(), 'input_hashes': deploy.input_hashes(cfg)}


def check_ordinary_plan(value, cfg, *, existing, adapter=None):
    check_plan(value, cfg['site']['node'], cfg['guest']['vmid'])
    files.require(not value.get('resource_drift'), 'Review native drift before ordinary reconciliation')
    if adapter is not None:
        adapter.check_plan(value, cfg, existing=existing)
    if not existing:
        deploy.check_merge_create_plan(value, cfg['site']['node'], cfg['guest']['vmid'])
        return
    for row in value['resource_changes']:
        change = row['change']
        files.require(change['actions'] in (['update'], ['no-op']) and isinstance(change.get('before'), dict)
                      and not change.get('replace_paths') and not change.get('importing'),
                      'Never recreate, replace or adopt an installed guest')
        # Resource identity and data volumes are permanent, even in an approved update.
        if row['address'] == 'module.guest.proxmox_virtual_environment_container.guest':
            before, after = change['before'], change['after']
            for key in ('node_name', 'vm_id', 'disk', 'mount_point', 'operating_system',
                        'unprivileged', 'protection', 'purge_on_destroy'):
                files.require(before.get(key) == after.get(key), 'Preserve the guest and its managed application data')


def infrastructure(cfg, site, work, operation, expected, adapter=None):
    """Plan the existing backend; apply only this reviewed guest's safe delta."""
    existing = (work / 'terraform.tfstate').is_file()
    files.require(existing or not any((work / name).exists() or (work / name).is_symlink() for name in
                  ('plan.json', 'applied.json', 'started.json', 'rollout-complete.json', 'foundation-complete.json')),
                  'Installation custody exists without state; no automatic recreation')
    if adapter is not None:
        adapter.before_infrastructure(cfg, site, work, operation, expected, engine=sys.modules[__name__])
    deploy.backup(cfg, work / 'terraform.tfstate', 'before-ordinary')
    shutil.copytree(deploy.SOURCE / 'tofu', operation / 'tofu',
                    ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', '*.tfplan'))
    variables = {k: cfg[k] for k in ('site', 'guest', 'ssh_public_keys')}
    variables['guest'] = dict(cfg['guest'], routing_labels=deploy.discovery.labels(cfg))
    deploy.write(operation / 'tofu/site.auto.tfvars.json', variables)
    environment = os.environ.copy()
    environment.update(TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1', SSL_CERT_FILE=cfg['paths']['ca_file'],
                       PROXMOX_VE_API_TOKEN=files.regular(Path(cfg['paths']['api_token']), private=True).decode().strip())
    tofu = ['tofu', '-chdir=' + str(operation / 'tofu')]
    log = operation / 'infrastructure.log'
    deploy.quiet(tofu + ['init', '-input=false', '-lockfile=readonly',
                 '-backend-config=path=' + str(work / 'terraform.tfstate')], environment, log)
    deploy.quiet(tofu + ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(operation / 'guest.tfplan')], environment, log)
    value = json.loads(subprocess.check_output(tofu + ['show', '-json', str(operation / 'guest.tfplan')], env=environment))
    check_ordinary_plan(value, cfg, existing=existing, adapter=adapter)
    files.require(binding(cfg, site) == expected, 'Approved inputs changed while planning')
    changed = any(row['change']['actions'] != ['no-op'] for row in value['resource_changes'])
    deploy.write(operation / 'plan.json', {'binding': expected, 'plan_sha256': deploy.sha(operation / 'guest.tfplan'),
                                          'changed': changed, 'existing_guest': existing})
    if not existing:
        # The shared identity checker anchors a new key to this exact plan and
        # the successful creation task inside its actual apply window.
        files.require(changed, 'A new guest requires the reviewed creation plan')
        files.write_new(work / 'plan.json', files.regular(operation / 'plan.json', private=True))
        window = {'plan_sha256': deploy.sha(operation / 'guest.tfplan'), 'started_at_ns': time.time_ns()}
        files.write_new(work / 'apply-window.json', encoded(window))
    if changed:
        deploy.quiet(tofu + ['apply', '-input=false', '-lock-timeout=30s', str(operation / 'guest.tfplan')], environment, log)
    if not existing:
        files.write_marker(work / 'apply-window.json', dict(window, finished_at_ns=time.time_ns()))
        deploy.guest_identity.pin(cfg, work, cfg['app']['address'], lambda p: deploy.api_get(cfg, p), deploy.write)
    deploy.backup(cfg, work / 'terraform.tfstate', 'after-ordinary')
    return {'changed': changed, 'created': not existing, 'state_sha256': deploy.sha(work / 'terraform.tfstate')}


def application(cfg, site, work, operation, expected, service=None, *, playbook='reconcile.yml'):
    """Reuse guarded packages/configuration tasks, with restoration excluded."""
    files.require(binding(cfg, site) == expected, 'Approved inputs changed before Ansible')
    files.require(playbook in ('reconcile.yml', 'zigbee-preflight.yml', 'zigbee-reconcile.yml'), 'Use the reviewed ordinary playbook')
    deploy.guest_trust(cfg, work)
    app = dict(cfg['app'], render_dir=str(operation / 'rendered'), start_services=True)
    if service is not None:
        files.require(service in deploy.AUTOMATION_SERVICES, 'Select one automation service')
        app['health_checks'] = cfg['app']['service_health_checks'][service]
    if 'stack_config' in app:
        deploy.quiet(['python3', str(deploy.SOURCE / 'render.py'), '--config', app['stack_config'],
                      '--output', app['render_dir']], deploy.ansible_environment(cfg), operation/'render.log')
    deploy.write(operation / 'variables.json', {'app': app, 'network_ready_interfaces': deploy.required_network_interfaces(cfg),
                  **({'ordinary_service': service} if service is not None else {})})
    deploy.write(operation / 'inventory.json', {'application': {'hosts': {app['hostname']: {
        'ansible_host': app['address'], 'ansible_user': 'root'}}}})
    command = ['ansible-playbook', '-i', str(operation / 'inventory.json'), '--private-key', cfg['paths']['private_key'],
               str(deploy.SOURCE / 'ansible' / playbook), '--extra-vars', '@' + str(operation / 'variables.json')]
    deploy.quiet(command, deploy.ansible_environment(cfg), operation / 'application.log')
    files.require(binding(cfg, site) == expected, 'Approved inputs changed during Ansible')
    text = (operation/'application.log').read_text()
    counts = re.findall(r'changed=(\d+)', text)
    files.require(counts, 'Ansible did not produce its completion recap')
    return {'status': 'passed', 'changed': any(int(n) for n in counts)}


def run(phase, packet, *, inputs=Path('/var/lib/homelab-inputs/ordinary'), environment=None, adapter=None, infrastructure_only=False):
    files.require(phase in ('infrastructure', 'application', *deploy.AUTOMATION_SERVICES), 'Select the visible OpenTofu or Ansible step')
    files.require(not any(p.exists() or p.is_symlink() for p in
                  (Path('/var/lib/homelab-bootstrap/CONFIGURING'), Path('/var/lib/homelab-bootstrap/BOOTSTRAP-CD-HOLD.json'))),
                  'Preserve bootstrap maintenance custody')
    cfg, site = prepare(packet, inputs, environment, **({"adapter": adapter} if adapter is not None else {}))
    vmid = deploy.validate(cfg)
    files.require(type(infrastructure_only) is bool and (not infrastructure_only or
                  cfg['app']['kind'] == 'automation' and phase == 'infrastructure' and adapter is None),
                  'Infrastructure-only preparation belongs to the Automation guest step')
    phases = list(deploy.AUTOMATION_SERVICES) if cfg['app']['kind'] == 'automation' else ['application']
    files.require(phase == 'infrastructure' or phase in phases, 'Select this guest application step')
    state = Path(cfg['paths']['state_root']); files.private_directory(state)
    work = state / str(vmid); files.private_directory(work, create=not work.exists())
    # Preserve shared database custody as well as per-guest deployment serialization.
    with ExitStack() as locks:
        for path, shared in [(state / 'database-network.lock', True), (work / 'workflow.lock', False),
                             (work / 'deployment.lock', False)]:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stream = locks.enter_context(os.fdopen(fd, 'a+'))
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        for directory in [work, *state.glob('database-network-cutover-*'),
                          *state.glob('database-server-cutover-*')]:
            files.require(not any(p.is_symlink() or p.exists() for p in directory.glob('*HOLD.json') if p != work/'ORDINARY-HOLD.json')
                          and not any((directory/n).exists() or (directory/n).is_symlink() for n in HOLDS - {'ORDINARY-HOLD.json'})
                          and not (directory / 'VERIFYING.json').exists(), 'Preserve an unresolved operation or verification hold')
        files.require(not any(work.glob('database-*/*HOLD.json')),
                      'Preserve a nested database operation hold')
        expected = binding(cfg, site); hold = work / 'ORDINARY-HOLD.json'
        complete = work / 'ordinary-complete.json'
        prepared = work / 'ordinary-infrastructure-ready.json'
        if infrastructure_only:
            files.require(not complete.exists() and not complete.is_symlink(), 'Use normal application mode after a completed deployment')
            if prepared.exists() or prepared.is_symlink():
                ready = json.loads(files.regular(prepared, private=True))
                if (ready.get('status') == 'infrastructure-ready' and ready.get('binding') == expected
                        and ready.get('state_sha256') == deploy.sha(work/'terraform.tfstate')):
                    files.require(not hold.exists() and not hold.is_symlink(), 'Preserve an interrupted preparation')
                    return {'status':'passed','vmid':vmid,'readiness':'infrastructure-ready',
                            'application_ready':False,'changed':False,'target_contacted':False}
        if complete.exists() or complete.is_symlink():
            old = json.loads(files.regular(complete, private=True))
            if old.get('status') == 'passed' and old.get('binding') == expected and old.get('state_sha256') == deploy.sha(work/'terraform.tfstate'):
                files.require(not hold.exists() and not hold.is_symlink(), 'Preserve an interrupted ordinary operation')
                return {'status': 'passed', 'vmid': vmid, 'changed': False, 'target_contacted': False}
        if cfg['app']['kind'] == 'automation' and phase == 'infrastructure' and not infrastructure_only and not complete.exists():
            ready = json.loads(files.regular(prepared, private=True))
            files.require(ready.get('status') == 'infrastructure-ready'
                          and ready.get('binding') == expected
                          and ready.get('state_sha256') == deploy.sha(work/'terraform.tfstate'),
                          'First application rollout needs the exact prepared infrastructure state')
        identity = '-'.join(os.environ.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
        files.require(re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*', identity), 'Use the identified merge-triggered deployment run')
        operation = work / ('ordinary-' + identity)
        marker = {'binding': expected, 'operation': str(operation), 'automatic_retry': False}
        if infrastructure_only: marker['infrastructure_only'] = True
        if phase == 'infrastructure':
            files.require(not hold.exists() and not hold.is_symlink() and not operation.exists(),
                          'An existing ordinary operation requires review; no replay')
            files.private_directory(operation, create=True); files.write_new(hold, encoded(marker))
            result = infrastructure(cfg, site, work, operation, expected, **({"adapter": adapter} if adapter is not None else {}))
            files.write_new(operation / 'infrastructure-complete.json', encoded({'binding': expected, **result}))
            if infrastructure_only:
                files.require(binding(cfg, site) == expected
                              and result['state_sha256'] == deploy.sha(work/'terraform.tfstate')
                              and files.regular(hold, private=True) == encoded(marker),
                              'Preserve changed or interrupted infrastructure preparation')
                receipt = {'status':'infrastructure-ready','binding':expected,
                           'state_sha256':result['state_sha256'],'application_ready':False}
                files.write_new(operation/'preparation-complete.json', encoded(receipt))
                deploy.write(prepared, receipt)
                # Only this fully successful preparation closes its own active
                # transaction. Failure/unknown holds are never cleared here.
                files.require(files.regular(hold, private=True) == encoded(marker), 'Preparation hold ownership changed')
                hold.unlink(); files.sync(work)
                return {'status':'passed','vmid':vmid,'readiness':'infrastructure-ready',
                        'application_ready':False,**result}
            return {'status': 'passed', 'vmid': vmid, **result}
        files.require(files.regular(hold, private=True) == encoded(marker), 'Only the same run may complete its Ansible step')
        ready = json.loads(files.regular(operation / 'infrastructure-complete.json', private=True))
        files.require(ready['binding'] == expected and ready['state_sha256'] == deploy.sha(work/'terraform.tfstate')
                      and not (operation/(phase+'-started.json')).exists(), 'Preserve changed or interrupted application custody')
        for previous in phases[:phases.index(phase)]:
            files.require(json.loads(files.regular(operation/(previous+'-complete.json'), private=True))['binding'] == expected,
                          'Complete the preceding service before its consumer')
        files.write_new(operation/(phase+'-started.json'), encoded(marker))
        result = (adapter.application(cfg, site, work, operation, expected, engine=sys.modules[__name__])
                  if adapter is not None else application(cfg, site, work, operation, expected,
                             phase if cfg['app']['kind'] == 'automation' else None))
        files.write_new(operation/(phase+'-complete.json'), encoded({'binding':expected, 'result':result}))
        if phase != phases[-1]:
            return {'status':'passed','vmid':vmid,'service':phase,'changed':result['changed']}
        changed = ready['changed'] or any(json.loads(files.regular(operation/(p+'-complete.json'), private=True))['result']['changed'] for p in phases)
        receipt = {'status': 'passed', 'binding': expected, 'state_sha256': ready['state_sha256'], 'result': result}
        files.write_new(operation/'complete.json', encoded(receipt))
        # Ordinary receipt is separate from all original installation/migration records.
        deploy.write(complete, receipt)
        files.require(files.regular(hold, private=True) == encoded(marker), 'Ordinary hold ownership changed')
        hold.unlink(); files.sync(work)
        return {'status': 'passed', 'vmid': vmid, 'changed': changed}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('infrastructure', 'application', *deploy.AUTOMATION_SERVICES), required=True)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--infrastructure-only', action='store_true')
    args = parser.parse_args()
    try:
        os.umask(0o077)
        print(json.dumps(run(args.phase, args.packet, infrastructure_only=args.infrastructure_only)))
    except Exception:
        raise SystemExit('Ordinary deployment held; preserve private inputs/state and all operation evidence. No automatic replay or restore.') from None
