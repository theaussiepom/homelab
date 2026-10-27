#!/usr/bin/env python3
"""One guest per CD run. Preview, apply the saved plan, stage, then explicitly start."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import ssl
import stat
import time
from urllib.parse import urlparse, quote
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

from plan import check_plan
from restore import sync_directory, validate_archive
import guest_identity
import discovery
import foundation
import ingress_routing
import zigbee2mqtt
import zigbee_usb

check_merge_create_plan = discovery.check_merge_create_plan

SOURCE = Path(__file__).resolve().parent
DATABASE_KINDS = {'mariadb', 'postgresql', 'influxdb'}


class InputNeeded(ValueError):
    """A deliberately non-secret operator instruction, safe for the job summary."""


class RefuseRedirects(HTTPRedirectHandler):
    """A token-bearing request must stay on its explicitly trusted endpoint."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InputNeeded('Proxmox API redirected; inspect its trusted endpoint before continuing')


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def source_hash():
    result = hashlib.sha256()
    for path in sorted([*SOURCE.rglob('*'), *(SOURCE.parent / 'common').rglob('*')]):
        if path.is_file() and not any(p in {'.terraform', '__pycache__', '.work'} for p in path.parts):
            result.update(str(path.relative_to(SOURCE.parent)).encode())
            result.update(bytes.fromhex(sha(path)))
    return result.hexdigest()


def required_network_interfaces(cfg):
    """Use the same ordered ethN names as the OpenTofu guest module."""
    interfaces = cfg['guest']['interfaces']
    result = ['eth' + str(i) for i, nic in enumerate(interfaces) if nic['ipv4'] != 'manual']
    if not result or len(interfaces) > 16:
        raise ValueError('Select the guest interfaces that require IPv4 before service startup')
    return result


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def validate(cfg):
    vmid = cfg['guest']['vmid']
    if isinstance(vmid, bool) or not isinstance(vmid, int) or vmid < 100 or vmid in {900, 4914, 4915, 4920}:
        raise ValueError('Select one application guest, never the deployment controller or protected targets')
    app = cfg['app']
    device = cfg['guest'].get('serial_device')
    if app.get('kind') == 'zigbee2mqtt':
        zigbee_usb.stage(cfg)
        stack = json.loads(Path(app['stack_config']).read_text())
        radio = zigbee2mqtt.validate(stack.get('zigbee'))
        backend = [nic for nic in cfg['guest']['interfaces'] if nic.get('role') == 'backend']
        if (stack.get('kind') != 'zigbee2mqtt' or not isinstance(device, dict) or
                device != {'path': radio['serial_device']} or
                len(backend) != 1 or radio['bind_address'] != backend[0]['ipv4'].split('/')[0]):
            raise ValueError('Zigbee must bind the same exact USB device and guest backend address')
    elif device is not None or 'usb_stage' in app:
        raise ValueError('Serial passthrough belongs only to the selected Zigbee guest')
    discovery.labels(cfg)
    if 'frontend_routing' in app:
        if app.get('kind') != 'ingress':
            raise ValueError('Frontend source routing belongs only to ingress')
        address, _, _, mac = ingress_routing.validate(app['frontend_routing'])
        if not any(nic['ipv4'] == app['frontend_routing']['address'] and nic['mac'].lower() == mac
                   for nic in cfg['guest']['interfaces']):
            raise ValueError('Frontend routing must bind the exact selected guest interface')
    if app['vmid'] != vmid or app['hostname'] != cfg['guest']['hostname'] or app['memory_mib'] != cfg['guest']['memory_mib']:
        raise ValueError('OpenTofu and Ansible must select the same guest and resource budget')
    if not any(nic['ipv4'].split('/')[0] == app['address'] and nic['mac'].lower() == app['mac'].lower() for nic in cfg['guest']['interfaces']):
        raise ValueError('Ansible must use a selected guest interface')
    if app.get('new_target') is not True:
        raise ValueError('This installer is for a selected new guest')
    if app.get('kind') in DATABASE_KINDS and ('capture' in app or 'capture' in app.get('database', {})):
        raise InputNeeded('Database restore is a separate migration step; remove capture inputs from server CD')
    if app.get('kind') in DATABASE_KINDS:
        database = app.get('database', {})
        mode = database.get('account_mode', 'fixed')
        if mode not in {'fixed', 'package'}:
            raise InputNeeded('Select fixed database account IDs or the explicit MariaDB package account mode')
        if mode == 'package' and (app['kind'] != 'mariadb' or database.get('user') != 'mysql'
                                  or database.get('group') != 'mysql' or 'uid' in database or 'gid' in database):
            raise InputNeeded('Package account mode is only for a new empty MariaDB mysql account; remove fixed uid/gid inputs')
    if app.get('kind') == 'automation' and 'stack_config' in app:
        stack = json.loads(Path(app['stack_config']).read_text())
        address = stack.get('services', {}).get('homeassistant', {}).get('environment', {}).get('HOMELAB_HA_IPV4')
        if address and address not in [nic['ipv4'].split('/')[0] for nic in cfg['guest']['interfaces']]:
            raise ValueError('HA discovery must select an address assigned to this guest')
    if 'stack_config' in app:
        stack = json.loads(Path(app['stack_config']).read_text())
        selected = foundation.validate(stack)
        if selected and app.get('kind') == 'ingress' and len(cfg['guest']['interfaces']) > 1:
            if 'frontend_routing' not in app or ingress_routing.validate(app['frontend_routing'])[0] != selected['bind_address']:
                raise ValueError('Multihomed ingress needs routing for its exact frontend listener')
        if selected and app.get('kind') in {'identity', 'ingress'}:
            if selected['bind_address'] not in [nic['ipv4'].split('/')[0] for nic in cfg['guest']['interfaces']]:
                raise ValueError('Foundation listeners must select an address assigned to this guest')
    if app.get('kind') == 'db-tools':
        stack = json.loads(Path(app['stack_config']).read_text())
        if stack.get('pgadmin_bind_address') not in [nic['ipv4'].split('/')[0] for nic in cfg['guest']['interfaces']]:
            raise ValueError('pgAdmin must select a backend address assigned to this guest')
    for key in ('state_root', 'backup_mount', 'backup_directory', 'api_token', 'ca_file', 'private_key', 'known_hosts'):
        if not Path(cfg['paths'][key]).is_absolute():
            raise ValueError(f'{key} must be an absolute private runner path')
    backup = Path(cfg['paths']['backup_directory']).resolve()
    mount = Path(cfg['paths']['backup_mount']).resolve()
    if mount == backup or mount not in backup.parents:
        raise ValueError('State recovery copies must be below the declared NAS mount')
    if not cfg['site']['api_endpoint'].startswith('https://'):
        raise ValueError('Use the trusted TLS API endpoint')
    return vmid


def input_hashes(cfg):
    """Bind external configuration and trust files as well as the top-level site JSON."""
    paths = [cfg['paths']['ca_file']]
    app = cfg['app']
    if 'stack_config' in app:
        paths.append(app['stack_config'])
        stack = json.loads(Path(app['stack_config']).read_text())
        paths.extend(foundation.source_files(stack))
    paths.extend(item['key_path'] for item in app.get('repositories', []))
    paths.extend(item['source'] for item in app.get('database', {}).get('config_files', []))
    return {path: sha(path) for path in sorted(set(paths))}


def api_get(cfg, path):
    """Read only the declared Proxmox endpoint, with its existing CA and token."""
    endpoint = urlparse(cfg['site']['api_endpoint'])
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.port != 8006 or endpoint.username:
        raise ValueError('Guest discovery requires the trusted Proxmox HTTPS endpoint')
    if not path.startswith('/nodes/'):
        raise ValueError('Use the selected Proxmox node API')
    request = Request('https://' + endpoint.netloc + '/api2/json' + path,
                      headers={'Authorization': 'PVEAPIToken=' + Path(cfg['paths']['api_token']).read_text().strip()})
    context = ssl.create_default_context(cafile=cfg['paths']['ca_file'])
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), RefuseRedirects())
    with opener.open(request, timeout=15) as response:
        return json.load(response)['data']


def application_address(cfg):
    """Resolve DHCP from the trusted PVE API and the selected MAC, never a scan."""
    if cfg['app']['address'] != 'dhcp':
        return cfg['app']['address']
    path = '/nodes/' + quote(cfg['site']['node'], safe='') + '/lxc/' + str(cfg['guest']['vmid']) + '/interfaces'
    rows = api_get(cfg, path)
    selected = [row for row in rows if row.get('hwaddr', '').lower() == cfg['app']['mac'].lower()]
    if len(selected) != 1 or not selected[0].get('inet'):
        raise InputNeeded('The selected guest has no IPv4 lease yet; inspect its DHCP reservation before configuration')
    address = ipaddress.ip_interface(selected[0]['inet']).ip
    if address.version != 4 or address.is_loopback or address.is_link_local or address.is_unspecified:
        raise InputNeeded('The selected guest has no usable DHCP IPv4 address')
    return str(address)


def guest_trust(cfg, work):
    """Pin this guest after creation; unrelated known_hosts additions are harmless."""
    address = cfg['app']['address']
    instruction = 'Verify the new guest SSH host key using the trusted Proxmox route, then supply its private known_hosts entry before Ansible'
    if not Path(cfg['paths']['known_hosts']).is_file():
        raise InputNeeded(instruction)
    result = subprocess.run(['ssh-keygen', '-F', address, '-f', cfg['paths']['known_hosts']], capture_output=True, text=True, check=False)
    if result.returncode == 1 and not result.stdout:
        raise InputNeeded(instruction)
    if result.returncode != 0:
        raise InputNeeded('Guest host-key lookup failed; inspect the private known_hosts file before continuing')
    output = result.stdout
    keys = []
    for line in output.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith('@') or not (parts[0] == address or parts[0].startswith('|1|')):
            raise ValueError('Use exact pinned guest host keys; do not introduce a wildcard or SSH CA')
        keys.append(parts[1:3])
    if not keys:
        raise InputNeeded(instruction)
    binding = {'address': address, 'keys': sorted(keys)}
    path = work / 'ssh-trust.json'
    if path.exists():
        if json.loads(path.read_text()) != binding:
            raise ValueError('Guest host trust changed; preserve the old binding for review')
    else:
        write(path, binding)


def quiet(command, environment, log, cwd=None):
    with log.open('ab') as output:
        os.chmod(log, 0o600)
        subprocess.run(command, env=environment, cwd=cwd, stdout=output, stderr=output, check=True)


def backup(cfg, state, label):
    mount = Path(cfg['paths']['backup_mount']).resolve()
    if not os.path.ismount(mount):
        raise ValueError('The declared NAS recovery mount is unavailable; no local fallback')
    actual = subprocess.check_output(['findmnt', '-rn', '-o', 'FSTYPE,SOURCE', '--target', str(mount)], text=True).strip().split()
    if len(actual) != 2 or actual[0] not in {'nfs', 'nfs4', 'cifs'} or actual[1] != cfg['paths']['backup_source']:
        raise ValueError('The recovery mount must match the selected NAS filesystem and source')
    destination = Path(cfg['paths']['backup_directory']) / str(cfg['guest']['vmid'])
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    # A write/read receipt also proves the mount is writable before initial creation.
    stamp = f'{time.time_ns()}-{label}'
    if state.exists():
        target = destination / f'{stamp}.tfstate'
        with state.open('rb') as src, target.open('xb') as dst:
            os.chmod(target, 0o600)
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        if sha(target) != sha(state):
            raise ValueError('State backup readback differs')
        write(destination / f'{stamp}.json', {'sha256': sha(target), 'file': target.name})
    else:
        write(destination / f'{stamp}.json', {'state': 'not-created', 'vmid': cfg['guest']['vmid']})


def _execute_step(action, cfg_path, approved_plan=None):
    os.umask(0o077)
    cfg = json.loads(cfg_path.read_text())
    vmid = validate(cfg)
    work = Path(cfg['paths']['state_root']) / str(vmid)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (work / 'deployment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (work / 'HOLD.json').exists():
            raise ValueError('A failed mutation is held for review; preserve its state and logs')
        state = work / 'terraform.tfstate'
        radio = cfg['app'].get('kind') == 'zigbee2mqtt'
        if radio:
            zigbee_usb.verify_firewall(cfg, api_get)
            if zigbee_usb.stage(cfg) == 'attached':
                zigbee_usb.require_prepared(cfg, work)
                zigbee_usb.verify_live(cfg, api_get)
            elif action not in {'plan', 'apply'}:
                raise InputNeeded('The stopped radio preparation cannot stage/start; finish the operator USB attachment first')
        backup(cfg, state, 'before-' + action)
        environment = os.environ.copy()
        environment.update({'TF_IN_AUTOMATION': '1', 'CHECKPOINT_DISABLE': '1',
                            'SSL_CERT_FILE': cfg['paths']['ca_file'],
                            'PROXMOX_VE_API_TOKEN': Path(cfg['paths']['api_token']).read_text().strip()})
        tofu = ['tofu', '-chdir=' + str(work / 'tofu')]
        logfile = work / f'{time.time_ns()}-{action}.log'
        if action == 'plan':
            shutil.copytree(SOURCE / 'tofu', work / 'tofu', dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('.terraform', '*.tfstate*', '*.tfplan'))
            variables = {k: cfg[k] for k in ('site', 'guest', 'ssh_public_keys')}
            variables['guest'] = dict(zigbee_usb.guest_variables(cfg), routing_labels=discovery.labels(cfg))
            write(work / 'tofu' / 'site.auto.tfvars.json', variables)
            quiet(tofu + ['init', '-input=false', '-lockfile=readonly', '-backend-config=path=' + str(state)], environment, logfile)
            quiet(tofu + ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(work / 'guest.tfplan')], environment, logfile)
            output = subprocess.check_output(tofu + ['show', '-json', str(work / 'guest.tfplan')], env=environment)
            plan_value = json.loads(output)
            check_plan(plan_value, cfg['site']['node'], vmid)
            if radio:
                zigbee_usb.check_plan(plan_value, cfg)
                if zigbee_usb.stage(cfg) == 'prepare':
                    check_merge_create_plan(plan_value, cfg['site']['node'], vmid)
            write(work / 'guest.tfplan.json', plan_value)
            creates_guest = any(row['address'] == 'module.guest.proxmox_virtual_environment_container.guest'
                                and row['change']['actions'] == ['create'] and row['change'].get('before') is None
                                for row in plan_value['resource_changes'])
            receipt = {'plan_sha256': sha(work / 'guest.tfplan'),
                       'plan_json_sha256': sha(work / 'guest.tfplan.json'), 'site_sha256': sha(cfg_path),
                       'source_sha256': source_hash(), 'input_hashes': input_hashes(cfg), 'vmid': vmid,
                       'creates_guest': creates_guest}
            if radio:
                receipt['usb_stage'] = zigbee_usb.stage(cfg)
            write(work / 'plan.json', receipt)
            return receipt
        receipt = json.loads((work / 'plan.json').read_text())
        if receipt['site_sha256'] != sha(cfg_path) or receipt['source_sha256'] != source_hash():
            raise ValueError('Source or site inputs changed; review a new plan')
        if receipt.get('input_hashes') != input_hashes(cfg):
            raise ValueError('Private configuration or trust files changed; review a new plan')
        if action == 'apply':
            if not approved_plan or approved_plan != receipt['plan_sha256'] or approved_plan != sha(work / 'guest.tfplan'):
                raise ValueError('Apply requires the exact reviewed plan SHA256')
            if radio:
                plan_path = work / 'guest.tfplan.json'
                if plan_path.is_symlink() or sha(plan_path) != receipt.get('plan_json_sha256'):
                    raise ValueError('Preserve the matching radio JSON plan before apply')
                selected_plan = json.loads(plan_path.read_text())
                zigbee_usb.check_plan(selected_plan, cfg)
                if zigbee_usb.stage(cfg) == 'prepare':
                    check_merge_create_plan(selected_plan, cfg['site']['node'], vmid)
        elif action not in {'stage', 'start', 'verify'}:
            raise ValueError('Unknown deployment step')
        applied = work / 'applied.json'
        if action == 'apply' and applied.exists() and json.loads(applied.read_text()) == receipt:
            raise ValueError('This saved plan was already applied; prepare a new plan')
        if action != 'apply' and (not applied.exists() or json.loads(applied.read_text()) != receipt):
            raise ValueError('Apply the selected reviewed plan before configuring its guest')
        if action == 'stage' and (work / 'started.json').exists():
            raise ValueError('This guest has already started; stage is only for a new installation')
        if action != 'apply':
            cfg = dict(cfg, app=dict(cfg['app'], address=application_address(cfg)))
            guest_trust(cfg, work)
        # Mark BEFORE a native command: SIGKILL/job cancellation cannot run an
        # exception handler, and local process exit never proves remote closure.
        if action != 'verify':
            write(work / 'HOLD.json', {'action': action, 'vmid': vmid, 'log': str(logfile),
                                      'started_at_ns': time.time_ns(), 'remote_closure': 'unconfirmed'})
        try:
            if action == 'apply':
                window = {'plan_sha256': receipt['plan_sha256'], 'started_at_ns': time.time_ns()}
                write(work / 'apply-window.json', window)
                quiet(tofu + ['apply', '-input=false', '-lock-timeout=30s', str(work / 'guest.tfplan')], environment, logfile)
                write(work / 'apply-window.json', dict(window, finished_at_ns=time.time_ns()))
                write(work / 'applied.json', receipt)
                if radio and zigbee_usb.stage(cfg) == 'prepare':
                    write(work / 'usb-prepared.json', zigbee_usb.prepared_receipt(cfg, state))
            else:
                app = dict(cfg['app'], start_services=(action == 'start'), render_dir=str(work / 'rendered'))
                write(work / 'variables.json', {'app': app,
                      'network_ready_interfaces': required_network_interfaces(cfg)})
                write(work / 'inventory.json', {'application': {'hosts': {app['hostname']: {'ansible_host': app['address'], 'ansible_user': 'root'}}}})
                environment.update({'ANSIBLE_CONFIG': str(SOURCE / 'ansible' / 'ansible.cfg'),
                                    'ANSIBLE_HOST_KEY_CHECKING': 'True',
                                    'ANSIBLE_SSH_ARGS': '-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=' + shlex.quote(cfg['paths']['known_hosts'])})
                playbook = 'verify.yml' if action == 'verify' else 'site.yml'
                quiet(['ansible-playbook', '-i', str(work / 'inventory.json'),
                       '--private-key', cfg['paths']['private_key'], str(SOURCE / 'ansible' / playbook),
                       '--extra-vars', '@' + str(work / 'variables.json')], environment, logfile)
                if action == 'start':
                    write(work / 'started.json', receipt)
            backup(cfg, state, 'after-' + action)
        except (OSError, ValueError, subprocess.CalledProcessError):
            if action != 'verify':
                write(work / 'HOLD.json', {'action': action, 'vmid': vmid, 'log': str(logfile), 'failed_at_ns': time.time_ns()})
            raise
        if action != 'verify':
            (work / 'HOLD.json').unlink()
            sync_directory(work)
        return {'step': action, 'vmid': vmid, 'status': 'passed'}


def execute(action, cfg_path, approved_plan=None):
    """Keep one approved rollout running through all phases, with no retries."""
    os.umask(0o077)
    cfg = json.loads(cfg_path.read_text())
    vmid = validate(cfg)
    if cfg['app'].get('kind') == 'zigbee2mqtt' and action == 'deploy':
        raise InputNeeded('Zigbee uses two stages: plan/apply prepare, operator USB attachment, then plan/apply attached and stage/start/verify')
    if action == 'apply' and cfg['app'].get('kind') == 'zigbee2mqtt':
        capture = cfg['app'].get('capture', {})
        path = Path(capture.get('path', ''))
        if (capture.get('coherent') is not True or path.is_symlink() or not path.is_file()
                or sha(path) != capture.get('sha256')):
            raise InputNeeded('Verify the selected Zigbee capture before creating its guest')
        stack = json.loads(Path(cfg['app']['stack_config']).read_text())
        zigbee2mqtt.check_archive(path, stack['zigbee'])
    work = Path(cfg['paths']['state_root']) / str(vmid)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (work / 'workflow.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        hold = work / 'ROLLOUT-HOLD.json'
        if hold.exists():
            raise InputNeeded('An interrupted rollout is held; review its phase receipts before another job')
        if action != 'deploy':
            return _execute_step(action, cfg_path, approved_plan)
        if (work / 'HOLD.json').exists():
            raise InputNeeded('A failed deployment is held; preserve its state and logs for review')
        if (work / 'applied.json').exists() or (work / 'started.json').exists():
            raise InputNeeded('This guest has already been applied; use verify or review its existing phase receipts')
        plan = json.loads((work / 'plan.json').read_text())
        if (not approved_plan or approved_plan != plan['plan_sha256']
                or sha(work / 'guest.tfplan') != approved_plan
                or plan['site_sha256'] != sha(cfg_path) or plan['source_sha256'] != source_hash()
                or plan.get('input_hashes') != input_hashes(cfg)):
            raise InputNeeded('Deploy needs the exact reviewed plan, source and private inputs')
        if (plan.get('creates_guest') is not True or type(plan.get('vmid')) is not int
                or plan['vmid'] != vmid):
            raise InputNeeded('Deploy requires a saved plan creating this fresh guest; use reviewed steps for an existing installation')
        json_plan = work / 'guest.tfplan.json'
        if (not isinstance(plan.get('plan_json_sha256'), str) or not json_plan.is_file()
                or json_plan.is_symlink() or sha(json_plan) != plan['plan_json_sha256']):
            raise InputNeeded('Deploy needs its matching saved JSON plan; prepare and review a new plan')
        # This entry point is also exposed by the public CLI/workflow template,
        # so its first-install guard cannot depend on the private CD adapter.
        # Individual reviewed apply/start paths retain ordinary convergence.
        try:
            check_merge_create_plan(json.loads(json_plan.read_text()), cfg['site']['node'], vmid)
        except ValueError:
            raise InputNeeded('Deploy needs three fresh creates for the selected guest and node; use reviewed steps for an existing installation') from None
        if cfg['app'].get('kind') not in DATABASE_KINDS:
            if cfg['app'].get('exclusive_writer_confirmed') is not True:
                raise InputNeeded('Confirm the selected service migration and retire its old writers before deploy')
            capture = cfg['app']['capture']
            path = Path(capture['path'])
            if capture.get('coherent') is not True or not path.is_file() or sha(path) != capture['sha256']:
                raise InputNeeded('Finish and verify the selected coherent data capture before creating a guest')
            validate_archive(path)
            if cfg['app'].get('kind') == 'zigbee2mqtt':
                stack = json.loads(Path(cfg['app']['stack_config']).read_text())
                zigbee2mqtt.check_archive(path, stack['zigbee'])
        hosts = Path(cfg['paths']['known_hosts'])
        instruction = 'Supply the deployment account private known_hosts file (regular file, mode 0600) before Deploy'
        try:
            info = hosts.lstat()
        except OSError:
            raise InputNeeded(instruction) from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise InputNeeded(instruction)
        # This marker survives a killed job, including between completed phases.
        # Each original step retains its own native-operation HOLD as well.
        started = time.time_ns()
        results = []
        for step in ('apply', 'identity', 'stage', 'start', 'verify'):
            write(hold, {'step': step, 'vmid': vmid, 'plan_sha256': approved_plan,
                         'started_at_ns': started, 'automatic_retry': False})
            if step == 'identity':
                address = application_address(cfg)
                try:
                    result = guest_identity.pin(cfg, work, address, lambda path: api_get(cfg, path), write)
                except ValueError as error:
                    raise InputNeeded(f'Guest identity verification failed: {error}') from None
            else:
                result = _execute_step(step, cfg_path, approved_plan)
            results.append({'step': step, 'result': result})
        receipt = {'step': 'deploy', 'vmid': vmid, 'status': 'passed',
                   'plan_sha256': approved_plan, 'steps': results}
        write(work / 'rollout-complete.json', receipt)
        hold.unlink()
        sync_directory(work)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'deploy', 'apply', 'stage', 'start', 'verify'])
    parser.add_argument('--site', required=True, type=Path)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.action, args.site, args.plan_sha256)))
    except InputNeeded as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        # Logs and inputs can contain secrets; do not emit command output or file contents.
        raise SystemExit(f'Deployment held ({type(error).__name__}); inspect private runner inputs/receipts') from None


if __name__ == '__main__':
    main()
