"""One bounded member operation for the coordinated database-network CD job.

Each invocation loads one guest's unchanged commissioned installer in a fresh
process. Runtime adapters and shared network code have independent source pins.
All results and Ansible logs stay in the existing private runner state tree.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import database_network_apply as network_apply
import database_network_maintenance as maintenance
from database_network_cutover import private_directory

PLAYBOOKS = {'postgresql': 'postgresql-network.yml',
             'identity': 'identity-database-network.yml', 'db-tools': 'pgadmin-database-network.yml'}
UNITS = {'postgresql': 'postgresql@.service', 'identity': 'docker.service', 'db-tools': 'docker.service'}
STATE = Path('/var/lib/homelab-applications')
INPUTS = Path('/var/lib/homelab-inputs')
require, regular, encoded, digest = maintenance.require, maintenance.regular, maintenance.encoded, maintenance.digest


def source_revision(path, revision):
    require(subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'],
            text=True, timeout=10).strip() == revision, 'An independent source checkout differs from its pin')


def save(path, raw):
    if path.exists() or path.is_symlink():
        require(regular(path) == raw, 'Existing member custody differs')
    else:
        maintenance.write_new(path, raw)


def site_path(role):
    return INPUTS / ('postgresql.json' if role == 'postgresql' else 'foundation-' + role + '/site.json')


def startup_probe(deployment, cfg, expected):
    """Read only the two fixed startup files over the existing pinned SSH key."""
    deployment.guest_trust(cfg, STATE / str(cfg['guest']['vmid']))
    script = '''import hashlib,json,os,pathlib,stat,sys
v=json.load(sys.stdin); paths=['/etc/systemd/system/homelab-network-ready.service','/etc/systemd/system/'+v['unit']+'.d/homelab-network-ready.conf']; out={}
for key,name in zip(['gate_sha256','dependency_sha256'],paths):
 p=pathlib.Path(name); assert not any(x.is_symlink() for x in [p,*p.parents]); s=p.stat(); assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o644 and s.st_size<16384
 out[key]=hashlib.sha256(p.read_bytes()).hexdigest()
print(json.dumps(out))'''
    argv = ['ssh', '-F', '/dev/null', '-i', cfg['paths']['private_key'], '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'UserKnownHostsFile=' + cfg['paths']['known_hosts'], '-o', 'BatchMode=yes',
            '-o', 'ControlMaster=no', '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no',
            '-o', 'ConnectTimeout=10', 'root@' + cfg['app']['address'], 'python3 -c ' + shlex.quote(script)]
    result = subprocess.run(argv, input=encoded({'unit': UNITS[cfg['app']['kind']]}),
                            capture_output=True, check=True, timeout=30)
    require(len(result.stdout) < 4096, 'Oversized startup metadata')
    observed = json.loads(result.stdout)
    require(set(observed) == {'gate_sha256', 'dependency_sha256'}
            and (expected is None or observed == expected), 'The bound startup files differ')
    return observed


def ansible(deployment, cfg, source, playbook, variables, directory, label):
    stamp = str(time.time_ns())
    inventory, values = directory / ('inventory-' + stamp + '.json'), directory / ('variables-' + stamp + '.json')
    maintenance.write_new(inventory, encoded({'application': {'hosts': {cfg['app']['hostname']: {
        'ansible_host': cfg['app']['address'], 'ansible_user': 'root'}}}}))
    maintenance.write_new(values, encoded(variables))
    environment = os.environ.copy()
    environment.update(LC_ALL='C.UTF-8', LANG='C.UTF-8',
        ANSIBLE_CONFIG=str(source / 'proxmox/applications/ansible/ansible.cfg'),
        ANSIBLE_HOST_KEY_CHECKING='True', ANSIBLE_SSH_ARGS='-F /dev/null -o StrictHostKeyChecking=yes '
        '-o BatchMode=yes -o ControlMaster=no -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no '
        '-o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=' + shlex.quote(cfg['paths']['known_hosts']))
    deployment.guest_trust(cfg, STATE / str(cfg['guest']['vmid']))
    with (directory / (label + '-' + stamp + '.log')).open('xb') as log:
        os.chmod(log.name, 0o600)
        subprocess.run(['ansible-playbook', '-i', str(inventory), '--private-key', cfg['paths']['private_key'],
            str(source / 'proxmox/applications/ansible' / playbook), '--extra-vars', '@' + str(values)],
            env=environment, stdout=log, stderr=log, check=True, timeout=240, umask=0o077)


def runtime(deployment, cfg, adapter, role, member, directory, action, quiesce_receipt=None):
    output = directory / (action + '-' + str(time.time_ns()) + '.json')
    request = member['runtime_packet']
    if role == 'db-tools' and action in {'activate', 'verify'}:
        require(quiesce_receipt is not None, 'Bind the common pgAdmin quiesce result before profile access')
        receipt = json.loads(regular(quiesce_receipt))
        require(receipt.get('phase') == 'quiesce' and receipt.get('role') == role
                and receipt.get('result', {}).get('status') == 'passed'
                and receipt['result'].get('action') == 'quiesce'
                and isinstance(receipt['result'].get('quiesced'), dict), 'The common quiesce phase differs')
        request = dict(request, quiesced=receipt['result']['quiesced'])
    values = {'app': cfg['app'], 'database_network_action': action,
              'database_network_request': request, 'database_network_result_path': str(output)}
    if role == 'postgresql':
        values = {'app': cfg['app'], 'postgres_runtime_mode': action,
                  'postgres_runtime_request': member['runtime_packet'], 'postgres_runtime_output': str(output)}
    ansible(deployment, cfg, adapter, PLAYBOOKS[role], values, directory, action)
    return json.loads(regular(output))


def execute(action, role, member, helper, installer, adapter, catalogue, operation, client_vmids, quiesce_receipt=None):
    source_revision(installer, member['installer_revision']); source_revision(adapter, member['adapter_revision'])
    # The current helper's pure imports resolve before the original installer.
    require('deploy' not in sys.modules, 'Use a fresh process for each commissioned installer')
    sys.modules.pop('site_config', None)
    sys.path.insert(0, str(installer / 'proxmox/applications'))
    deployment = importlib.import_module('deploy')
    require(Path(deployment.__file__).resolve() == installer / 'proxmox/applications/deploy.py',
            'The loaded commissioned installer differs')
    site = site_path(role); cfg = json.loads(regular(site)); deployment.validate(cfg)
    require(cfg['app']['kind'] == role and cfg['guest']['vmid'] == member['vmid']
            and cfg['paths']['state_root'] == str(STATE) and cfg['app']['address'] != 'dhcp',
            'Use the original fixed management identity and state directory')
    work = STATE / str(member['vmid']); private_directory(work)
    directory = work / ('database-network-runtime-' + operation)
    if not directory.exists(): directory.mkdir(mode=0o700)
    private_directory(directory)
    network_packet = directory / 'network-packet.json'
    save(network_packet, encoded(member['network_packet']))
    args = (deployment, site, catalogue, work / member['plan_directory'], network_packet, digest(regular(network_packet)))
    if action == 'preflight':
        context = network_apply.load(*args)
        bind_runtime(role, member['runtime_packet'], context, adapter, client_vmids)
        with network_apply.locked(context):
            network_apply.no_holds(context)
            network_apply.admission(deployment, context)
        startup_probe(deployment, cfg, member['startup'])
        checked = runtime(deployment, cfg, adapter, role, member, directory, 'preflight')
        require(checked.get('status') == 'passed', 'The runtime did not pass preflight')
        return {'status': 'admitted', 'vmid': member['vmid']}
    if action == 'network':
        result = network_apply.apply(*args)
        return {'status': result['status'], 'vmid': member['vmid'], 'service_acceptance_verified': False}
    if action == 'startup':
        context = network_apply.load(*args)
        bind_runtime(role, member['runtime_packet'], context, adapter, client_vmids)
        candidate = context['candidate']
        values = {'app': cfg['app'], 'network_ready_interfaces': ['eth' + str(i) for i, nic in
                  enumerate(candidate['interfaces']) if nic['ipv4'] != 'manual'],
                  'network_ready_gate_sha256': member['startup']['gate_sha256'],
                  'network_ready_dependency_sha256': member['startup']['dependency_sha256']}
        if role == 'postgresql':
            cluster = member['runtime_packet']['before']['cluster']
            values['postgresql_cluster_unit'] = 'postgresql@' + str(cluster['major']) + '-' + cluster['name'] + '.service'
        ansible(deployment, cfg, helper, 'network-update.yml', values, directory, action)
        result = startup_probe(deployment, cfg, None)
        save(directory / 'startup-after.json', encoded(result))
        return {'status': 'passed', 'vmid': member['vmid'], **result}
    if action == 'verify':
        network_apply.verify(*args)
        startup_probe(deployment, cfg, json.loads(regular(directory / 'startup-after.json')))
        return runtime(deployment, cfg, adapter, role, member, directory, 'verify', quiesce_receipt)
    require(action in {'quiesce', 'activate'} and (action != 'quiesce' or role != 'postgresql'),
            'Select only a declared member phase')
    return runtime(deployment, cfg, adapter, role, member, directory, action, quiesce_receipt)


def bind_runtime(role, packet, context, adapter, client_vmids):
    request = context['request']
    require(request['engine'] == 'postgresql' and request['phase'] == 'cutover'
            and len(client_vmids) == len(set(client_vmids)) == 2
            and sorted(request['client_vmids']) == sorted(client_vmids),
            'The saved plan must select exactly both coordinated clients')
    import database_networks
    from database_network_server import clients
    catalogue = json.loads(context['catalogue_raw'])
    endpoint = database_networks.endpoint(catalogue, 'postgresql')
    if role == 'postgresql':
        require(packet.get('endpoint') == endpoint
                and packet.get('old_address') == request['legacy_server_address']
                and packet.get('clients') == clients(catalogue, 'postgresql', sorted(client_vmids)),
                'The server runtime endpoint/client set differs from its exact network plan')
    else:
        # Each owner validates its own closed runtime schema, avoiding duplicate
        # Authentik or pgAdmin schema/credential logic in the common coordinator.
        sys.path.insert(0, str(adapter / 'proxmox/applications'))
        module = importlib.import_module({'identity': 'identity_database_runtime',
                                          'db-tools': 'pgadmin_database_runtime'}[role])
        require(module.validate_binding(packet, catalogue, sorted(client_vmids), request['legacy_server_address']) is True,
                'The client runtime differs from the catalogue/group network operation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('preflight', 'quiesce', 'network', 'startup', 'activate', 'verify'), required=True)
    parser.add_argument('--role', choices=PLAYBOOKS, required=True)
    parser.add_argument('--member', type=Path, required=True)
    parser.add_argument('--installer', type=Path, required=True)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--catalogue', type=Path, required=True)
    parser.add_argument('--operation', required=True)
    parser.add_argument('--client-vmid', type=int, action='append', required=True)
    parser.add_argument('--quiesce-receipt', type=Path)
    args = parser.parse_args(); os.umask(0o077)
    try:
        import re
        require(re.fullmatch(r'postgresql-[a-z0-9][a-z0-9-]{0,63}', args.operation), 'Invalid operation identity')
        member = json.loads(regular(args.member))
        result = execute(args.action, args.role, member, Path(__file__).resolve().parents[2],
                         args.installer.resolve(), args.adapter.resolve(), args.catalogue, args.operation,
                         args.client_vmid, args.quiesce_receipt)
        print(json.dumps(result))
    except Exception as error:
        raise SystemExit('Member operation held (' + type(error).__name__ + '); preserve private group evidence') from None


if __name__ == '__main__': main()
