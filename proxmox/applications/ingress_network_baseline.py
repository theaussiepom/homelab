"""Opt-in accepted ACME baseline for one ingress's additive Influx network.

Original installation inputs stay immutable. This file is read-only custody and
projection logic; it has no plan, apply, state rewrite or guest lifecycle action.
"""
import copy
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import database_network_maintenance as maintenance
import ingress_acme as acme

SCHEMA = 'homelab-ingress-acme-network-baseline-v1'
FILES = {'claim.json', 'complete.json', 'attempt/dns.tfplan', 'attempt/dns.tfplan.json',
         'attempt/reviewed-plan.json', 'attempt/tofu/site.auto.tfvars.json'}
CONFIRMATION = {'confirmation-claim.json', 'confirmation-complete.json'}
require = maintenance.require
encoded = maintenance.encoded
digest = maintenance.digest


def directory(path, *, private=True):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) in ({0o700} if private else {0o700,0o755}),
            'Use existing private baseline custody without symlinks')


def read(path, stop):
    require(path.is_relative_to(stop) and '..' not in path.parts, 'Baseline evidence is outside its custody')
    parent = path.parent
    while True:
        directory(parent, private=parent == stop)
        if parent == stop: break
        parent = parent.parent
    with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 16*1024*1024,
                'Use bounded owned private regular baseline evidence')
        return stream.read(16*1024*1024+1)


def nas_root(cfg):
    mount = Path(cfg['paths']['backup_mount']).resolve()
    require(os.path.ismount(mount), 'The original NAS custody mount is unavailable')
    lines = subprocess.check_output(['findmnt','-rn','-o','FSTYPE,SOURCE','--target',str(mount)],
                                    text=True, timeout=15).strip().splitlines()
    rows = [line.split() for line in lines if line.split() and line.split()[0] in {'nfs','nfs4','cifs'}]
    require(len(rows) == 1 and len(rows[0]) == 2 and rows[0][1] == cfg['paths']['backup_source'],
            'The original NAS custody mount identity differs')
    root = Path(cfg['paths']['backup_directory']) / str(cfg['guest']['vmid'])
    require(mount in root.resolve().parents, 'Keep baseline custody under the original NAS mount')
    directory(root)
    return root


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)


def scope(cfg, engine, phase, client_vmids, legacy_server_address):
    require(cfg['guest']['vmid'] == cfg['app']['vmid'] == 212 and cfg['app']['kind'] == 'ingress'
            and engine == 'influxdb' and phase == 'additive' and client_vmids == [212]
            and legacy_server_address is None,
            'The accepted ingress baseline belongs only to its additive Influx client operation')


def state_values(raw):
    state = json.loads(raw); result = {}
    require(isinstance(state.get('lineage'), str) and state['lineage'] and type(state.get('serial')) is int,
            'Bind the exact original state lineage and serial')
    for row in state.get('resources', []):
        if row.get('mode') == 'data': continue
        address = row.get('module', '') + '.' + row.get('type', '') + '.' + row.get('name', '')
        require(row.get('mode') == 'managed' and address in maintenance.RESOURCES
                and address not in result and len(row.get('instances', [])) == 1,
                'No additional or ambiguous managed baseline state resources')
        instance = row['instances'][0]
        require(not instance.get('deposed') and 'index_key' not in instance, 'No replaced or indexed baseline resources')
        result[address] = instance['attributes']
    require(set(result) == set(maintenance.RESOURCES), 'Expected the original ingress and its firewall state')
    return state, result


def load(cfg, work, reference, *, current=False):
    require(isinstance(reference, dict) and set(reference) == {'path','sha256'} and sha(reference['sha256'])
            and reference['path'] == str(work/'ingress-acme-network-baseline.json'),
            'Bind the exact private accepted-ACME baseline manifest')
    raw = read(Path(reference['path']), work)
    require(digest(raw) == reference['sha256'], 'Accepted ingress baseline manifest changed')
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == {'schema','vmid','operation','files','state_before','state_after'}
            and value['schema'] == SCHEMA and value['vmid'] == cfg['guest']['vmid'] == 212
            and cfg['app']['kind'] == 'ingress' and cfg['app']['vmid'] == 212
            and isinstance(value['operation'],str) and re.fullmatch('acme-resolvers-[0-9a-f]{16}',value['operation'])
            and isinstance(value['files'],dict) and set(value['files']) in (FILES, FILES|CONFIRMATION)
            and all(sha(v) for v in value['files'].values()), 'Use the closed accepted ingress ACME baseline')
    operation = work/value['operation']; directory(operation); nas = nas_root(cfg)
    rows = {name: read(operation/name, work) for name in value['files']}
    require(all(digest(rows[name]) == wanted for name,wanted in value['files'].items()),
            'Accepted ACME evidence changed')
    complete = json.loads(rows['complete.json']); selected = json.loads(rows['claim.json'])
    foundation = json.loads(read(work/'foundation-complete.json',work))
    from foundation_maintenance import packet
    packet(selected)
    require(selected['schema'] == 'homelab-ingress-acme-update-v1' and selected['vmid'] == 212
            and len(selected['after']) == 2 and set(complete) == {'packet','state_sha256'}
            and complete['packet'] == selected and sha(complete['state_sha256'])
            and value['operation'] == 'acme-resolvers-' + digest(encoded(selected['after']))[:16]
            and digest(read(work/'foundation-complete.json',work)) == selected['foundation_complete_sha256']
            and json.loads(read(work/'plan.json',work))['plan_sha256'] == selected['plan_sha256'],
            'The accepted ACME operation differs from the original completed ingress')
    require(foundation.get('status') == 'passed' and foundation.get('binding',{}).get('vmid') == 212
            and foundation['binding'].get('guest') == 'ingress'
            and foundation.get('plan_sha256') == selected['plan_sha256'], 'The original ingress completion is not accepted')
    for name in ('claim.json','complete.json'):
        require(read(nas/(value['operation']+'-'+name), nas) == rows[name], 'Accepted ACME NAS custody differs')
    present = [(operation/name).exists() or (operation/name).is_symlink() for name in CONFIRMATION]
    require(all(present) or not any(present), 'Preserve an incomplete resolver confirmation')
    confirms = all(present)
    require(confirms == (set(value['files']) == FILES|CONFIRMATION), 'Bind the existing confirmation explicitly')
    if confirms:
        confirmation = json.loads(rows['confirmation-claim.json']); packet(confirmation)
        require(confirmation['schema'] == 'homelab-ingress-acme-confirmation-v1'
                and confirmation['update'] == selected and confirmation['state_sha256'] == complete['state_sha256']
                and rows['confirmation-claim.json'] == rows['confirmation-complete.json'],
                'Accepted resolver confirmation differs')
        for name,wanted in confirmation['failure_hashes'].items():
            require(digest(read(operation/name,work)) == wanted, 'Preserve the original failed ACME evidence')
        require(all(read(nas/(value['operation']+'-'+name),nas) == rows[name] for name in CONFIRMATION),
                'Accepted confirmation NAS custody differs')
    snapshots = {}
    for key, label, expected in [('state_before','before-acme-resolver-update',selected['state_sha256']),
                                  ('state_after','after-acme-firewall-update',complete['state_sha256'])]:
        row = value[key]
        require(isinstance(row,dict) and set(row) == {'file','sha256','receipt_sha256'}
                and isinstance(row['file'],str) and re.fullmatch('[0-9]+-'+label+r'\.tfstate',row['file'])
                and row['sha256'] == expected and sha(row['receipt_sha256']), 'Bind exact before/after ACME state backups')
        snapshots[key] = read(nas/row['file'],nas)
        receipt_raw = read((nas/row['file']).with_suffix('.json'),nas)
        require(digest(snapshots[key]) == expected and digest(receipt_raw) == row['receipt_sha256']
                and json.loads(receipt_raw) == {'sha256':expected,'file':row['file']}, 'ACME state backup custody differs')
    before, before_values = state_values(snapshots['state_before'])
    after, after_values = state_values(snapshots['state_after'])
    require(before['lineage'] == after['lineage'] and after['serial'] > before['serial'], 'ACME state ancestry differs')
    shown = json.loads(rows['attempt/dns.tfplan.json'])
    acme.check_plan(shown,cfg['site']['node'],212,selected['after'])
    maintenance.validate_provider_drift(shown)
    reviewed = json.loads(rows['attempt/reviewed-plan.json'])
    require(reviewed == {'plan_sha256':digest(rows['attempt/dns.tfplan']),'scope':'DNS egress additions only'},
            'The accepted saved DNS plan binding differs')
    for row in shown['resource_changes']:
        address = row['address']; change = row['change']
        require(maintenance.provider_values_equal(address,before_values[address],change['before'])
                and maintenance.provider_values_equal(address,after_values[address],change['after']),
                'Saved DNS plan differs from accepted state snapshots')
    guest = copy.deepcopy(cfg['guest']); guest['rules'] += acme.guest_rules(selected['after'])
    variables = {key:copy.deepcopy(cfg[key]) for key in ('site','guest','ssh_public_keys')}
    variables['guest'] = copy.deepcopy(guest)
    original_vars = json.loads(read(work/'tofu/site.auto.tfvars.json',work))
    if 'routing_labels' in original_vars['guest']:
        variables['guest']['routing_labels'] = copy.deepcopy(original_vars['guest']['routing_labels'])
    require(json.loads(rows['attempt/tofu/site.auto.tfvars.json']) == variables,
            'Accepted DNS variables contain an unrelated overlay')
    maintenance.expected_container(before_values[maintenance.CONTAINER],cfg['guest'],cfg['guest'])
    require([maintenance.rule_projection(r) for r in before_values[maintenance.RULES]['rule']]
            == [maintenance.normal_rule(r) for r in cfg['guest']['rules']]
            and [maintenance.rule_projection(r) for r in after_values[maintenance.RULES]['rule']]
            == [maintenance.normal_rule(r) for r in guest['rules']], 'Accepted DNS rules differ from exact append')
    if current:
        require(digest(read(work/'terraform.tfstate',work)) == complete['state_sha256'], 'Current ingress state differs from accepted ACME baseline')
    return {'guest':guest,'manifest_raw':raw,'selected':selected,'manifest':value}


def new_rule_template(rows):
    """Copy only the commissioned ordinary outbound TCP provider defaults."""
    templates = [row for row in rows if row.get('type') == 'out' and row.get('proto') == 'tcp'
                 and row.get('dport') == '80,443' and row.get('dest') == '0.0.0.0/0']
    require(len(templates) == 1, 'Bind one existing ordinary outbound TCP rule template')
    row = templates[0]
    semantics = {'type','action','proto','dport','source','dest','comment'}
    defaults = {'enabled','log','pos','iface','macro','security_group','sport'}
    require(set(row) <= semantics|defaults and row.get('action') == 'ACCEPT'
            and row.get('source') in (None,'') and row.get('enabled') is True
            and row.get('log') in (None,'','nolog')
            and all(row.get(name) in (None,'') for name in ('iface','macro','security_group','sport')),
            'No inherited interface, macro, port, log or other rule authority')
    return row


def verify_runtime(deployment, context, directory):
    """Check the accepted resolver on the guest without old ACME ToFu inputs."""
    import shlex
    c = context; cfg = c['cfg']; selected = c['ingress_acme']['selected']
    address = deployment.application_address(cfg)
    require(address == cfg['app']['address'], 'No alternate ingress management address')
    deployment.guest_identity.pin(cfg,directory,address,lambda path:deployment.api_get(cfg,path),deployment.write)
    maintenance.write_new(directory/'ingress-inventory.json',encoded({'application':{'hosts':{cfg['app']['hostname']:{
        'ansible_host':address,'ansible_user':'root'}}}}))
    maintenance.write_new(directory/'ingress-variables.json',encoded({
        'app':cfg['app'],'acme_settings':selected,'acme_verify_only':True}))
    source = Path(__file__).resolve().parent
    environment = os.environ.copy()
    environment.update(LC_ALL='C.UTF-8',LANG='C.UTF-8',ANSIBLE_CONFIG=str(source/'ansible/ansible.cfg'),
        ANSIBLE_HOST_KEY_CHECKING='True',ANSIBLE_SSH_ARGS=
        '-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no '
        '-o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes '
        '-o UserKnownHostsFile='+shlex.quote(cfg['paths']['known_hosts']))
    deployment.quiet(['ansible-playbook','-i',str(directory/'ingress-inventory.json'),'--private-key',
        cfg['paths']['private_key'],str(source/'ansible/component-acme.yml'),
        '--extra-vars','@'+str(directory/'ingress-variables.json')],environment,directory/'ingress-runtime.log')


def helper_files():
    """Seal the opt-in projection and guest-verification dependencies too."""
    source = Path(__file__).resolve().parent
    require(Path(acme.__file__).resolve() == source/'ingress_acme.py', 'Use the selected baseline ACME checker')
    return [source/name for name in ('ingress_network_baseline.py','ingress_acme.py','foundation_maintenance.py',
        'component_acme.py','component_image.py','ansible/component-acme.yml')]
