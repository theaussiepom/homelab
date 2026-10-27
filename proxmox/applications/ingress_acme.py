"""Correct one ingress certificate resolver path through the existing CD state.

The original guest installation stays pinned. OpenTofu owns the four explicit
DNS egress additions; Ansible changes only the mounted Traefik resolver list.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time

RESOURCES = {
    'module.guest.proxmox_virtual_environment_container.guest': 'vm_id',
    'module.guest.proxmox_virtual_environment_firewall_options.guest': 'container_id',
    'module.guest.proxmox_virtual_environment_firewall_rules.guest': 'container_id',
}
RULES = list(RESOURCES)[-1]


def require(value, message):
    """Refuse drift before a broader operation becomes possible."""
    if not value:
        raise ValueError(message)


def resolvers(values):
    """Accept bounded, unique literal unicast resolvers on DNS port53 only."""
    require(isinstance(values, list) and 1 <= len(values) <= 3, 'Select 1-3 DNS resolvers')
    hosts = []
    for value in values:
        require(isinstance(value, str) and value.endswith(':53'), 'Use literal IPv4 DNS port53')
        host = value[:-3]
        ip = ipaddress.IPv4Address(host)
        require(str(ip) == host and not any((ip.is_loopback, ip.is_unspecified, ip.is_multicast, ip.is_link_local))
                and host not in hosts, 'Use unique unicast DNS addresses')
        hosts.append(host)
    return hosts


def candidate(original, before, after):
    """Replace only the selected resolver list; preserve all private contents."""
    resolvers(before); resolvers(after)
    require(before != after, 'Select a different resolver path')
    value = json.loads(original)
    challenge = value['certificatesResolvers']['letsencrypt']['acme']['dnsChallenge']
    require(challenge['provider'] == 'cloudflare' and challenge['resolvers'] == before,
            'Installed certificate resolver differs')
    challenge['resolvers'] = after
    return (json.dumps(value, indent=2) + '\n').encode()


def provider_rules(values):
    """Describe the exact provider representation of the permitted additions."""
    return [dict(type='out', action='ACCEPT', proto=proto, dport='53', dest=host + '/32',
                 comment='Selected ACME recursive DNS') for host in resolvers(values) for proto in ('udp', 'tcp')]


def guest_rules(values):
    """Use the same guest module inputs as normal OpenTofu deployments."""
    return [dict(direction='out', proto=row['proto'], port='53', destination=row['dest'],
                 comment=row['comment']) for row in provider_rules(values)]


def check_plan(value, node, vmid, selected, completed=False):
    """Reject all container changes and firewall edits beyond the DNS append."""
    rows = value.get('resource_changes', [])
    require(type(vmid) is int and vmid >= 100 and vmid not in {900,4914,4915,4920}
            and len(rows) == len(RESOURCES) and {r.get('address') for r in rows} == set(RESOURCES),
            'Use only the existing ingress and its two firewall resources')
    for row in rows:
        change = row['change']; before = change.get('before'); after = change.get('after')
        def unknown(value):
            if isinstance(value,dict):return any(unknown(v) for v in value.values())
            if isinstance(value,list):return any(unknown(v) for v in value)
            return bool(value)
        require(not unknown(change.get('after_unknown',{})), 'All saved DNS plan values must be known')
        require(isinstance(before, dict) and isinstance(after, dict), 'No guest creation or adoption')
        field = RESOURCES[row['address']]
        require(all(str(v[field]) == str(vmid) and v['node_name'] == node for v in (before,after)),
                'Wrong firewall or guest identity')
        if row['address'] != RULES or completed:
            require(change['actions'] == ['no-op'] and before == after, 'No other resource change admitted')
            continue
        require(change['actions'] == ['update'] and {k:v for k,v in before.items() if k != 'rule'} ==
                {k:v for k,v in after.items() if k != 'rule'}, 'Only firewall rules may change')
        expected = provider_rules(selected)
        require(after['rule'][:len(before['rule'])] == before['rule']
                and len(after['rule']) == len(before['rule']) + len(expected), 'Existing firewall rules differ')
        for actual, wanted in zip(after['rule'][len(before['rule']):], expected):
            require(all(actual.get(k) == v for k,v in wanted.items()), 'Wrong DNS rule scope')
            require(all(v in (None,'') or (k == 'enabled' and v is True) or (k == 'log' and v == 'nolog')
                        for k,v in actual.items() if k not in wanted), 'Additional firewall rule authority')
    if completed:
        rules = next(row for row in rows if row['address'] == RULES)['change']['after']['rule']
        expected = provider_rules(selected)
        require(len(rules) >= len(expected) and all(all(actual.get(k) == v for k,v in wanted.items())
                for actual,wanted in zip(rules[-len(expected):],expected)), 'Completed DNS rules differ')


def run(deployment, fc, cfg, site, source, selected, state_root):
    """Apply one claimed correction with the canonical state and pinned identity."""
    import fcntl
    import foundation_maintenance as maintenance
    work = state_root / str(selected['vmid'])
    with (work / 'deployment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        maintenance.expected(deployment, fc, cfg, site, work, selected)
        require(cfg['app']['kind'] == 'ingress' and not any((work / n).exists() or (work / n).is_symlink()
                for n in fc.HOLDS), 'Existing ingress is not completed or is held')
        require(deployment.sha(work / 'foundation-complete.json') == selected['foundation_complete_sha256'],
                'Completed ingress receipt changed')
        operation = work / ('acme-resolvers-' + hashlib.sha256(fc.encoded(selected)).hexdigest()[:16])
        done = operation / 'complete.json'; claim = operation / 'claim.json'
        nas = Path(cfg['paths']['backup_directory']) / str(selected['vmid'])
        if not operation.exists():
            require(deployment.sha(work / 'terraform.tfstate') == selected['state_sha256'], 'Original state changed')
            operation.mkdir(mode=0o700)
            fc.write_new(claim, fc.encoded(selected))
            deployment.backup(cfg, work / 'terraform.tfstate', 'before-acme-resolver-update')
            fc.write_new(nas / (operation.name + '-claim.json'), fc.encoded(selected))
        else:
            completion = json.loads(fc.regular(done, private=True))  # A failed claim never replays.
            require(completion['packet'] == selected and fc.regular(claim, private=True) == fc.encoded(selected)
                    and deployment.sha(work / 'terraform.tfstate') == completion['state_sha256']
                    and fc.regular(nas / (operation.name + '-complete.json'), private=True) == fc.regular(done, private=True),
                    'Completed resolver correction custody differs')
        completed = done.exists()
        evidence = operation / ('verify-' + str(time.time_ns()) if completed else 'attempt')
        evidence.mkdir(mode=0o700)
        tofu_dir = evidence / 'tofu'
        shutil.copytree(source / 'tofu', tofu_dir, ignore=shutil.ignore_patterns('.terraform','*.tfstate*','*.tfplan'))
        variables = {k: copy.deepcopy(cfg[k]) for k in ('site','guest','ssh_public_keys')}
        variables['guest']['routing_labels'] = deployment.discovery.labels(cfg)
        variables['guest']['rules'] += guest_rules(selected['after'])
        fc.write_new(tofu_dir / 'site.auto.tfvars.json', fc.encoded(variables))
        env = os.environ.copy()
        env.update(TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1', SSL_CERT_FILE=cfg['paths']['ca_file'],
                   PROXMOX_VE_API_TOKEN=Path(cfg['paths']['api_token']).read_text().strip(), LC_ALL='C.UTF-8', LANG='C.UTF-8')
        tofu = ['tofu','-chdir='+str(tofu_dir)]; log = evidence / 'tofu.log'; plan = evidence / 'dns.tfplan'
        deployment.quiet(tofu + ['init','-input=false','-lockfile=readonly','-backend-config=path='+str(work/'terraform.tfstate')],env,log)
        deployment.quiet(tofu + ['plan','-input=false','-lock-timeout=30s','-out='+str(plan)],env,log)
        value = json.loads(subprocess.check_output(tofu + ['show','-json',str(plan)],env=env,timeout=60))
        fc.write_new(evidence / 'dns.tfplan.json',fc.encoded(value))
        check_plan(value,cfg['site']['node'],selected['vmid'],selected['after'],completed)
        plan_hash = deployment.sha(plan)
        fc.write_new(evidence / 'reviewed-plan.json',fc.encoded({'plan_sha256':plan_hash,'scope':'DNS egress additions only'}))
        if not completed:
            require(deployment.sha(plan) == plan_hash, 'Saved DNS plan changed')
            deployment.quiet(tofu + ['apply','-input=false','-lock-timeout=30s',str(plan)],env,log)
            deployment.backup(cfg,work/'terraform.tfstate','after-acme-firewall-update')
        address = deployment.application_address(cfg)
        require(address == cfg['app']['address'], 'No alternate ingress address')
        deployment.guest_identity.pin(cfg,evidence,address,lambda path: deployment.api_get(cfg,path),deployment.write)
        fc.write_new(evidence/'inventory.json',fc.encoded({'application':{'hosts':{cfg['app']['hostname']:{'ansible_host':address,'ansible_user':'root'}}}}))
        fc.write_new(evidence/'variables.json',fc.encoded({'app':cfg['app'],'acme_settings':selected,'acme_verify_only':completed}))
        env.update(ANSIBLE_CONFIG=str(source/'ansible/ansible.cfg'),ANSIBLE_HOST_KEY_CHECKING='True',
            ANSIBLE_SSH_ARGS='-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no '
            '-o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes '
            '-o UserKnownHostsFile='+shlex.quote(cfg['paths']['known_hosts']))
        deployment.quiet(['ansible-playbook','-i',str(evidence/'inventory.json'),'--private-key',cfg['paths']['private_key'],
            str(source/'ansible/component-acme.yml'),'--extra-vars','@'+str(evidence/'variables.json')],env,evidence/'ansible.log')
        if not completed:
            completion = fc.encoded({'packet':selected,'state_sha256':deployment.sha(work/'terraform.tfstate')})
            fc.write_new(done,completion);fc.write_new(nas/(operation.name+'-complete.json'),completion)
        return {'status':'passed','changed':not completed}
