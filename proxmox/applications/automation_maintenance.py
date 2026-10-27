"""Complete the selected existing-guest prerequisites through reviewed CD once.

The installation sources and receipts remain frozen. An additive firewall
packet owns its new canonical state; the old ACME records remain immutable
evidence. Failed claims cannot replay under a different source revision.
"""
import argparse
import copy
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

import firewall_append
import automation_oidc
import foundation_maintenance as expected_installation

SOURCE=Path(__file__).resolve().parent


def source_hash():
    names=('automation_maintenance.py','firewall_append.py','automation_oidc.py',
           'foundation_maintenance.py','ansible/automation-ingress.yml','ansible/automation-oidc.yml')
    return hashlib.sha256(b''.join((SOURCE/name).read_bytes() for name in names)).hexdigest()


def require(value,message):
    if not value: raise ValueError(message)


def validate(packet):
    require(isinstance(packet,dict) and set(packet) == {'schema','ingress','identity'}
            and packet['schema'] == 'homelab-automation-maintenance-v1','Use the exact automation prerequisite packet')
    for phase in ('ingress','identity'):
        row=packet[phase]
        common={'vmid','source_revision','plan_sha256','state_sha256','proofs'}
        extra={'retained_rules','additions','runtime_sha256','compose_sha256'} if phase=='ingress' else {'oidc'}
        require(isinstance(row,dict) and set(row) == common|extra and type(row['vmid']) is int
                and row['vmid'] >= 100 and row['vmid'] not in {200,900,4914,4915,4920}
                and re.fullmatch('[0-9a-f]{40}',row['source_revision']), 'Invalid existing guest or frozen source')
        hashes=[row['plan_sha256'],row['state_sha256']]
        require(isinstance(row['proofs'],dict) and {'plan.json','foundation-complete.json','rollout-complete.json'} <= set(row['proofs'])
                and all(re.fullmatch(r'(?:plan|foundation-complete|rollout-complete)\.json|acme-resolvers-[0-9a-f]{16}/(?:complete|confirmation-complete)\.json',p)
                        for p in row['proofs']), 'Use only existing completion proofs')
        hashes.extend(row['proofs'].values())
        if phase=='ingress':
            hashes += [row['runtime_sha256'],row['compose_sha256']]
            require(isinstance(row['retained_rules'],list) and len(row['retained_rules']) == 4,'Retain the four commissioned ACME rules')
            firewall_append.provider_rules(row['additions'])
        else:
            automation_oidc.validate(row['oidc'])
            require(row['oidc']['vmid'] == row['vmid'],'OIDC must select the same identity guest')
        require(all(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) for v in hashes),'Invalid prerequisite evidence hash')
    require(packet['ingress']['vmid'] != packet['identity']['vmid'],'Prerequisites must select distinct existing guests')


def ansible(deployment,fc,cfg,evidence,phase,row,verify):
    app=cfg['app'];address=deployment.application_address(cfg)
    require(address == app['address'],'No alternate prerequisite route')
    deployment.guest_identity.pin(cfg,evidence,address,lambda p:deployment.api_get(cfg,p),deployment.write)
    fc.write_new(evidence/'inventory.json',fc.encoded({'application':{'hosts':{app['hostname']:{'ansible_host':address,'ansible_user':'root'}}}}))
    variables={'app':app,'maintenance_source':str(SOURCE),'maintenance_verify':verify,
               'ingress_settings':row,'oidc_settings':row.get('oidc',{})}
    fc.write_new(evidence/'variables.json',fc.encoded(variables))
    env=os.environ.copy()
    # The original frozen deployment modules predate the shared environment
    # helper. Keep their exact SSH trust controls without changing those sources.
    env.update(LC_ALL='C.UTF-8',LANG='C.UTF-8',ANSIBLE_CONFIG=str(SOURCE/'ansible/ansible.cfg'),
        ANSIBLE_HOST_KEY_CHECKING='True',ANSIBLE_SSH_ARGS='-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no '
        '-o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes '
        '-o UserKnownHostsFile='+shlex.quote(cfg['paths']['known_hosts']))
    deployment.quiet(['ansible-playbook','-i',str(evidence/'inventory.json'),'--private-key',cfg['paths']['private_key'],
        str(SOURCE/'ansible'/('automation-ingress.yml' if phase=='ingress' else 'automation-oidc.yml')),
        '--extra-vars','@'+str(evidence/'variables.json')],env,evidence/'ansible.log')


def ingress(deployment,fc,cfg,row,work,evidence,completed):
    tofu=evidence/'tofu';shutil.copytree(deployment.SOURCE/'tofu',tofu,ignore=shutil.ignore_patterns('.terraform','*.tfstate*','*.tfplan'))
    variables={k:copy.deepcopy(cfg[k]) for k in ('site','guest','ssh_public_keys')}
    variables['guest']['routing_labels']=deployment.discovery.labels(cfg)
    variables['guest']['rules'] += row['retained_rules']+row['additions']
    fc.write_new(tofu/'site.auto.tfvars.json',fc.encoded(variables))
    env=os.environ.copy();env.update(TF_IN_AUTOMATION='1',CHECKPOINT_DISABLE='1',SSL_CERT_FILE=cfg['paths']['ca_file'],
        PROXMOX_VE_API_TOKEN=Path(cfg['paths']['api_token']).read_text().strip(),LC_ALL='C.UTF-8',LANG='C.UTF-8')
    command=['tofu','-chdir='+str(tofu)];plan=evidence/'firewall.tfplan';log=evidence/'tofu.log'
    deployment.quiet(command+['init','-input=false','-lockfile=readonly','-backend-config=path='+str(work/'terraform.tfstate')],env,log)
    deployment.quiet(command+['plan','-input=false','-lock-timeout=30s','-out='+str(plan)],env,log)
    value=json.loads(subprocess.check_output(command+['show','-json',str(plan)],env=env,timeout=60))
    fc.write_new(evidence/'firewall.tfplan.json',fc.encoded(value))
    firewall_append.check_plan(value,cfg['site']['node'],row['vmid'],row['additions'],completed)
    checked=deployment.sha(plan)
    fc.write_new(evidence/'reviewed-plan.json',fc.encoded({'plan_sha256':checked,'scope':'Exact automation backend firewall append only'}))
    if not completed:
        require(deployment.sha(plan) == checked,'Saved prerequisite plan changed')
        deployment.quiet(command+['apply','-input=false','-lock-timeout=30s',str(plan)],env,log)
        deployment.backup(cfg,work/'terraform.tfstate','after-automation-backend-firewall')
    ansible(deployment,fc,cfg,evidence,'ingress',row,completed)


def run(phase,packet,deployment,fc,maintenance,site):
    validate(packet);row=packet[phase];cfg=json.loads(fc.regular(site,private=True))
    work=Path(cfg['paths']['state_root'])/str(row['vmid'])
    with (work/'foundation.lock').open('a') as foundation_lock, (work/'deployment.lock').open('a') as lock:
        fcntl.flock(foundation_lock,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        maintenance.expected(deployment,fc,cfg,site,work,row)
        require(not any((work/n).exists() or (work/n).is_symlink() for n in fc.HOLDS),'Preserve the existing guest hold')
        for name,digest in row['proofs'].items():require(deployment.sha(work/name) == digest,'Existing completion evidence changed')
        operation=work/'automation-200-prerequisite';done=operation/'complete.json'
        binding={'packet':row,'maintenance_source_sha256':source_hash()}
        nas=Path(cfg['paths']['backup_directory'])/str(row['vmid'])
        completed=operation.exists()
        if completed:
            receipt=json.loads(fc.regular(done,private=True))
            require(receipt['binding'] == binding and receipt['state_sha256'] == deployment.sha(work/'terraform.tfstate')
                    and fc.regular(nas/'automation-200-complete.json',private=True) == fc.regular(done,private=True),
                    'Completed prerequisite differs or an earlier attempt remains held; no replay')
        else:
            require(deployment.sha(work/'terraform.tfstate') == row['state_sha256'],'Original prerequisite state changed')
            operation.mkdir(mode=0o700)
            fc.write_new(operation/'claim.json',fc.encoded(binding))
            deployment.backup(cfg,work/'terraform.tfstate','before-automation-prerequisite')
            fc.write_new(nas/'automation-200-claim.json',fc.encoded(binding))
        evidence=operation/('verify-'+str(time.time_ns()) if completed else 'attempt');evidence.mkdir(mode=0o700)
        marker=work/'CONTINUATION-HOLD.json';fc.write_new(marker,fc.encoded(binding))
        if phase=='ingress':ingress(deployment,fc,cfg,row,work,evidence,completed)
        else:ansible(deployment,fc,cfg,evidence,phase,row,completed)
        result={'binding':binding,'state_sha256':deployment.sha(work/'terraform.tfstate')}
        if not completed:
            fc.write_new(done,fc.encoded(result));fc.write_new(nas/'automation-200-complete.json',fc.encoded(result))
        require(fc.regular(marker,private=True) == fc.encoded(binding),'Prerequisite hold ownership changed')
        marker.unlink();fc.sync(work)
        return {'status':'passed','vmid':row['vmid'],'changed':not completed}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=['ingress','identity'],required=True)
    parser.add_argument('--packet',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    try:
        packet=json.loads(args.packet.read_text());validate(packet)
        require(subprocess.check_output(['git','-C',str(args.source),'rev-parse','HEAD'],text=True).strip() ==
                packet[args.phase]['source_revision'],'Original installation source differs')
        sys.path.insert(0,str(args.source.resolve()/'proxmox/applications'))
        deployment,fc=[importlib.import_module(n) for n in ('deploy','foundation_cd')]
        site=Path('/var/lib/homelab-inputs')/('foundation-'+args.phase)/'site.json'
        print(json.dumps(run(args.phase,packet,deployment,fc,expected_installation,site)))
    except Exception:
        raise SystemExit('Automation prerequisite held; retain its private claim, plan and logs. No automatic retry.') from None
