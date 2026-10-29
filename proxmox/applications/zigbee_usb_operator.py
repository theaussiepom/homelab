#!/usr/bin/env python3
"""Plan/apply one USB attachment through the existing workstation bootstrap SSH.

This separate operator command never reads or copies runner OpenTofu state and
is not called by deployment jobs. Native execution requires its own approval.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from urllib.parse import urlsplit

import zigbee_usb

HERE=Path(__file__).resolve().parent


def authenticated_revision(revision,signer_fingerprint):
    """Require the explicitly reviewed signed commit and its exact source bytes."""
    if not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise ValueError('Select the full reviewed, signed source revision')
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',signer_fingerprint):
        raise ValueError('Supply the SSH signer fingerprint independently approved in the native action packet')
    def git(*args,text=False):
        return subprocess.check_output(['git',*args],cwd=HERE,stderr=subprocess.PIPE,timeout=15,text=text)
    root=Path(git('rev-parse','--show-toplevel',text=True).strip()).resolve()
    if git('rev-parse','HEAD',text=True).strip()!=revision:
        raise ValueError('The operator checkout must be at the exact reviewed revision')
    # Uses the operator's existing trusted Git signer configuration; fail closed.
    git('verify-commit',revision)
    if git('log','-1','--format=%G?',revision,text=True).strip()!='G':
        raise ValueError('The reviewed source must have a good signature from an existing trusted signer')
    if git('log','-1','--format=%GF',revision,text=True).strip()!=signer_fingerprint:
        raise ValueError('The signed source does not match the independently approved signer fingerprint')
    if Path(zigbee_usb.__file__).resolve()!=HERE/'zigbee_usb.py':
        raise ValueError('The loaded USB helper must come from this signed checkout')
    for path in (Path(__file__).resolve(),HERE/'zigbee_usb.py'):
        if path.is_symlink() or path.read_bytes()!=git('show',revision+':'+path.relative_to(root).as_posix()):
            raise ValueError('Operator/helper source differs from the authenticated commit')
    return revision


def write(path,value,exclusive=False):
    """Keep operator plans and uncertain outcomes private and durable."""
    flags=os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|(os.O_EXCL if exclusive else os.O_TRUNC)
    fd=os.open(path,flags,0o600)
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def execute(work,request,key,known_hosts,approved='',revision='',signer_fingerprint=''):
    """Use pinned bootstrap authority, a reviewed live hash and one attempt hold."""
    zigbee_usb.validate_request(request)
    reviewed=authenticated_revision(revision,signer_fingerprint)
    if approved and not re.fullmatch(r'[0-9a-f]{64}',approved):
        raise ValueError('Select the exact reviewed USB plan SHA256')
    for path in (work,key,known_hosts):
        if path.is_symlink() or not path.exists():raise ValueError('Supply the existing bootstrap bundle and pinned SSH files')
    authority=work/'tofu/site.auto.tfvars.json'
    site=json.loads(authority.read_text())['site']
    endpoint=urlsplit(site['api_endpoint'])
    if (site['node']!=request['node'] or endpoint.scheme!='https' or endpoint.port!=8006 or
            not endpoint.hostname or endpoint.username or endpoint.path not in ('','/') or endpoint.query or endpoint.fragment):
        raise ValueError('The radio must use the node and management endpoint already pinned by bootstrap')
    source=(HERE/'zigbee_usb.py').read_text()
    source_hash=hashlib.sha256(source.encode()+Path(__file__).read_bytes()).hexdigest()
    binding={'request':request,'revision':reviewed,'signer_fingerprint':signer_fingerprint,'source_sha256':source_hash,
             'known_hosts_sha256':hashlib.sha256(known_hosts.read_bytes()).hexdigest(),
             'bootstrap_site_sha256':hashlib.sha256(authority.read_bytes()).hexdigest()}
    saved=work/f'zigbee-usb-plan-{request["vmid"]}.json'
    hold=work/f'zigbee-usb-HOLD-{request["vmid"]}.json'
    with (work/'.bootstrap.lock').open('a') as lock:
        os.fchmod(lock.fileno(),0o600)
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (hashlib.sha256(authority.read_bytes()).hexdigest()!=binding['bootstrap_site_sha256'] or
                hashlib.sha256(known_hosts.read_bytes()).hexdigest()!=binding['known_hosts_sha256']):
            raise ValueError('Bootstrap authority or host trust changed while acquiring its lock')
        if hold.exists():raise ValueError('An operator USB attempt is held; preserve its evidence, no replay')
        if approved:
            previous=json.loads(saved.read_text())
            if previous['binding']!=binding or previous['plan']['plan_sha256']!=approved:
                raise ValueError('Review the exact unchanged source, request and operator plan before apply')
            write(hold,{'binding':binding,'plan_sha256':approved,'remote_closure':'unconfirmed','automatic_retry':False},exclusive=True)
        payload={'source':source,'request':request,'apply':approved}
        # Pinned SSH host keys authenticate the host. Its hostname is an
        # additional node consistency check, not the authentication mechanism.
        remote=("import json,os,socket,sys; p=json.loads(sys.argv[1]); "
                "assert os.geteuid()==0 and socket.gethostname().split('.')[0]==p['request']['node']; "
                "n={'__name__':'operator_usb_remote'};exec(compile(p['source'],'operator_usb_remote','exec'),n); "
                "print(json.dumps(n['host_apply'](p['request'],p['apply']) if p['apply'] else n['host_plan'](p['request'])))")
        command=['ssh','-F','/dev/null','-i',str(key),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                 '-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null',
                 '-o','UserKnownHostsFile='+str(known_hosts),'-o','ConnectTimeout=10',
                 'root@'+endpoint.hostname,'python3 -c '+shlex.quote(remote)+' '+shlex.quote(json.dumps(payload))]
        # Timeout or malformed output deliberately leaves HOLD in place.
        result=subprocess.run(command,capture_output=True,text=True,timeout=120)
        write(work/f'zigbee-usb-result-{request["vmid"]}.json',
              {'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'automatic_retry':False})
        if result.returncode or len(result.stdout)>1048576:raise ValueError('Operator USB result is unconfirmed; preserve the hold')
        value=json.loads(result.stdout)
        if approved:
            if (value.get('status')!='attached' or value.get('vmid')!=request['vmid'] or
                    value.get('node')!=request['node'] or value.get('device')!=request['path'] or
                    value.get('guest_stays_stopped') is not True or value.get('protection_changed') is not False):
                raise ValueError('Operator USB readback differs; preserve the hold')
            hold.unlink()
        else:
            if value.get('request')!=request or not re.fullmatch(r'[0-9a-f]{64}',str(value.get('plan_sha256',''))):
                raise ValueError('The operator USB plan did not bind the requested guest')
            write(saved,{'binding':binding,'plan':value})
        return value


def main():
    """Require explicit files; never discover or expand a credential route."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap',required=True,type=Path)
    parser.add_argument('--request',required=True,type=Path)
    parser.add_argument('--ssh-key',required=True,type=Path)
    parser.add_argument('--known-hosts',required=True,type=Path)
    parser.add_argument('--revision',required=True,help='Full reviewed commit, verified with existing trusted Git signers')
    parser.add_argument('--signer-fingerprint',required=True,help='SSH SHA256 signer fingerprint independently approved in the native action packet')
    parser.add_argument('--apply',default='',help='Exact SHA256 from the reviewed operator plan')
    args=parser.parse_args()
    try:
        result=execute(args.bootstrap,json.loads(args.request.read_text()),args.ssh_key,args.known_hosts,args.apply,args.revision,args.signer_fingerprint)
        print(json.dumps({'status':result.get('status','planned'),'plan_sha256':result.get('plan_sha256'),
                          'native_radio_qualified':False,'runner_refresh_required':bool(args.apply)}))
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):
        raise SystemExit('USB operation held; inspect the private operator plan/result and any HOLD before another action') from None


if __name__=='__main__':main()
