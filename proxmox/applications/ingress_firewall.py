"""Firewall-only ingress successor using the existing saved-plan apply driver.

The accepted ACME and network candidates are read from their completed custody.
Original three-interface installation inputs are never used as the new candidate.
"""
import argparse
import copy
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sys

import database_network_maintenance as m
import ingress_network_baseline as baseline
import ingress_browser as browser

POLICY_SCHEMA='homelab-ingress-egress-policy-v1'
PLAN_SCHEMA='homelab-ingress-egress-plan-v1'
APPLY_SCHEMA='homelab-ingress-egress-apply-v1'
require=m.require


def policy(value):
    require(isinstance(value,dict) and set(value)=={'schema','vmid','rules','baseline'}
            and value['schema']==POLICY_SCHEMA and value['vmid']==212 and type(value['vmid']) is int,
            'Use the closed ingress backend rule policy')
    rules=value['rules']
    require(isinstance(rules,list) and 1<=len(rules)<=2,'Select only the finite reviewed backend rule list')
    ports=[]
    for row in rules:
        require(isinstance(row,dict) and set(row)=={'source','destination','port'}
                and type(row['port']) is int and row['port'] in (8080,5000) and row['port'] not in ports,
                'Select each known backend port at most once')
        ports.append(row['port'])
        for name in ('source','destination'):
            address=ipaddress.IPv4Address(row[name])
            require(str(address)==row[name] and address.is_private and not any((address.is_multicast,
                address.is_loopback,address.is_link_local,address.is_unspecified)),'Use exact private backend IPv4 addresses')
    b=value['baseline'];work=m.STATE/'212'
    require(isinstance(b,dict) and set(b)=={'state_sha256','state_lineage','state_serial','network_overlay',
            'network_plan_directory','catalogue','acme','browser_packet_sha256'}
            and all(baseline.sha(b[k]) for k in ('state_sha256','browser_packet_sha256'))
            and isinstance(b['state_lineage'],str) and b['state_lineage']
            and type(b['state_serial']) is int and b['state_serial']>=0
            and isinstance(b['network_plan_directory'],str)
            and re.fullmatch('database-network-plan-[a-zA-Z0-9-]+',b['network_plan_directory']),
            'Bind the exact accepted ingress successor state and history')
    for name in ('network_overlay','catalogue','acme'):
        row=b[name]
        require(isinstance(row,dict) and set(row)=={'path','sha256'} and baseline.sha(row['sha256'])
                and isinstance(row['path'],str) and '..' not in Path(row['path']).parts
                and Path(row['path']).is_relative_to(work),'Keep accepted evidence in this ingress custody')
    return value


def candidate(guest,value):
    policy(value);nics=guest.get('interfaces',[])
    require(guest.get('vmid')==212 and len(nics)==4 and any(n.get('bridge')=='vmbr33' for n in nics),
            'Preserve the accepted four-interface ingress')
    result=copy.deepcopy(guest)
    for row in value['rules']:
        matches=[n for n in nics if str(ipaddress.IPv4Interface(n['ipv4']).ip)==row['source']]
        require(len(matches)==1,'Derive each unique source from the installed ingress NICs')
        nic=matches[0];backend=ipaddress.IPv4Interface(nic['ipv4']);destination=ipaddress.IPv4Address(row['destination'])
        require((row['port']==8080 and nic.get('bridge')=='vmbr30' and nic.get('vlan') is None)
                or (row['port']==5000 and nic.get('vlan')==25),'Use the established backend or management interface')
        require(destination in backend.network and destination not in
                (backend.ip,backend.network.network_address,backend.network.broadcast_address),
                'Use the installed source and one distinct same-subnet target')
        rule={'direction':'out','proto':'tcp','port':str(row['port']),'source':row['source']+'/32',
              'destination':row['destination']+'/32','comment':'Selected ingress backend'}
        require(rule not in result['rules'],'The selected rule is already present; preserve its accepted operation')
        result['rules'].append(rule)
    return result


def provider_rules(rows,value):
    template=baseline.new_rule_template(rows);result=[]
    for index,row in enumerate(value['rules']):
        rule=copy.deepcopy(template)
        rule.update(type='out',action='ACCEPT',proto='tcp',dport=str(row['port']),
                    source=row['source']+'/32',dest=row['destination']+'/32',comment='Selected ingress backend')
        if 'pos' in rule:rule['pos']=len(rows)+index
        result.append(rule)
    return result


def check_plan(value,node,guest,selected,accepted):
    """Only the exact raw rule append; all other configured values remain equal."""
    candidate(guest,selected)
    rows=value.get('resource_changes',[])
    require(len(rows)==len(m.RESOURCES) and {r.get('address') for r in rows}==set(m.RESOURCES)
            and not value.get('errored') and not value.get('deferred_changes'),'Only the existing ingress and its firewall resources')
    observations=m.validate_provider_drift(value)
    for row in rows:
        address=row['address'];change=row.get('change',{});before=change.get('before');after=change.get('after')
        require(row.get('mode','managed')=='managed' and not row.get('previous_address')
                and not change.get('replace_paths') and not change.get('importing')
                and not m.unknown(change.get('after_unknown',{}))
                and isinstance(before,dict) and isinstance(after,dict),'No unknown, moved, replaced or adopted resource')
        field=m.RESOURCES[address]
        require(all(str(v.get(field))=='212' and v.get('node_name')==node for v in (before,after))
                and m.provider_values_equal(address,before,accepted[address]),'Accepted ingress resource identity or baseline differs')
        if address!=m.RULES:
            require(change.get('actions')==['no-op'] and before==after,'No container, NIC, option or lifecycle changes')
            continue
        m.validate_rule_positions(before);m.validate_rule_positions(after,allow_omitted=range(len(before.get('rule',[])),len(after.get('rule',[]))))
        require(change.get('actions')==['update'] and {k:v for k,v in before.items() if k!='rule'}==
                {k:v for k,v in after.items() if k!='rule'}
                and after.get('rule',[])[:len(before.get('rule',[]))]==before.get('rule')
                and len(after['rule'])==len(before['rule'])+len(selected['rules']),'Preserve every old raw firewall rule and position')
        for index,(actual,wanted) in enumerate(zip(after['rule'][len(before['rule']):],provider_rules(before['rule'],selected))):
            actual=copy.deepcopy(actual)
            if 'pos' in actual and actual['pos'] is None:actual['pos']=len(before['rule'])+index
            # BPG plans represent these unset fields as null for additions and
            # empty strings for existing rules. Compare only these observed
            # defaults; old rules and all semantic fields remain raw-exact.
            for name in ('sport','iface','macro','log','security_group'):
                if name in actual and name in wanted and actual[name] in (None,'') and wanted[name] in (None,''):
                    actual[name]=wanted[name]
            require(actual.get('enabled') is True and actual==wanted,
                    'Only the exact sources, targets, TCP ports and ordinary provider defaults')
    return observations


def accepted(cfg,work,selected):
    """Read the completed network candidate and route custody, never replay them."""
    policy(selected);b=selected['baseline']
    require(cfg['guest']['vmid']==cfg['app']['vmid']==212 and cfg['app']['kind']=='ingress',
            'Use the original commissioned ingress inputs')
    def read(path):return baseline.read(path,work)
    def referenced(row):
        raw=read(Path(row['path']));require(m.digest(raw)==row['sha256'],'Accepted prerequisite bytes changed');return raw
    raw=referenced(b['network_overlay']);overlay=json.loads(raw)
    fields=('request_sha256','review_packet_sha256','candidate_guest_sha256','packet_sha256','state_sha256')
    require(overlay.get('schema')=='homelab-database-network-overlay-v1'
            and overlay.get('status')=='network_overlay_verified' and overlay.get('vmid')==212
            and all(baseline.sha(overlay.get(k)) for k in fields)
            and Path(b['network_overlay']['path'])==work/('database-network-apply-'+overlay['review_packet_sha256'])/'overlay.json',
            'Use the exact accepted network overlay, not an incomplete proposal')
    operation=Path(b['network_overlay']['path']).parent;nas=baseline.nas_root(cfg)
    require(baseline.read(nas/operation.name/'overlay.json',nas)==raw,'Accepted network NAS overlay differs')
    claim=read(operation/'claim.json')
    require(m.digest(claim)==overlay['packet_sha256'] and baseline.read(nas/operation.name/'claim.json',nas)==claim,
            'Accepted network claim custody differs')
    old=work/b['network_plan_directory'];request_raw=read(old/'request.json');review_raw=read(old/'review-packet.json')
    request,review=json.loads(request_raw),json.loads(review_raw)
    require(m.digest(request_raw)==overlay['request_sha256'] and m.digest(review_raw)==overlay['review_packet_sha256']
            and request.get('schema')==m.SCHEMA and request.get('engine')=='influxdb'
            and request.get('phase')=='additive' and request.get('client_vmids')==[212]
            and request.get('vmid')==212 and request.get('legacy_server_address') is None
            and overlay.get('original')==request.get('original') and review.get('status')=='review_required'
            and all(review.get(k)==v for k,v in request.items())
            and request.get('ingress_acme_baseline')==b['acme'],'Accepted network planning ancestry differs')
    catalogue_raw=referenced(b['catalogue'])
    require(m.digest(catalogue_raw)==request['catalogue_sha256'],'Use the accepted operation catalogue')
    shown_raw=read(old/'guest.tfplan.json')
    require(m.digest(shown_raw)==review['plan_json_sha256'] and m.digest(read(old/'guest.tfplan'))==review['plan_sha256'],
            'Accepted saved network plan changed')
    checked=m.check_plan(json.loads(shown_raw),cfg,json.loads(catalogue_raw),'influxdb',phase='additive',
        client_vmids=[212],ingress_acme_baseline=b['acme'])
    guest=checked['candidate_guest']
    require(m.digest(m.encoded(guest))==m.digest(read(old/'candidate-guest.json'))==overlay['candidate_guest_sha256']
            and review['candidate_guest_sha256']==overlay['candidate_guest_sha256'], 'Accepted four-interface candidate differs')
    state_raw=read(operation/'state-after.json');state,values=baseline.state_values(state_raw)
    require(baseline.read(nas/operation.name/'state-after.json',nas)==state_raw
            and m.digest(state_raw)==b['state_sha256']==overlay['state_sha256']
            and state['lineage']==b['state_lineage']==overlay['state_lineage']
            and state['serial']==b['state_serial']==overlay['state_serial'],'Accepted state ancestry or NAS snapshot differs')
    for row in json.loads(shown_raw)['resource_changes']:
        require(m.provider_values_equal(row['address'],row['change']['after'],values[row['address']]),
                'Accepted state differs from the saved network candidate')
    browser_raw=read(work/'influx-browser-route/complete.json')
    require(m.digest(browser_raw)==b['browser_packet_sha256']
            and read(work/'influx-browser-route/claim.json')==browser_raw
            and baseline.read(nas/'influx-browser-claim.json',nas)==browser_raw
            and baseline.read(nas/'influx-browser-complete.json',nas)==browser_raw,
            'Preserve the exact completed browser route claim and NAS custody')
    route=browser.packet(json.loads(browser_raw))
    require(route['state_sha256']==b['state_sha256'] and route['vmid']==212
            and route['network_evidence']==b['network_overlay']
            and m.digest(baseline.read(nas/'influx-browser-shared-before.json',nas))==route['shared_before_sha256'],
            'Accepted browser route belongs to different infrastructure')
    return guest,values


def helpers():
    import database_network_apply as driver
    return [Path(__file__),Path(m.__file__),Path(m.networks.__file__),
            Path(__file__).with_name('database_network_server.py'),Path(driver.__file__),Path(browser.__file__),*baseline.helper_files()]


def plan(deployment,site,policy_path,evidence):
    """Prepare one read-only saved plan; this function needs separate native admission."""
    import database_network_apply as driver
    site,policy_path,evidence=map(Path,(site,policy_path,evidence))
    raw=m.regular(policy_path,private=False);selected=policy(json.loads(raw))
    cfg=json.loads(m.regular(site));deployment.validate(cfg);work=m.STATE/'212'
    require(cfg['paths']['state_root']==str(m.STATE) and evidence.parent==work
            and evidence.name.startswith('database-network-plan-') and not evidence.exists() and not evidence.is_symlink(),
            'Use one fresh saved-plan directory under the original ingress state')
    driver.private_directory(work)
    with driver.locked({'work':work}):
        m.no_holds(work);original,variables=m.bindings(deployment,cfg,site,work)
        guest,values=accepted(cfg,work,selected);new=candidate(guest,selected)
        require(original['files']['terraform.tfstate']==selected['baseline']['state_sha256'],
                'Current canonical state differs from the accepted ingress')
        evidence.mkdir(mode=0o700)
        request={'schema':PLAN_SCHEMA,'vmid':212,'policy_sha256':m.digest(raw),'original':original,
            'helper_sha256':{p.name:m.digest(p.read_bytes()) for p in helpers()},
            'apply_supported':False,'lifecycle_effects_verified':False}
        m.write_new(evidence/'request.json',m.encoded(request))
        try:
            source=Path(deployment.SOURCE)/'tofu'
            require(not any(p.is_symlink() for p in source.rglob('*')),'No alternate original ToFu source')
            shutil.copytree(source,evidence/'tofu',ignore=shutil.ignore_patterns('.terraform','*.tfstate*','*.tfplan*','*.auto.tfvars*'))
            m.write_new(evidence/'tofu/site.auto.tfvars.json',m.encoded(m.candidate_variables(variables,new)))
            m.write_new(evidence/'candidate-guest.json',m.encoded(new))
            log=evidence/'plan.log';m.write_new(log,b'');env=driver.environment(cfg);command=['tofu','-chdir='+str(evidence/'tofu')]
            m.tofu(command+['init','-input=false','-lockfile=readonly','-backend-config=path='+str(work/'terraform.tfstate')],env,log)
            m.tofu(command+['plan','-input=false','-lock-timeout=30s','-out='+str(evidence/'guest.tfplan')],env,log)
            m.tofu(command+['show','-json',str(evidence/'guest.tfplan')],env,log,evidence/'guest.tfplan.json')
            shown=m.regular(evidence/'guest.tfplan.json')
            observed=check_plan(json.loads(shown),cfg['site']['node'],guest,selected,values)
            m.no_holds(work,current_plan=evidence)
            require(m.bindings(deployment,cfg,site,work)[0]==original and m.regular(policy_path,private=False)==raw
                    and accepted(cfg,work,selected)==(guest,values),'Accepted source, state or history drifted during planning')
            review={**request,'status':'review_required','plan_sha256':m.digest(m.regular(evidence/'guest.tfplan')),
                    'plan_json_sha256':m.digest(shown),'candidate_guest_sha256':m.digest(m.encoded(new)),
                    'observed_provider_refresh':observed}
            m.write_new(evidence/'review-packet.json',m.encoded(review));return review
        except Exception as error:
            m.write_new(evidence/'HOLD.json',m.encoded({'status':'held','error_type':type(error).__name__,'automatic_retry':False}))
            raise


def load(deployment,site,policy_path,evidence,packet_path,expected_packet_sha256):
    """Adapt this closed request to the unchanged saved-plan execution primitives."""
    import database_network_apply as driver
    site,policy_path,evidence,packet_path=map(Path,(site,policy_path,evidence,packet_path))
    packet_raw=m.regular(packet_path);require(m.digest(packet_raw)==expected_packet_sha256,'Reviewed packet bytes changed')
    selected=driver.packet(json.loads(packet_raw));require(selected['schema']==APPLY_SCHEMA,'Select the firewall-only apply packet')
    raw=m.regular(policy_path,private=False);target=policy(json.loads(raw));cfg=json.loads(m.regular(site));deployment.validate(cfg)
    work=m.STATE/'212';driver.private_directory(work);driver.private_directory(evidence)
    require(cfg['paths']['state_root']==str(m.STATE) and evidence.parent==work
            and evidence.name.startswith('database-network-plan-'),'Use original ingress state and saved-plan custody')
    request_raw=m.regular(evidence/'request.json');review_raw=m.regular(evidence/'review-packet.json')
    require(m.digest(request_raw)==selected['request_sha256'] and m.digest(review_raw)==selected['review_packet_sha256'],
            'Saved request or review bytes changed')
    request,review=json.loads(request_raw),json.loads(review_raw)
    fields={'schema','vmid','policy_sha256','original','helper_sha256','apply_supported','lifecycle_effects_verified'}
    require(set(request)==fields and request['schema']==PLAN_SCHEMA and request['vmid']==selected['vmid']==212
            and request['apply_supported'] is False and request['lifecycle_effects_verified'] is False
            and request['policy_sha256']==m.digest(raw)
            and request.get('original',{}).get('files',{}).get('terraform.tfstate')==target['baseline']['state_sha256']
            and request['original'].get('state_lineage')==target['baseline']['state_lineage']
            and request['original'].get('state_serial')==target['baseline']['state_serial']
            and request['helper_sha256']=={p.name:m.digest(p.read_bytes()) for p in helpers()}
            and set(review)==fields|{'status','plan_sha256','plan_json_sha256','candidate_guest_sha256','observed_provider_refresh'}
            and all(review[k]==v for k,v in request.items()) and review['status']=='review_required',
            'Use the exact policy and reviewed helper set')
    guest,values=accepted(cfg,work,target);new=candidate(guest,target)
    shown=m.regular(evidence/'guest.tfplan.json')
    require(m.digest(shown)==review['plan_json_sha256'] and m.digest(m.regular(evidence/'guest.tfplan'))==review['plan_sha256']
            and m.digest(m.regular(evidence/'candidate-guest.json'))==review['candidate_guest_sha256']==m.digest(m.encoded(new)),
            'Saved binary, JSON or four-interface candidate changed')
    require(check_plan(json.loads(shown),cfg['site']['node'],guest,target,values)==review['observed_provider_refresh']
            and driver.copied_source_files(Path(deployment.SOURCE)/'tofu')==driver.copied_source_files(evidence/'tofu'),
            'Saved-plan source or provider observation changed')
    return dict(cfg=cfg,site=site,catalogue_path=policy_path,catalogue_raw=raw,plan=evidence,work=work,
        request=request,review=review,candidate=new,selected=selected,packet_raw=packet_raw,
        packet_sha256=expected_packet_sha256,packet_path=packet_path,request_raw=request_raw,review_raw=review_raw,
        attempt=work/('database-network-apply-'+selected['review_packet_sha256']),ingress_acme=None)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--config',type=Path,required=True);parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True);args=parser.parse_args();os.umask(0o077)
    try:
        require('deploy' not in sys.modules,'Use a fresh process for the unchanged original installer')
        sys.modules.pop('site_config',None);sys.path.insert(0,str(args.source.resolve()/'proxmox/applications'))
        deployment=importlib.import_module('deploy')
        require(Path(deployment.__file__).resolve()==args.source.resolve()/'proxmox/applications/deploy.py','Wrong original installer')
        result=plan(deployment,args.config,args.policy,args.evidence)
        print(json.dumps({k:result[k] for k in ('status','vmid','plan_sha256','apply_supported')}))
    except Exception as error:raise SystemExit('Ingress firewall planning held ('+type(error).__name__+'); preserve evidence') from None


if __name__=='__main__':main()
