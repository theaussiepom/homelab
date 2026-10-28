"""Add one native-login PegaProx router with certificate-verified HTTPS."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from ingress_browser import dns, require

EVIDENCE_ROOT=Path('/var/lib/homelab-applications')
SCHEMA='homelab-pegaprox-browser-v1'
FIELDS={'schema','host','backend','proxy_address','frontend_address','backend_certificate_pem','backend_certificate_sha256','backend_spki_sha256'}
PRIVATE=[ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15')]


def address(value):
    ip=ipaddress.IPv4Address(value)
    require(str(ip)==value and any(ip in n for n in PRIVATE),'Use a canonical private IPv4 address')
    return ip


def spki(pem):
    pub=subprocess.run(['openssl','x509','-pubkey','-noout'],input=pem.encode(),capture_output=True,timeout=5,check=True).stdout
    der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,timeout=5,check=True).stdout
    return hashlib.sha256(der).hexdigest()


def validate(value):
    require(isinstance(value,dict) and set(value)==FIELDS and value['schema']==SCHEMA,'Use the closed native-login browser policy')
    require(dns(value['host']),'Use a literal browser hostname')
    url=value['backend'];require(isinstance(url,str) and not any(c.isspace() for c in url) and '\\' not in url,'Use a canonical HTTPS backend')
    peer=urlsplit(url)
    require(peer.scheme=='https' and peer.port==5000 and peer.path=='' and not peer.query and not peer.fragment and peer.username is None and peer.password is None,'Keep the existing HTTPS backend on port5000')
    backend=address(peer.hostname);proxy=address(value['proxy_address']);address(value['frontend_address'])
    require(proxy!=backend and proxy in ipaddress.IPv4Network(str(backend)+'/24',strict=False),'Use the distinct existing management-side proxy address')
    pem=value['backend_certificate_pem']
    require(isinstance(pem,str) and len(pem)<=8192 and pem.count('-----BEGIN CERTIFICATE-----')==1 and pem.count('-----END CERTIFICATE-----')==1 and 'PRIVATE KEY' not in pem,'Supply only the reviewed public backend certificate')
    require(re.fullmatch('[0-9a-f]{64}',value['backend_certificate_sha256']) and hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()==value['backend_certificate_sha256'],'The backend certificate differs')
    with tempfile.TemporaryDirectory(prefix='pegaprox-cert-') as tmp:
        path=Path(tmp)/'peer.pem';path.write_text(pem)
        cert=ssl._ssl._test_decode_cert(str(path))
    sans=set(cert.get('subjectAltName',[]))
    require(('DNS',value['host']) in sans and ('IP Address',str(backend)) in sans,'The backend certificate must cover the exact SNI and address')
    require(ssl.cert_time_to_seconds(cert['notBefore'])<=time.time()<ssl.cert_time_to_seconds(cert['notAfter']),'The backend certificate is not currently valid')
    require(re.fullmatch('[0-9a-f]{64}',value['backend_spki_sha256']) and spki(pem)==value['backend_spki_sha256'],'The retained backend public key differs')
    return value


def objects(settings):
    v=validate(settings)
    return {'http':{'routers':{'pegaprox-browser':{'rule':f"Host(`{v['host']}`)",'entryPoints':['websecure'],'tls':{'certResolver':'letsencrypt'},'service':'pegaprox-private','middlewares':['security-headers']}},'services':{'pegaprox-private':{'loadBalancer':{'servers':[{'url':v['backend']}],'passHostHeader':True,'serversTransport':'pegaprox-verified@file'}}},'serversTransports':{'pegaprox-verified':{'serverName':v['host'],'rootCAs':[v['backend_certificate_pem']]}}}}


def merge(original,settings):
    validate(settings);require(isinstance(original,dict),'Expected the existing watched configuration')
    result=copy.deepcopy(original);http=result.setdefault('http',{})
    require(isinstance(http,dict) and 'security-headers' in http.get('middlewares',{}),'Keep the existing security headers')
    for router in http.get('routers',{}).values():
        rule=router.get('rule','')
        match=re.fullmatch(r'Host\(`([a-z0-9.-]+)`\)(?: && PathPrefix\(`/[A-Za-z0-9/._-]*`\))?',rule)
        require(match is not None and match[1]!=settings['host'],'An existing router may claim the hostname; preserve it for review')
    for router in result.get('tcp',{}).get('routers',{}).values():
        if 'websecure' in router.get('entryPoints',['websecure']):
            rule=router.get('rule','')
            require(re.fullmatch(r'HostSNI\(`[a-z0-9.-]+`\)',rule) and settings['host'] not in rule,'An existing TLS router may capture this hostname')
    for section,values in objects(settings)['http'].items():
        target=http.setdefault(section,{})
        require(isinstance(target,dict) and not set(target).intersection(values),'A reserved PegaProx object already exists; no adoption')
        target.update(values)
    return result


def candidate(original,settings):
    return (json.dumps(merge(json.loads(original),settings),indent=2)+'\n').encode()


def packet(value):
    fields={'schema','revision','vmid','plan_sha256','state_sha256','foundation_complete_sha256','compose_sha256','runtime_sha256','shared_before_sha256','shared_after_sha256','image','startup','network_evidence','policy_evidence','route'}
    require(isinstance(value,dict) and set(value)==fields and value['schema']=='homelab-pegaprox-browser-update-v1','Use the closed PegaProx overlay packet')
    require(type(value['vmid']) is int and value['vmid']>=100 and value['vmid'] not in {900,4914,4915,4920},'Select the existing ingress guest')
    require(re.fullmatch('[0-9a-f]{40}',value['revision']) and re.fullmatch(r'traefik@sha256:[0-9a-f]{64}',value['image']),'Bind immutable source and unchanged ingress image')
    for key in fields:
        if key.endswith('_sha256'):require(re.fullmatch('[0-9a-f]{64}',value[key]),'Bind every exact retained/current digest')
    require(value['shared_before_sha256']!=value['shared_after_sha256'],'Declare an actual route addition')
    startup=value['startup']
    require(set(startup)=={'interfaces','gate_sha256','docker_dependency_sha256','routing_unit_sha256','routing_dependency_sha256'} and startup['interfaces']==['eth0','eth1','eth2','eth3'] and all(re.fullmatch('[0-9a-f]{64}',v) for k,v in startup.items() if k!='interfaces'),'Preserve the accepted four-interface startup gate')
    for key in ('network_evidence','policy_evidence'):
        evidence=value[key];path=Path(evidence.get('path',''))
        require(set(evidence)=={'path','sha256'} and path.is_absolute() and '..' not in path.parts and path.is_relative_to(EVIDENCE_ROOT/str(value['vmid'])) and len(path.parts)>len((EVIDENCE_ROOT/str(value['vmid'])).parts)+1 and re.fullmatch('[0-9a-f]{64}',evidence['sha256']),'Bind the existing ingress network and policy acceptance')
    validate(value['route'])
    return value



def admission(settings,network,policy):
    packet(settings)
    require(network.get("schema")=="homelab-database-network-overlay-v1" and network.get("status")=="network_overlay_verified" and network.get("vmid")==settings["vmid"] and network.get("state_sha256")==settings["state_sha256"],"Use the current completed ingress network overlay")
    require(set(policy)=={"schema","vmid","route_sha256","native_login_retained","authentik_deferred","network_enforcement_deferred"} and policy["schema"]=="homelab-pegaprox-browser-policy-evidence-v1" and policy["vmid"]==settings["vmid"] and policy["route_sha256"]==hashlib.sha256((json.dumps(settings["route"],sort_keys=True,indent=2)+"\n").encode()).hexdigest() and all(policy[k] is True for k in ("native_login_retained","authentik_deferred","network_enforcement_deferred")),"Require the exact reviewed temporary local-login policy")
