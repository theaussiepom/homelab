"""One PegaProx overlay in the accepted Traefik watched inode; no restart."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
from urllib.parse import urlsplit

import component_browser as base
import component_image as shared
import pegaprox_browser as browser


packet=browser.packet

def request(route,host,path,frontend=False):
    if frontend:
        context=ssl.create_default_context();peer=(route['frontend_address'],443);source=None
    else:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=route['backend_certificate_pem'])
        peer=(urlsplit(route['backend']).hostname,5000);source=(route['proxy_address'],0)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    conn=http.client.HTTPSConnection(host,timeout=4,context=context)
    raw=socket.create_connection(peer,timeout=4,source_address=source)
    try:
        conn.sock=context.wrap_socket(raw,server_hostname=host)
        conn.request('GET',path);reply=conn.getresponse();body=reply.read(65537)
        browser.require(len(body)<=65536,'Oversized readiness response')
        return reply.status,json.loads(body)
    finally:conn.close();raw.close()


def readiness(route,frontend=False):
    health=request(route,route['host'],'/api/health',frontend)
    auth=request(route,route['host'],'/api/auth/check',frontend)
    browser.require(health==(200,{'status':'ok','version':'1.4.1'}),'PegaProx HTTPS health differs')
    code,state=auth
    browser.require(code==401 and state.get('initialized') is True and state.get('authenticated') is False and state.get('oidc_enabled') is False and state.get('ldap_enabled') is False,'Keep the initialized native-login policy')


def backend_ready(route):
    browser.validate(route)
    rows=json.loads(shared.command(['ip','-j','-4','address','show']))
    sources={x['ifname'].split('@')[0]:[a.get('local') for a in x.get('addr_info',[]) if a.get('family')=='inet'] for x in rows}
    browser.require(route['proxy_address'] in sources.get('eth0',[]),'The backend source must be the accepted management interface')
    readiness(route)


def route_ready(route):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        try:readiness(route,frontend=True);return
        except (OSError,ValueError,http.client.HTTPException):time.sleep(2)
    raise ValueError('Verified frontend HTTPS/native login did not become ready')


def run(selected,verify_only=False):
    settings=packet(selected);browser.require(os.geteuid()==0,'Use the reviewed ingress maintenance path')
    runtime=base.guard(settings)
    base.STATE.mkdir(mode=0o700,exist_ok=True);i=base.STATE.lstat()
    browser.require(stat.S_ISDIR(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o700,'Unexpected route evidence directory')
    operation=base.STATE/'pegaprox-browser-v1';encoded=(json.dumps(settings,sort_keys=True,indent=2)+'\n').encode()
    if verify_only:
        i=operation.lstat();browser.require(stat.S_ISDIR(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o700,'Unexpected operation metadata')
        browser.require(shared.read(operation/'settings.json')==encoded and shared.read(operation/'complete.json')==b'{"status":"passed"}\n' and not (operation/'HOLD.json').exists() and not (operation/'HOLD.json').is_symlink(),'Preserve incomplete route work; no replay')
        original=shared.read(operation/'shared-before.json')
        browser.require(base.digest(original)==settings['shared_before_sha256'] and base.read_config(base.CONFIG)==browser.candidate(original,settings['route']),'The maintained PegaProx overlay drifted')
        backend_ready(settings['route']);route_ready(settings['route'])
        browser.require(base.guard(settings)==runtime,'Ingress changed/restarted during verification')
        return {'status':'passed','changed':False,'login_reconfigured':False}
    original=base.read_config(base.CONFIG);updated=browser.candidate(original,settings['route'])
    browser.require(base.digest(original)==settings['shared_before_sha256'] and base.digest(updated)==settings['shared_after_sha256'],'The original/candidate shared configuration differs')
    backend_ready(settings['route'])
    operation.mkdir(mode=0o700) # A prior claim never becomes another installation.
    shared.save(operation/'settings.json',encoded);shared.save(operation/'shared-before.json',original);shared.save(operation/'HOLD.json',b'{"automatic_retry":false}\n')
    with os.fdopen(os.open(base.CONFIG,os.O_RDONLY|os.O_NOFOLLOW),'rb') as anchor:
        info=os.fstat(anchor.fileno());mode=stat.S_IMODE(info.st_mode)
        browser.require(anchor.read()==original and info.st_nlink==1 and info.st_uid==0 and mode in (0o400,0o600),'Watched-file admission drift')
        os.fchmod(anchor.fileno(),0o600)
        try:
            with os.fdopen(os.open(base.CONFIG,os.O_RDWR|os.O_NOFOLLOW),'r+b',buffering=0) as stream:
                current=os.fstat(stream.fileno())
                browser.require((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino) and stream.read()==original,'Watched inode changed')
                base.replace_watched(stream,updated,original)
        finally:os.fchmod(anchor.fileno(),mode);os.fsync(anchor.fileno())
    browser.require(base.read_config(base.CONFIG)==updated and base.guard(settings)==runtime,'Ingress/static/Compose/startup changed during activation')
    route_ready(settings['route'])
    browser.require(base.guard(settings)==runtime,'Ingress changed/restarted during readiness')
    shared.save(operation/'complete.json',b'{"status":"passed"}\n');(operation/'HOLD.json').unlink();shared.sync(operation)
    return {'status':'passed','changed':True,'login_reconfigured':False,'ingress_restarted':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--settings',type=Path,required=True);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
    try:print(json.dumps(run(json.loads(shared.read(a.settings)),a.verify_only)))
    except Exception:raise SystemExit('PegaProx hostname route held; preserve original evidence. No replay.') from None
