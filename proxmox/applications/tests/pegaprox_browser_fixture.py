#!/usr/bin/env python3
"""Prove inline backend trust and SNI with pinned PegaProx/Traefik, no host ports."""
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pegaprox
import pegaprox_browser as browser
import pegaprox_setup

TRAEFIK='traefik@sha256:1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65'


def docker(*args,input=None):
    p=subprocess.run(['docker',*args],input=input,capture_output=True,text=True,timeout=90)
    if p.returncode:raise RuntimeError('Disposable Docker fixture command failed: '+p.stderr[-1200:])
    return p.stdout.strip()


def main():
    prefix='pegaprox-browser-'+uuid.uuid4().hex[:10];backend=prefix+'-app';proxy=prefix+'-proxy';network=prefix+'-network'
    volumes=[prefix+'-'+n for n in ('config','logs','key')];created_network=False;created_volumes=[]
    result={'network':'internal','host_ports':[],'native_changed':False}
    bounded=['--pull=never','--platform','linux/amd64','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','2','--memory','1536m','--pids-limit','256','--tmpfs','/tmp:rw,nosuid,nodev,size=64m']
    try:
        with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
            root=Path(tmp)
            conf=root/'cert.cnf';conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=prox.example.invalid\n[ext]\nsubjectAltName=DNS:prox.example.invalid,IP:198.18.25.34\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            for stem in ('peer','wrong'):
                subprocess.run(['openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-config',str(conf),'-keyout',str(root/(stem+'.key')),'-out',str(root/(stem+'.pem'))],check=True,capture_output=True)
            pem=(root/'peer.pem').read_text()
            cfg={'schema':browser.SCHEMA,'host':'prox.example.invalid','backend':'https://198.18.25.34:5000','proxy_address':'198.18.25.33','frontend_address':'198.18.25.33','backend_certificate_pem':pem,'backend_certificate_sha256':__import__('hashlib').sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest(),'backend_spki_sha256':browser.spki(pem)}
            original={'tls':{'certificates':[{'certFile':'/fixture/peer.pem','keyFile':'/fixture/peer.key'}]},'http':{'middlewares':{'security-headers':{'headers':{'contentTypeNosniff':True}}}}}
            dynamic=browser.merge(original,cfg);shared=root/'shared.yml';shared.write_text(json.dumps(dynamic))
            static={'entryPoints':{'websecure':{'address':':8443'}},'providers':{'file':{'filename':'/fixture/shared.yml','watch':True}},'certificatesResolvers':{'letsencrypt':{'acme':{'email':'fixture@example.invalid','storage':'/tmp/acme.json','caServer':'https://127.0.0.1:1/directory','httpChallenge':{'entryPoint':'websecure'}}}},'log':{'level':'ERROR'}}
            (root/'static.yml').write_text(json.dumps(static))
            docker('network','create','--internal','--subnet','198.18.25.0/24',network);created_network=True
            for volume in volumes:docker('volume','create',volume);created_volumes.append(volume)
            init="import base64,json,os,pathlib,sys;p=json.load(sys.stdin);d=pathlib.Path('/app/config/ssl');d.mkdir(mode=0o700);c=d/'cert.pem';c.write_text(p['certificate']);c.chmod(0o644);k=d/'key.pem';k.write_text(p['key']);k.chmod(0o600);m=pathlib.Path('/app/logs/db-key');m.write_bytes(base64.urlsafe_b64encode(os.urandom(32)));m.chmod(0o600)"
            docker('run','--rm','-i',*bounded,'--network','none','-v',volumes[0]+':/app/config','-v',volumes[2]+':/app/logs','--entrypoint','python3',pegaprox.IMAGE,'-c',init,input=json.dumps({'certificate':pem,'key':(root/'peer.key').read_text()}))
            docker('run','-d','--name',backend,*bounded,'--network',network,'--ip','198.18.25.34','-e','PEGAPROX_KEY_FILE=/run/secrets/db-key','-e','PEGAPROX_SUPERVISED=1','-v',volumes[0]+':/app/config','-v',volumes[1]+':/app/logs','-v',volumes[2]+':/run/secrets:ro',pegaprox.IMAGE)
            pegaprox_setup.invoke(['docker','exec','-i',backend],'bootstrap','practice-admin','Fixture-'+secrets.token_urlsafe(18)+'7')
            docker('run','-d','--name',proxy,*bounded,'--user',str(os.getuid()),'--network',network,'--ip','198.18.25.33','-v',str(root)+':/fixture:ro',TRAEFIK,'--configFile=/fixture/static.yml')
            client="import http.client,json,socket,ssl;ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.load_verify_locations(cafile='/app/config/ssl/cert.pem');c=http.client.HTTPSConnection('prox.example.invalid',8443,context=ctx,timeout=3);c.sock=ctx.wrap_socket(socket.create_connection(('198.18.25.33',8443),timeout=3),server_hostname='prox.example.invalid');c.request('GET','/api/health');r=c.getresponse();print(json.dumps({'status':r.status,'body':r.read(4096).decode()}));c.close()"
            def wait(status):
                deadline=time.monotonic()+35
                while time.monotonic()<deadline:
                    try:
                        value=json.loads(docker('exec',backend,'python3','-c',client))
                        if value['status']==status:return value
                    except (RuntimeError,ValueError):pass
                    time.sleep(1)
                raise RuntimeError('The expected TLS proxy result did not become ready: '+repr(locals().get('value'))+'; logs='+docker('logs','--tail','8',proxy)[-1200:])
            initial=wait(200);assert json.loads(initial['body'])=={'status':'ok','version':'1.4.1'}
            result['inline_leaf_trust_and_exact_sni']=True
            dynamic['http']['serversTransports']['pegaprox-verified']['serverName']='wrong.example.invalid';shared.write_text(json.dumps(dynamic));wait(500);logs=docker('logs','--tail','12',proxy);assert 'not wrong.example.invalid' in logs;result['wrong_sni_rejected']=True
            dynamic['http']['serversTransports']['pegaprox-verified']['serverName']=cfg['host'];shared.write_text(json.dumps(dynamic));wait(200)
            dynamic['http']['serversTransports']['pegaprox-verified']['rootCAs']=[(root/'wrong.pem').read_text()];shared.write_text(json.dumps(dynamic));wait(500);logs=docker('logs','--tail','12',proxy);assert 'certificate signed by unknown authority' in logs;result['wrong_trust_anchor_rejected']=True
            dynamic['http']['serversTransports']['pegaprox-verified']['rootCAs']=[pem];shared.write_text(json.dumps(dynamic));wait(200)
            auth=json.loads(docker('exec',backend,'python3','-c',client.replace("'/api/health'","'/api/auth/check'")))
            assert auth['status']==401
            state=json.loads(auth['body']);assert state['initialized'] is True and state['authenticated'] is False and state['oidc_enabled'] is False
            result['native_login_still_initialized']=True
    finally:
        for name in (proxy,backend):subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30)
        for volume in created_volumes:docker('volume','rm',volume)
        if created_network:docker('network','rm',network)
        result['disposable_resources_removed']=True
        print(json.dumps(result,indent=2))


if __name__=='__main__':main()
