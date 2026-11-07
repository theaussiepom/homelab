#!/usr/bin/env python3
"""Exercise the middleware through real Traefik, using only synthetic peers/feed.

The disposable source copy changes only the fixed feed URL to its local fixture.
No real Cloudflare network is routed and no production credential is involved.
Native Go tests separately cover HTTPS client errors, deadlines and concurrency.
"""
import argparse
import base64
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

BACKEND = r'''
import json,hashlib,base64
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path=='/unavailable':
   self.send_response(503);self.end_headers();return
  if self.path=='/ips':
   print('synthetic feed requested',flush=True)
   data=json.dumps({'success':True,'result':{'ipv4_cidrs':['198.18.71.0/24'],'ipv6_cidrs':['2400:cb00::/32']}}).encode()
  elif self.headers.get('Upgrade','').lower()=='websocket':
   self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade')
   self.send_header('Sec-WebSocket-Accept',base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode())
   self.send_header('X-Fixture-Proto',self.headers.get('X-Forwarded-Proto','missing'));self.end_headers();return
  else:data=json.dumps(dict(self.headers)).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
'''
CLIENT = r'''
import json,sys,ssl,time,http.client
host,scheme,headers,expected=sys.argv[1:];headers=json.loads(headers);expected=int(expected)
ctx=ssl.create_default_context(cafile='/fixture/cert.pem')
deadline=time.monotonic()+25
while True:
 try:
  cls=http.client.HTTPSConnection if scheme=='https'else http.client.HTTPConnection
  conn=cls('fixture.example.invalid',8443 if scheme=='https'else 8080,timeout=4,**({'context':ctx}if scheme=='https'else{}))
  conn.request('GET','/',headers=headers);response=conn.getresponse();status=response.status
  body=response.read().decode()if status!=101 else ''
  result={'status':status,'headers':json.loads(body)if status==200 else {},'websocket_proto':response.getheader('X-Fixture-Proto'),'failure_body':body if status not in (200,101) else None}
  conn.close()
  if (status==404 or status==503 and expected==200) and time.monotonic()<deadline:
   time.sleep(.2);continue
  print(json.dumps(result));assert status==expected;break
 except OSError:
  if time.monotonic()>deadline:raise
  time.sleep(.2)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--traefik-image', required=True)
    parser.add_argument('--python-image', required=True)
    args = parser.parse_args()
    assert all('@sha256:' in value for value in (args.traefik_image, args.python_image))
    name = 'cf-fixture-' + uuid.uuid4().hex[:10]
    owned, networks = [], []

    def docker(*argv):
        try:
            return subprocess.check_output(['docker', *argv], text=True, stderr=subprocess.STDOUT, timeout=60).strip()
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(exc.output) from None

    with tempfile.TemporaryDirectory(prefix='homelab-cloudflare-') as directory:
        root = Path(directory)
        source = Path(__file__).resolve().parents[1] / 'traefik_cloudflare'
        plugin = root / 'plugin'
        shutil.copytree(source, plugin, ignore=shutil.ignore_patterns('*_test.go'))
        code = (plugin / 'cloudflare.go').read_text()
        original = 'https://api.cloudflare.com/client/v4/ips'
        assert code.count(original) == 1
        (plugin / 'cloudflare.go').write_text(code.replace(original, 'http://10.254.71.3:8080/ips'))
        (root / 'backend.py').write_text(BACKEND)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-subj', '/CN=fixture.example.invalid',
            '-addext', 'subjectAltName=DNS:fixture.example.invalid'], check=True, capture_output=True)
        static = {'entryPoints': {'web': {'address': ':8080'}, 'secure': {'address': ':8443'}},
            'experimental': {'abortOnPluginFailure': True, 'localPlugins': {
                'cloudflare-source': {'moduleName': 'github.com/theaussiepom/homelab-cloudflare'}}},
            'providers': {'file': {'filename': '/fixture/dynamic.yml'}}, 'global': {'checkNewVersion': False}, 'log': {'level':'INFO'}}
        dynamic = {'tls': {'certificates': [{'certFile': '/fixture/cert.pem', 'keyFile': '/fixture/key.pem'}]},
            'http': {'routers': {key: {'rule': 'Host(`fixture.example.invalid`)', 'service': 'echo',
                'entryPoints': [entry], 'middlewares': ['boundary'], **({'tls': {}} if entry=='secure' else {})}
                for key,entry in (('plain','web'),('tls','secure'))},
            'services': {'echo': {'loadBalancer': {'servers': [{'url': 'http://10.254.71.3:8080'}]}}},
            'middlewares': {'boundary': {'plugin': {'cloudflare-source': {
                'internalCIDRs': ['10.254.71.4/32'], 'originHeader': 'x-origin-key',
                'originToken': 'synthetic-origin-value-for-tests'}}}}}}
        for leaf, model in (('static.yml', static), ('dynamic.yml', dynamic)):
            (root/leaf).write_text(json.dumps(model))
        try:
            for suffix, subnet in (('internal', '10.254.71.0/24'), ('public', '198.18.71.0/24')):
                net = name+'-'+suffix
                docker('network','create','--subnet',subnet,net);networks.append(net)
            backend=name+'-backend';owned.append(backend)
            docker('run','-d','--name',backend,'--network',networks[0],'--ip','10.254.71.3',
                '-v',str(root)+':/fixture:ro',args.python_image,'python','/fixture/backend.py')
            docker('exec',backend,'python','-c',"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ips',timeout=4).read()")
            proxy=name+'-proxy';owned.append(proxy)
            docker('run','-d','--name',proxy,'--platform','linux/amd64','--network',networks[0],'--ip','10.254.71.2',
                '-v',str(root)+':/fixture:ro','-v',str(plugin)+':/plugins-local/src/github.com/theaussiepom/homelab-cloudflare:ro',
                args.traefik_image,'--configFile=/fixture/static.yml')
            docker('network','connect','--ip','198.18.71.2',networks[1],proxy)
            headers={'X-Origin-Key':'synthetic-origin-value-for-tests','CF-Connecting-IP':'203.0.113.7',
                'CF-Visitor':'{"scheme":"https"}','X-Forwarded-For':'198.18.71.44','X_Forwarded_For':'10.0.0.9'}

            def request(network, ip, target, scheme, values, expected):
                result=docker('run','--rm','--network',network,'--ip',ip,'--add-host','fixture.example.invalid:'+target,
                    '-v',str(root)+':/fixture:ro',args.python_image,'python','-c',CLIENT,target,scheme,json.dumps(values),str(expected))
                return json.loads(result)

            public=request(networks[1],'198.18.71.4','198.18.71.2','http',headers,200)
            local=request(networks[0],'10.254.71.4','10.254.71.2','https',headers,200)
            for result,ip,port in ((public,'203.0.113.7','8080'),(local,'10.254.71.4','8443')):
                actual={k.lower():v for k,v in result['headers'].items()}
                assert actual['x-real-ip']==ip and all(v.strip()==ip for v in actual['x-forwarded-for'].split(',')),actual
                assert actual['x-forwarded-proto']=='https' and actual['x-forwarded-host'].startswith('fixture.example.invalid') and actual['x-forwarded-port']==port,actual
                assert 'x-origin-key' not in actual and 'cf-connecting-ip' not in actual and 'x_forwarded_for' not in actual,actual
            websocket=request(networks[0],'10.254.71.4','10.254.71.2','https',{**headers,'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Key':base64.b64encode(os.urandom(16)).decode(),'Sec-WebSocket-Version':'13'},101)
            assert websocket['websocket_proto']=='https'
            request(networks[0],'10.254.71.5','10.254.71.2','http',headers,403)
            request(networks[1],'198.18.71.4','198.18.71.2','http',{**headers,'X-Origin-Key':'wrong'},403)
            request(networks[1],'198.18.71.4','198.18.71.2','http',{**headers,'CF-Connecting-IP':'bad-ip'},400)
            failed_plugin=root/'failed-plugin'
            shutil.copytree(plugin,failed_plugin)
            (failed_plugin/'cloudflare.go').write_text(code.replace(original,'http://10.254.71.3:8080/unavailable'))
            failed_proxy=name+'-failed-proxy';owned.append(failed_proxy)
            docker('run','-d','--name',failed_proxy,'--platform','linux/amd64','--network',networks[0],'--ip','10.254.71.6',
                '-v',str(root)+':/fixture:ro','-v',str(failed_plugin)+':/plugins-local/src/github.com/theaussiepom/homelab-cloudflare:ro',
                args.traefik_image,'--configFile=/fixture/static.yml')
            docker('network','connect','--ip','198.18.71.6',networks[1],failed_proxy)
            request(networks[1],'198.18.71.4','198.18.71.6','http',headers,503)
            request(networks[0],'10.254.71.4','10.254.71.6','https',headers,200)
            print(json.dumps({'actual_traefik_image':args.traefik_image,'public_visitor_headers':True,
                'internal_https_headers':True,'internal_https_websocket':True,'origin_secret_removed':True,'spoofed_source_denied':True,
                'wrong_secret_denied':True,'malformed_visitor_denied':True,'synthetic_feed_only':True,'initial_feed_failure_public_denied_internal_preserved':True}))
        except Exception:
            for container in owned:
                print(container,docker('logs',container))
            raise
        finally:
            for container in reversed(owned):subprocess.run(['docker','rm','-f',container],capture_output=True)
            for network in reversed(networks):subprocess.run(['docker','network','rm',network],capture_output=True)


if __name__ == '__main__':
    main()
