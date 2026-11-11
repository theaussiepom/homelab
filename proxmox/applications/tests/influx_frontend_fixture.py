"""Disposable Linux fixture: unit ordering syntax and real proxy HTTP traffic."""
import http.server,json,os,pathlib,subprocess,sys,tempfile,threading,time,urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import component_native
value={'adapter':'influxdb','role_addresses':{'web_interface':'198.18.40.26','service_interface':'198.18.33.26'},'listeners':{}}
for name,role in [('web','web'),('backend','service')]:
 value['listeners'][name]={'service':'influxdb','namespace':'host','interface':role,'bind':'interface','protocol':'tcp','port':8086,'actual_bind':value['role_addresses'][role]}
with tempfile.TemporaryDirectory()as directory:
 root=pathlib.Path(directory)
 for row in component_native.web_frontend(value)['files']:(root/row['name']).write_text(row['content'])
 for name in ['homelab-network-ready.service','influxdb.service']:
  (root/name).write_text('[Unit]\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
 env=dict(os.environ,SYSTEMD_UNIT_PATH=str(root)+':')
 checked=subprocess.run(['systemd-analyze','verify','--man=no',str(root/'homelab-influxdb-web.socket'),str(root/'homelab-influxdb-web.service')],env=env,text=True,capture_output=True)
 if checked.returncode:raise RuntimeError(checked.stderr)
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  data=json.dumps({'status':'pass','fixture':'original-private-api'}).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',38087),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
with tempfile.TemporaryFile()as log:
 proxy=subprocess.Popen(['systemd-socket-activate','--listen=127.0.0.2:38086','/usr/lib/systemd/systemd-socket-proxyd','127.0.0.1:38087'],stdout=log,stderr=log)
 try:
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  for attempt in range(40):
   try:
    with opener.open('http://127.0.0.2:38086/health',timeout=2)as response:result=json.load(response)
    break
   except OSError:
    if proxy.poll()is not None:raise RuntimeError('proxy stopped')
    time.sleep(.05)
  else:raise RuntimeError('bounded fixture deadline')
  assert result=={'status':'pass','fixture':'original-private-api'}
  with opener.open('http://127.0.0.1:38087/health',timeout=2)as response:assert json.load(response)==result
 finally:
  proxy.terminate();proxy.wait(timeout=5);server.shutdown();server.server_close();thread.join(5)
print(json.dumps({'unit_verification':'passed','real_systemd_socket_proxy':'passed','native_boot':'not_tested','target_contact':False}))
