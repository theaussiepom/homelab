"""Synthetic HTTPS through a stateful router; four disposable local containers.

No host networking, published ports, production peers or private credentials.
Only NET_ADMIN inside these disposable namespaces is used. Main routes remain
unchanged by the production helper; all test-owned resources are removed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(image, output):
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    context = subprocess.check_output(['docker', 'context', 'show'], text=True).strip()
    endpoint = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context], text=True))[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):
        raise RuntimeError('This fixture requires a local Unix-socket Docker context')
    docker = ['docker', '--context', context]
    def cli(argv, check=True, input=None):
        value = subprocess.run([*docker, *argv], capture_output=True, text=True, timeout=30, input=input)
        if check and value.returncode:
            raise RuntimeError('Isolated routing fixture command failed: ' + value.stderr[-2000:])
        return value
    cli(['image', 'inspect', image])
    prefix = 'homelab-routing-' + uuid.uuid4().hex[:10]
    networks, containers = [], []
    names = {role: prefix + '-' + role for role in ('router', 'proxy', 'management', 'backend')}
    segments = {role: prefix + '-' + role for role in ('mgmt', 'data', 'front')}
    def execute(role, *argv, check=True):
        return cli(['exec', names[role], *argv], check=check)
    def ip(role, *argv):
        return json.loads(execute(role, 'ip', '-j', '-4', *argv).stdout)
    def copy(role, source, destination):
        # Create files as the guest's actual root owner. Docker cp can retain
        # host UID metadata, which is inappropriate for the private config check.
        program = 'import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); stream=os.fdopen(fd,\"w\"); stream.write(sys.stdin.read()); stream.close()'
        cli(['exec','-i',names[role],'python3','-c',program,destination], input=source.read_text())
    try:
        for role, octet in (('mgmt', 25), ('data', 30), ('front', 40)):
            cli(['network', 'create', '--subnet', f'10.249.{octet}.0/24', '--gateway', f'10.249.{octet}.254', segments[role]])
            networks.append(segments[role])
        for role, address in (('router', '10.249.25.1'), ('proxy', '10.249.25.33'),
                              ('management', '10.249.25.32'), ('backend', '10.249.25.34')):
            args = ['run', '-d', '--pull', 'never', '--platform', 'linux/amd64', '--name', names[role],
                    '--network', segments['mgmt'], '--ip', address, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                    '--memory', '192m', '--cpus', '0.5', '--pids-limit', '64']
            if role == 'router': args += ['--sysctl', 'net.ipv4.ip_forward=1']
            if role == 'proxy': args += ['--cap-add', 'NET_BIND_SERVICE', '--sysctl', 'net.ipv4.conf.all.rp_filter=1',
                                         '--sysctl', 'net.ipv4.conf.default.rp_filter=1']
            cli([*args, image, 'python3', '-c', 'import time; time.sleep(600)'])
            containers.append(names[role])
        for role, segment, address in (('router', 'front', '10.249.40.1'), ('proxy', 'front', '10.249.40.33'),
                ('proxy', 'data', '10.249.30.33'), ('backend', 'data', '10.249.30.32')):
            cli(['network', 'connect', '--ip', address, segments[segment], names[role]])
        # Docker --internal bridges discard off-subnet IP packets before our
        # router namespace receives them. Isolate this routed topology instead
        # by removing the router's external default and allowing only this TLS flow.
        execute('router', 'ip', 'route', 'del', 'default')
        assert not any(row.get('dst') == 'default' for row in ip('router', 'route', 'show'))
        for role in ('proxy', 'management', 'backend'):
            execute(role, 'ip', 'route', 'replace', 'default', 'via', '10.249.25.1')
            defaults = [row for row in ip(role, 'route', 'show') if row.get('dst') == 'default']
            assert len(defaults) == 1 and defaults[0]['gateway'] == '10.249.25.1'
        execute('router', 'iptables', '-P', 'FORWARD', 'DROP')
        execute('router', 'iptables', '-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
        execute('router', 'iptables', '-A', 'FORWARD', '-s', '10.249.25.0/24', '-d', '10.249.40.33/32',
                '-p', 'tcp', '--dport', '443', '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT')
        server = output / 'server.py'
        server.write_text('''import http.server,ssl
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')
    def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('10.249.40.33',443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
context.load_cert_chain('/tmp/cert.pem','/tmp/key.pem'); server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
''')
        execute('proxy', 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=proxy.lab.example.org', '-addext', 'subjectAltName=DNS:proxy.lab.example.org',
                '-keyout', '/tmp/key.pem', '-out', '/tmp/cert.pem')
        copy('proxy', server, '/tmp/server.py')
        cli(['exec', '-d', names['proxy'], 'sh', '-c', 'exec python3 /tmp/server.py >/tmp/server.log 2>&1'])
        cert = output / 'cert.pem'; cli(['cp', names['proxy'] + ':/tmp/cert.pem', str(cert)])
        client = output / 'client.py'
        client.write_text('''import socket,ssl
context=ssl.create_default_context(cafile='/tmp/cert.pem')
with socket.create_connection(('10.249.40.33',443),timeout=3) as raw:
    with context.wrap_socket(raw,server_hostname='proxy.lab.example.org') as stream:
        stream.sendall(b'GET / HTTP/1.0\\r\\nHost: proxy.lab.example.org\\r\\n\\r\\n')
        response=b''
        while True:
            block=stream.recv(4096)
            if not block: break
            response+=block
assert b'200 OK' in response and response.endswith(b'OK')
print('HTTPS verified')
''')
        for role in ('proxy', 'management', 'backend'):
            if role != 'proxy': copy(role, cert, '/tmp/cert.pem')
            copy(role, client, '/tmp/client.py')
        deadline = time.monotonic() + 15
        while True:
            readiness = execute('proxy', 'python3', '/tmp/client.py', check=False)
            if readiness.returncode == 0: break
            if time.monotonic() > deadline:
                (output / 'readiness-error.log').write_text(readiness.stderr + execute('proxy', 'cat', '/tmp/server.log', check=False).stdout)
                raise RuntimeError('Synthetic HTTPS readiness failed; see the retained fixture log')
            time.sleep(.25)
        main_before = ip('proxy', 'route', 'show', 'table', 'main')
        wrong = ip('proxy', 'route', 'get', '10.249.25.32', 'from', '10.249.40.33')[0]
        assert wrong.get('gateway') != '10.249.40.1'
        negative = execute('management', 'python3', '/tmp/client.py', check=False)
        assert negative.returncode != 0, 'The asymmetric baseline must fail before reply routing is installed'
        link = next(link for link in ip('proxy', 'address', 'show') if any(a.get('local') == '10.249.40.33' for a in link.get('addr_info', [])))
        link = next(row for row in ip('proxy', 'link', 'show') if row['ifname'] == link['ifname'])
        assert execute('proxy','cat','/proc/sys/net/ipv4/conf/' + link['ifname'] + '/rp_filter').stdout.strip() == '1'
        settings = output / 'routing.json'
        settings.write_text(json.dumps({'address':'10.249.40.33/24','gateway':'10.249.40.1','mac':link['address']})); settings.chmod(0o600)
        copy('proxy', settings, '/tmp/routing.json'); copy('proxy', ROOT / 'ingress_routing.py', '/tmp/ingress_routing.py')
        def helper(apply=False, check=True):
            args = ['python3', '/tmp/ingress_routing.py', '--config', '/tmp/routing.json'] + (['--apply'] if apply else [])
            return execute('proxy', *args, check=check)
        first = json.loads(helper(True).stdout); assert first['changed'] is True
        second = json.loads(helper(True).stdout); assert second['changed'] is False
        assert json.loads(helper().stdout)['status'] == 'passed'
        replies = {}
        for role, address in (('management','10.249.25.32'),('backend','10.249.25.34')):
            row = ip('proxy', 'route', 'get', address, 'from', '10.249.40.33')[0]
            assert row.get('gateway') == '10.249.40.1' and row['dev'] == link['ifname']
            execute(role, 'python3', '/tmp/client.py'); replies[role] = row
        assert ip('proxy', 'route', 'show', 'table', 'main') == main_before
        assert ip('proxy', 'route', 'get', '10.249.30.32')[0]['prefsrc'] == '10.249.30.33'
        assert ip('proxy', 'route', 'get', '203.0.113.7')[0]['gateway'] == '10.249.25.1'
        # Simulate fresh boot kernel state and use the same helper again.
        execute('proxy', 'ip', 'rule', 'del', 'priority', '10040')
        execute('proxy', 'ip', 'route', 'flush', 'table', '10040')
        assert json.loads(helper(True).stdout)['changed'] is True
        execute('backend', 'python3', '/tmp/client.py')
        execute('proxy', 'ip', 'route', 'add', '192.0.2.0/24', 'dev', link['ifname'], 'table', '10040')
        routes = ip('proxy', 'route', 'show', 'table', '10040')
        assert helper(True, check=False).returncode != 0
        assert ip('proxy', 'route', 'show', 'table', '10040') == routes
        result = dict(status='passed', baseline_reply=wrong, baseline_https_passed=negative.returncode == 0,
            verified_https=replies, repeat_unchanged=True, simulated_boot_reapplied=True,
            main_routes_unchanged=True, backend_route_unchanged=True, foreign_policy_preserved=True,
            strict_reverse_path_filter=True, stateful_router=True, external_routes_absent=True, native_host_contacted=False, published_ports=[])
        (output / 'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    except BaseException:
        diagnostics = {}
        for role in ('router','proxy','management','backend'):
            if names[role] not in containers: continue
            diagnostics[role] = {}
            for label, argv in (('addresses',['ip','-j','address','show']), ('rules',['ip','-j','rule','show']),
                    ('routes',['ip','-j','route','show','table','all']), ('neighbors',['ip','neighbor','show']),
                    ('forwarding',['cat','/proc/sys/net/ipv4/ip_forward']),
                    ('reverse_filter',['cat','/proc/sys/net/ipv4/conf/all/rp_filter'])):
                value = execute(role,*argv,check=False)
                diagnostics[role][label] = value.stdout + value.stderr
        diagnostics['router_firewall'] = execute('router','iptables','-L','FORWARD','-n','-v',check=False).stdout
        (output/'diagnostics.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
        raise
    finally:
        removed = [cli(['rm', '-f', name],check=False).returncode == 0 for name in reversed(containers)]
        removed += [cli(['network', 'rm', name],check=False).returncode == 0 for name in reversed(networks)]
        (output / 'cleanup.json').write_text(json.dumps({'all_removed':all(removed),'containers':containers,'networks':networks})+'\n')
        if not all(removed): raise RuntimeError('Routing fixture cleanup needs attention')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='homelab-routing-test:1')
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(run(args.image,args.output)))
