"""Exercise the selected pgAdmin image using only synthetic profile/OIDC data.

A disposable volume is first initialized by the stock image, including a saved
server. The same image then starts from that profile with the generated OAuth
configuration and no default-email/password variables. No real login, database,
credential, published port, or external container network is used.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid

from provider_fixture import certificate_files

IMAGE = 'dpage/pgadmin4@sha256:cefc4cc6b7d9d71a9e81e76fb9d7e14038ab5661b539a190eea1b63fa612589a'
IDENTITY = 'https://sso.example.invalid:9444'
PUBLIC = 'https://pgadmin.example.invalid'


def serve():
    class OIDC(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/application/o/pgadmin4/.well-known/openid-configuration':
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'issuer': IDENTITY + '/application/o/pgadmin4/',
                'authorization_endpoint': IDENTITY + '/application/o/authorize/',
                'token_endpoint': IDENTITY + '/application/o/token/',
                'userinfo_endpoint': IDENTITY + '/application/o/userinfo/',
                'jwks_uri': IDENTITY + '/application/o/pgadmin4/jwks/',
                'response_types_supported': ['code'], 'subject_types_supported': ['public'],
                'id_token_signing_alg_values_supported': ['RS256'],
            }).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 9444), OIDC)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/fixture/server.pem', '/fixture/server.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def request(method, path, body=None, cookie=None):
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    headers = {'Host': 'pgadmin.example.invalid', 'X-Forwarded-Host': 'pgadmin.example.invalid',
               'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '198.18.0.10'}
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if cookie:
        headers['Cookie'] = cookie
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.getheaders(), response.read().decode()
    finally:
        connection.close()


def ready():
    for attempt in range(240):
        try:
            if request('GET', '/misc/ping')[0] == 200:
                return
        except OSError:
            pass
        if attempt == 239:
            raise RuntimeError('Synthetic pgAdmin startup exceeded 120 seconds')
        time.sleep(0.5)


def check():
    ready()
    status, headers, body = request('GET', '/login')
    assert status == 200, (status, body[:300])
    # pgAdmin9.15 passes the token to the React login page in its JSON bootstrap.
    match = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', body)
    assert match, 'The actual login page must expose its CSRF bootstrap token'
    cookies = '; '.join(value.split(';', 1)[0] for key, value in headers if key.lower() == 'set-cookie')
    status, headers, body = request('POST', '/authenticate/login',
        urlencode({'oauth2_button': 'authentik', 'csrf_token': match[1]}), cookies)
    assert status == 302, (status, body[:300])
    target = dict(headers).get('Location', '')
    parsed = urlsplit(target)
    assert parsed.scheme == 'https' and parsed.netloc == 'sso.example.invalid:9444', target
    assert parsed.path == '/application/o/authorize/', target
    params = parse_qs(parsed.query)
    assert params['client_id'] == ['same-client']
    assert params['redirect_uri'] == [PUBLIC + '/oauth2/authorize'], params
    assert params['scope'] == ['openid email profile']
    assert params.get('state') and params.get('nonce')
    assert 'theaussiepom' not in target
    print('pgAdmin fixture passed: preserved profile starts without default credentials; '
          'generated config reaches trusted synthetic OIDC discovery and redirects to '
          'the selected HTTPS issuer/callback. Real login and database connectivity remain unverified.')


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, timeout=180, **kwargs)


def preserved_profile(container, *, expected_replacement=False):
    # The expected snapshot is an independent, explicit fixture projection.
    # Compare every table/cell, including references and sequence values: no
    # fields are masked or omitted from the complete profile digest.
    result = docker('exec', container, '/venv/bin/python3', '-c',
        '''import hashlib,json,sqlite3,sys
expected=sys.argv[1]=='expected'
c=sqlite3.connect("file:/var/lib/pgadmin/pgadmin4.db?mode=ro",uri=True)
c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
servers=c.execute("SELECT id,name,host,username,port,user_id FROM server ORDER BY id").fetchall()
assert servers
if expected:
    assert [s[0] for s in servers]==[1,2] and servers[1][5]==2
profile=[]
table_hashes={}
for name, in c.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
    quoted='"'+name.replace('"','""')+'"'
    columns=[r[1] for r in c.execute('PRAGMA table_info('+quoted+')')]
    rows=[list(r) for r in c.execute('SELECT * FROM '+quoted)]
    if expected:
        if name=='server':
            rows=[r for r in rows if r[columns.index('id')]==2]
            assert len(rows)==1 and rows[0][columns.index('user_id')]==2
            for field,value in {'id':3,'name':'PostgreSQL','host':'198.18.31.23','port':5432}.items():
                rows[0][columns.index(field)]=value
        elif name=='database':
            assert len(rows)==1 and rows[0][columns.index('server')]==2
            rows[0][columns.index('server')]=3
        elif name=='sqlite_sequence':
            for row in rows:
                if row[columns.index('name')]=='server':
                    assert row[columns.index('seq')]==2
                    row[columns.index('seq')]=3
        elif name=='query_history':
            rows=[r for r in rows if r[columns.index('sid')] not in (1,2)]
    if name=='server':
        servers=[[r[columns.index(k)] for k in ('id','name','host','username','port','user_id')] for r in rows]
    item=(name,columns,sorted(rows,key=repr))
    table_hashes[name]=hashlib.sha256(repr(item).encode()).hexdigest()
    profile.append(item)
print(json.dumps({'users':c.execute('SELECT id,email FROM user ORDER BY id').fetchall(),
    'servers':servers,'profile_sha256':hashlib.sha256(repr(profile).encode()).hexdigest(),
    'table_hashes':table_hashes}))''', 'expected' if expected_replacement else 'actual',
        capture_output=True, text=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    from test_foundation import fixture, render
    names = []
    volume = 'homelab-pgadmin-profile-' + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix='homelab-pgadmin-fixture-') as tmp:
        root = Path(tmp)
        certificate_files(root)
        cfg = fixture(root, 'db-tools')
        cfg['foundation']['identity_url'] = IDENTITY
        cfg['foundation']['public_url'] = PUBLIC
        for artifact in render.foundation_files(cfg):
            (root / artifact['path']).write_text(artifact['content'])
        (root / 'servers.json').write_text(json.dumps({'Servers': {'1': {
            'Name': 'Synthetic saved server', 'Group': 'Synthetic only',
            'Host': '127.0.0.1', 'Port': 5432, 'MaintenanceDB': 'postgres',
            'Username': 'fixture', 'SSLMode': 'prefer'}}}))
        # These files contain only generated fixture credentials/certificates.
        # Different test-container UIDs need read access; production modes and
        # ownership remain checked separately by test_foundation.py.
        root.chmod(0o755)
        for path in root.iterdir():
            path.chmod(0o644)
        try:
            docker('volume', 'create', volume, stdout=subprocess.DEVNULL)
            backend = 'homelab-pgadmin-oidc-' + uuid.uuid4().hex[:10]
            names.append(backend)
            common = ['run', '-d', '--platform', 'linux/amd64', '--cap-drop', 'ALL',
                      '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '512m',
                      '--pids-limit', '100', '-v', f'{root}:/fixture:ro']
            docker(*common, '--name', backend, '--network', 'none', '--read-only',
                   '--add-host', 'sso.example.invalid:127.0.0.1',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--entrypoint', 'python3',
                   '-v', f'{Path(__file__).resolve()}:/fixture.py:ro',
                   '-v', f'{Path(__file__).with_name("provider_fixture.py").resolve()}:/provider_fixture.py:ro',
                   args.tools_image, '/fixture.py', 'serve', stdout=subprocess.DEVNULL)
            baseline = 'homelab-pgadmin-initial-' + uuid.uuid4().hex[:10]
            names.append(baseline)
            # The official image places cap_net_bind_service on its Python
            # interpreter. Keep that one capability in the bounding set so
            # exec succeeds; its process remains the stock unprivileged UID.
            app = ['--cap-add', 'NET_BIND_SERVICE', '--network', 'container:' + backend,
                   '-v', f'{volume}:/var/lib/pgadmin',
                   '-e', 'PGADMIN_DISABLE_POSTFIX=1', '-e', 'PGADMIN_LISTEN_ADDRESS=0.0.0.0',
                   '-e', 'PGADMIN_LISTEN_PORT=80']
            docker(*common, '--name', baseline, *app,
                   '-e', 'PGADMIN_DEFAULT_EMAIL=operator@example.com',
                   '-e', 'PGADMIN_DEFAULT_PASSWORD=synthetic-fixture-only',
                   '-e', 'PGADMIN_CONFIG_CHECK_EMAIL_DELIVERABILITY=False',
                   '-e', 'PGADMIN_SERVER_JSON_FILE=/fixture/servers.json', IMAGE,
                   stdout=subprocess.DEVNULL)
            docker('exec', backend, 'python3', '/fixture.py', 'ready')
            # Two synthetic registrations mirror the admitted removal scope:
            # one local owner, one OAuth owner. Keep all real-image columns.
            docker('exec',baseline,'/venv/bin/python3','-c', '''import sqlite3
c=sqlite3.connect('/var/lib/pgadmin/pgadmin4.db')
def clone(table,changes):
    columns=[r[1] for r in c.execute('PRAGMA table_info("'+table+'")')]
    values=list(c.execute('SELECT * FROM "'+table+'" LIMIT 1').fetchone())
    for key,value in changes.items():
        if key in columns: values[columns.index(key)]=value
    c.execute('INSERT INTO "'+table+'" ('+','.join('"'+s+'"' for s in columns)+') VALUES ('+','.join('?' for _ in values)+')',values)
clone('user',{'id':2,'email':'oauth@example.invalid','username':'oauth-fixture','auth_source':'oauth2'})
clone('server',{'id':2,'user_id':2,'host':'postgresql','name':'OAuth synthetic server'})
c.execute('INSERT INTO "database"(id,server,schema_res) VALUES(?,?,?)',
          (12345,2,'retained_synthetic_schema'))
c.commit();c.close()''',stdout=subprocess.DEVNULL)
            before = preserved_profile(baseline)
            assert before['users'] and before['servers'][0][1] == 'Synthetic saved server', before
            expected = preserved_profile(baseline, expected_replacement=True)
            docker('stop', '--time', '20', baseline, stdout=subprocess.DEVNULL)
            docker('rm', baseline, stdout=subprocess.DEVNULL)
            names.remove(baseline)
            # Exercise the adapter only on this disposable, stopped profile.
            # The real shared controller must own guest admission and quiescence.
            selector = {'server_id': 2, 'user_id': 2}
            docker('run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
                   '--cap-drop', 'ALL', '--cap-add', 'NET_BIND_SERVICE',
                   '--security-opt', 'no-new-privileges', '--entrypoint', '/venv/bin/python3',
                   '-e', 'PYTHONDONTWRITEBYTECODE=1', '-v', f'{volume}:/var/lib/pgadmin',
                   '-v', f'{Path(__file__).resolve().parents[1] / "pgadmin_endpoint.py"}:/pgadmin_endpoint.py:ro',
                   IMAGE, '-c',
                   'import sqlite3,sys;sys.path.insert(0,"/");import pgadmin_endpoint as p;'
                   'c=sqlite3.connect("file:/var/lib/pgadmin/pgadmin4.db?mode=rw",uri=True);'
                   f's=p.replacement_plan(c,{selector!r},{{"host":"postgresql","port":5432}},'
                   '{"address":"198.18.31.23","port":5432});assert p.replacement_apply(c,s);c.close()',
                   stdout=subprocess.DEVNULL)
            migrated = 'homelab-pgadmin-migrated-' + uuid.uuid4().hex[:10]
            names.append(migrated)
            docker(*common, '--name', migrated, *app,
                   '-e', 'REQUESTS_CA_BUNDLE=/fixture/ca.pem',
                   '-v', f'{root / "pgadmin-config.py"}:/pgadmin4/config_local.py:ro',
                   '-v', f'{root / "oauth-client-secret"}:/run/secrets/oauth-client-secret:ro',
                   IMAGE, stdout=subprocess.DEVNULL)
            docker('exec', backend, 'python3', '/fixture.py', 'check')
            after=preserved_profile(migrated)
            assert after == expected, {'message':'Profile changed beyond the approved replacement',
                                      'expected':expected,'observed':after}
            print('Both synthetic registrations replaced by one fresh OAuth-owned registration; '
                  'retained role/TLS/encrypted settings and per-database schema restrictions '
                  'survive with only the database registration reference updated; all unrelated '
                  'profile values survive the replacement and OAuth configuration migration.')
        except Exception:
            for name in names:
                subprocess.run(['docker', 'logs', '--tail', '60', name], check=False, timeout=20)
            raise
        finally:
            for name in reversed(names):
                subprocess.run(['docker', 'rm', '-f', name], check=False, timeout=30,
                               stdout=subprocess.DEVNULL)
            subprocess.run(['docker', 'volume', 'rm', volume], check=False, timeout=30,
                           stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']:
        serve()
    elif sys.argv[1:] == ['ready']:
        ready()
    elif sys.argv[1:] == ['check']:
        check()
    else:
        main()
        from pgadmin_restart_fixture import run as restart_policy_fixture
        restart_policy_fixture()
