"""Local pinned OAuth gateway fixture; synthetic keys/accounts and mock services only."""
import ast
import base64
import copy
import datetime
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import tempfile
import tomllib
import traceback
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

PACKAGE = Path(__file__).resolve().parent
if os.environ.get('HOMELAB_FRAMEWORK'):
    FRAMEWORK = Path(os.environ['HOMELAB_FRAMEWORK']).resolve()
else:
    FRAMEWORK = next((parent for parent in Path(__file__).resolve().parents
                      if (parent/'proxmox/applications/cloudbeaver.py').is_file()), None)
    if FRAMEWORK is None:
        raise RuntimeError('Select the framework root with HOMELAB_FRAMEWORK')
IMAGE = 'quay.io/oauth2-proxy/oauth2-proxy:v7.15.5@sha256:0d989b27d90d5e527fb2b045d864c4001c3104bdd763b3211b7e9ba2110380ea'
CE_IMAGE = 'dbeaver/cloudbeaver:26.2.3@sha256:a537c60a7ca98d8d791c11c01172c1354e8dedfe222d04a54795ceeb32f12bbc'
DOCKER = ['docker'] + (['--context', os.environ['CLOUDBEAVER_DOCKER_CONTEXT']]
                      if os.environ.get('CLOUDBEAVER_DOCKER_CONTEXT') else [])
LINUX = sys.platform.startswith('linux')
REAL_CE = '--real-ce' in sys.argv
os.umask(0o077)
run_id = uuid.uuid4().hex
OUTPUT = Path(os.environ['CLOUDBEAVER_FIXTURE_OUTPUT']).resolve() if os.environ.get('CLOUDBEAVER_FIXTURE_OUTPUT') else Path(tempfile.mkdtemp(prefix='cloudbeaver-signed-oidc-'))
ROOT = OUTPUT/run_id
ROOT.mkdir(parents=True, mode=0o700)
ROOT.chmod(0o700)
container_name = 'cloudbeaver-oidc-fixture-' + run_id[:12]
result = {'schema': 'cloudbeaver-synthetic-gateway-fixture-v1', 'run_id': run_id,
          'image': IMAGE, 'native_or_private_targets': False, 'tests': [],
          'mode': 'combined-ce-and-gateway' if REAL_CE else 'gateway-header-echo',
          'fixture_source_sha256_at_start': hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()}
container_id = None
ce_id = network_id = None
network_name = 'cloudbeaver-fixture-net-' + run_id[:12]
ce_name = container_name+'-ce'
servers = []
cookie_records = []


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def record(name, condition, **flags):
    result['tests'].append({'name': name, 'passed': bool(condition), **flags})
    if not condition:
        raise AssertionError(name)


def docker(*args, timeout=30, check=True):
    return subprocess.run([*DOCKER, *args], capture_output=True, text=True,
                          timeout=timeout, check=check)


def write(path, value, mode=0o600, *, replace_existing=False):
    value = value if isinstance(value, bytes) else value.encode()
    if path.exists() and not path.stat().st_mode & 0o200:
        if path.read_bytes() == value:
            return
        if not replace_existing or path.is_symlink() or path.stat().st_uid != os.geteuid():
            raise RuntimeError('Refuse rewriting immutable synthetic fixture output')
        path.chmod(0o600)
    path.write_bytes(value)
    path.chmod(mode)


def issue_certificates():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic CloudBeaver Fixture CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=5))
          .not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'cloud.fixture.test')]))
            .issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=5))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('cloud.fixture.test'), x509.DNSName('host.docker.internal')]), False)
            .sign(ca_key, hashes.SHA256()))
    write(ROOT/'test-ca.pem', ca.public_bytes(serialization.Encoding.PEM), 0o444)
    write(ROOT/'server.pem', leaf.public_bytes(serialization.Encoding.PEM))
    write(ROOT/'server.key', key.private_bytes(serialization.Encoding.PEM,
          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b'', **headers):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name.replace('_', '-'), value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Provider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes = {}
        self.access = {}
        self.mode = 'valid'
        self.username = 'fixture-user'
        self.signed_tokens = self.pkce_verified = 0
        self.client_id = 'synthetic-cloudbeaver-client'
        self.client_secret = 'synthetic-retained-client-secret-with-high-entropy-for-local-tests-only'
        self.issuer = ''
        self.public_url = ''

    def claims(self, nonce, mode, username):
        now = int(time.time())
        return {'iss': self.issuer if mode != 'wrong_issuer' else self.issuer+'wrong/',
                'aud': self.client_id if mode != 'wrong_audience' else 'wrong-client',
                'exp': now+300, 'iat': now-1, 'sub': 'synthetic-subject-123',
                'nonce': nonce if mode != 'bad_nonce' else 'wrong-nonce',
                'email': 'fixture-user@example.invalid', 'email_verified': True,
                'preferred_username': username, 'groups': ['user', 'admin']}

    def jwt(self, claims, mode):
        body = (b64(json.dumps({'alg': 'RS256', 'kid': 'synthetic-fixture-key'}).encode()) + '.'
                + b64(json.dumps(claims).encode()))
        key = self.wrong_key if mode == 'bad_signature' else self.key
        self.signed_tokens += 1
        return body + '.' + b64(key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256()))


provider = Provider()
seen_upstream = []
HEADERS = ()


class OIDC(Quiet):
    def do_GET(self):
        path = urlsplit(self.path).path.rstrip('/')
        base = provider.issuer.rstrip('/')
        if path.endswith('/.well-known/openid-configuration'):
            self.reply(200, {'issuer': provider.issuer, 'authorization_endpoint': base+'/authorize',
                'token_endpoint': base+'/token', 'userinfo_endpoint': base+'/userinfo',
                'jwks_uri': base+'/jwks', 'response_types_supported': ['code'],
                'subject_types_supported': ['public'], 'id_token_signing_alg_values_supported': ['RS256'],
                'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
                'code_challenge_methods_supported': ['S256']}, Content_Type='application/json')
        elif path.endswith('/jwks'):
            public = provider.key.public_key().public_numbers()
            integer = lambda x: b64(x.to_bytes((x.bit_length()+7)//8, 'big'))
            self.reply(200, {'keys': [{'kty': 'RSA', 'kid': 'synthetic-fixture-key', 'use': 'sig',
                'alg': 'RS256', 'n': integer(public.n), 'e': integer(public.e)}]}, Content_Type='application/json')
        elif path.endswith('/authorize'):
            query = parse_qs(urlsplit(self.path).query)
            assert query['client_id'] == [provider.client_id]
            assert query['redirect_uri'] == [provider.public_url+'/oauth2/callback']
            assert query['code_challenge_method'] == ['S256']
            code = secrets.token_urlsafe(24)
            provider.codes[code] = {'nonce': query.get('nonce', [''])[0],
                'challenge': query['code_challenge'][0], 'mode': provider.mode,
                'username': provider.username}
            location = query['redirect_uri'][0] + '?' + urlencode({'code': code, 'state': query['state'][0]})
            self.reply(302, Location=location)
        elif path.endswith('/userinfo'):
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            if token not in provider.access:
                self.reply(401)
            else:
                self.reply(200, provider.access[token], Content_Type='application/json')
        else:
            self.reply(404)

    def do_POST(self):
        if not urlsplit(self.path).path.rstrip('/').endswith('/token'):
            self.reply(404); return
        query = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
        basic = self.headers.get('Authorization', '')
        if basic.startswith('Basic '):
            client, secret = base64.b64decode(basic[6:]).decode().split(':', 1)
        else:
            client, secret = query.get('client_id', [''])[0], query.get('client_secret', [''])[0]
        if client != provider.client_id or secret != provider.client_secret:
            self.reply(401); return
        code = query.get('code', [''])[0]
        if code not in provider.codes:
            self.reply(400); return
        row = provider.codes.pop(code)
        if b64(hashlib.sha256(query['code_verifier'][0].encode()).digest()) != row['challenge']:
            self.reply(400); return
        provider.pkce_verified += 1
        claims = provider.claims(row['nonce'], row['mode'], row['username'])
        access = secrets.token_urlsafe(32)
        provider.access[access] = claims
        self.reply(200, {'access_token': access, 'token_type': 'Bearer', 'expires_in': 300,
            'id_token': provider.jwt(claims, row['mode']), 'scope': 'openid email profile'}, Content_Type='application/json')


class Echo(Quiet):
    def do_GET(self):
        allowed = {name.lower() for name in HEADERS}
        values = {}
        for name, value in self.headers.items():
            if name.lower().replace('_', '-') in allowed:
                values.setdefault(name.lower(), []).append(value)
        seen_upstream.append(values)
        self.reply(200, {'identity_headers': values}, Content_Type='application/json')


gateway_port = None


class Frontdoor(Quiet):
    def do_GET(self):
        headers = {name: value for name, value in self.headers.items()
                   if name.lower() not in {'connection', 'host', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port'}}
        origin = urlsplit(provider.public_url)
        headers.update({'Host': origin.netloc, 'X-Forwarded-Proto': 'https',
                        'X-Forwarded-Host': origin.netloc, 'X-Forwarded-Port': str(origin.port)})
        conn = http.client.HTTPConnection('127.0.0.1', gateway_port, timeout=15)
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if size > 65536:
                self.reply(413); return
            body = self.rfile.read(size) if size else None
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse(); body = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {'connection', 'transfer-encoding', 'content-length'}:
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        finally:
            conn.close()

    do_POST = do_GET


def server(handler, tls=False):
    # Linux containers reach this ephemeral synthetic service through host-gateway.
    bind = '0.0.0.0' if LINUX and handler in {OIDC, Echo} else '127.0.0.1'
    service = http.server.ThreadingHTTPServer((bind, 0), handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT/'server.pem', ROOT/'server.key')
        service.socket = context.wrap_socket(service.socket, server_side=True)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    servers.append(service)
    return service.server_port


request_id = 0


def get(url, jar, headers=None, query=None):
    global request_id
    request_id += 1
    body_path, header_path = ROOT/f'response-{request_id}.body', ROOT/f'response-{request_id}.headers'
    issuer, origin = urlsplit(provider.issuer), urlsplit(provider.public_url)
    args = ['curl', '--silent', '--show-error', '--noproxy', '*', '--max-time', '20',
        '--cacert', str(ROOT/'test-ca.pem'), '--resolve', f'{issuer.hostname}:{issuer.port}:127.0.0.1',
        '--resolve', f'{origin.hostname}:{origin.port}:127.0.0.1', '--cookie', str(jar),
        '--cookie-jar', str(jar), '--dump-header', str(header_path), '--output', str(body_path),
        '--write-out', '%{http_code}']
    for name, value in (headers or {}).items():
        args += ['--header', name+': '+value]
    if query is not None:
        args += ['--request', 'POST', '--header', 'Content-Type: application/json',
                 '--header', 'Origin: '+provider.public_url, '--data-raw', json.dumps({'query': query})]
    response = subprocess.run([*args, url], capture_output=True, text=True, timeout=25)
    if response.returncode:
        raise RuntimeError('Synthetic curl request failed with exit '+str(response.returncode))
    parsed_headers = {}
    for line in header_path.read_text().splitlines():
        if ':' in line:
            name, value = line.split(':', 1)
            parsed_headers.setdefault(name.lower(), []).append(value.strip())
    for line in parsed_headers.get('set-cookie', []):
        fields = [field.strip() for field in line.split(';')]
        name, value = fields[0].split('=', 1)
        if value and 'max-age=0' not in {field.lower() for field in fields[1:]}:
            attrs = {field.split('=', 1)[0].lower(): field.split('=', 1)[-1]
                     for field in fields[1:]}
            cookie_records.append({'name': name, 'secure': 'secure' in attrs,
                'httponly': 'httponly' in attrs, 'samesite': attrs.get('samesite', '')})
    return int(response.stdout), parsed_headers, body_path.read_bytes()


def login(mode='valid', username='fixture-user'):
    provider.mode, provider.username = mode, username
    jar = ROOT/('cookie-'+uuid.uuid4().hex+'.txt')
    url = provider.public_url+'/'
    statuses = []
    for _ in range(8):
        status, headers, body = get(url, jar)
        statuses.append(status)
        if status not in {301, 302, 303, 307, 308}:
            return jar, status, body, statuses
        location = headers.get('location', [''])[0]
        url = urljoin(url, location)
        allowed = {urlsplit(provider.issuer).netloc, urlsplit(provider.public_url).netloc}
        if urlsplit(url).netloc not in allowed:
            raise RuntimeError('Synthetic provider attempted a foreign redirect')
    raise RuntimeError('Synthetic redirect loop')


def start_community(module, selected, value):
    global ce_id, network_id
    sys.modules['cloudbeaver'] = module
    sys.path.insert(0, str(FRAMEWORK/'proxmox/applications/tests'))
    import render
    from test_cloudbeaver import fixture
    cfg = fixture()
    cfg['foundation'] = dict(selected, version=1,
                             secret_files={'oauth_client_secret': '/synthetic/oauth-secret'})
    cfg['cloudbeaver'].update(value, recovery_admin='local-recovery')
    cfg['services']['cloudbeaver']['image'] = CE_IMAGE
    cfg['services']['auth_gateway']['image'] = IMAGE
    rows = module.files(cfg, provider.client_secret.encode())
    for row in rows:
        write(ROOT/row['path'], row['content'], 0o444)
    workspace = ROOT/'workspace'; workspace.mkdir(mode=0o777); workspace.chmod(0o777)
    destination = workspace/'GlobalConfiguration/.dbeaver'
    destination.mkdir(parents=True); destination.parent.chmod(0o777); destination.chmod(0o777)
    write(destination/'data-sources-permissions.json', (ROOT/'cloudbeaver-permissions.json').read_bytes(), 0o444)
    compose = render.compose(cfg); service = compose['services']['cloudbeaver']
    write(ROOT/'generated-compose.json', json.dumps(compose, sort_keys=True))
    network_id = docker('network', 'create', '--label', 'org.homelab.fixture.owner='+run_id, network_name).stdout.strip()
    # Compose preserves the exact generated CMD-form healthcheck, including its
    # argv boundaries. A CLI --health-cmd would silently convert it to a shell.
    ce_service = copy.deepcopy(service)
    ce_service.update(container_name=ce_name, platform='linux/amd64', pull_policy='never')
    ce_service.setdefault('labels', {})['org.homelab.fixture.owner'] = run_id
    ce_service['volumes'][0]['source'] = str(workspace)
    for mount in ce_service['volumes'][1:]:
        mount['source'] = str(ROOT/Path(mount['source']).name)
    compose_file = ROOT/'community-fixture-compose.json'
    write(compose_file, json.dumps({'services': {'cloudbeaver': ce_service},
        'networks': {'database_tools': {'external': True, 'name': network_name}}}, indent=2))
    docker('compose', '--project-name', container_name, '--file', str(compose_file),
           'up', '--detach', '--no-deps', 'cloudbeaver', timeout=45)
    ce_id = docker('compose', '--project-name', container_name, '--file', str(compose_file),
                   'ps', '--all', '--quiet', 'cloudbeaver').stdout.strip()
    deadline = time.monotonic()+180
    while time.monotonic() < deadline:
        info = json.loads(docker('inspect', ce_id).stdout)[0]
        write(ROOT/'community-health-state.json', json.dumps(info['State'], indent=2))
        if not info['State']['Running']:
            raise RuntimeError('Synthetic Community container exited before health')
        if info['State'].get('Health', {}).get('Status') == 'healthy':
            record('fresh_community_healthy_and_unpublished', not info['HostConfig']['PortBindings']
                and info['Config']['User'] == '8978:8978')
            command = service['healthcheck']['test']
            argv = ['sh', '-c', command[1]] if command[0] == 'CMD-SHELL' else command[1:]
            exact = docker('exec', ce_id, *argv, check=False)
            record('exact_generated_compose_health_command_passes', exact.returncode == 0,
                   exit_code=exact.returncode)
            break
        time.sleep(.5)
    else:
        raise RuntimeError('Fresh synthetic Community startup deadline')
    result['community_image'] = CE_IMAGE
    result['exact_generated_compose_health_command'] = service['healthcheck']['test']
    result['generated_runtime_files'] = {row['path']: hashlib.sha256(row['content'].encode()).hexdigest() for row in rows}
    result['fixture_file_difference'] = 'Synthetic nonroot UID fixture file modes inside a private output directory; no real credentials or production ownership proof.'
    # Keep the source curl/body unchanged; only replace Compose's transport
    # selection with Docker exec for this exclusively owned local container.
    runtime = (FRAMEWORK/'proxmox/applications/cloudbeaver-runtime.py').read_bytes()
    write(ROOT/'frozen-cloudbeaver-runtime.py', runtime)
    health = next(node for node in ast.parse(runtime.decode()).body if isinstance(node, ast.FunctionDef) and node.name == 'health')
    call = next(node for node in ast.walk(health) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == 'docker'
                and node.args and isinstance(node.args[0], ast.List)
                and any(isinstance(item, ast.Constant) and item.value == 'exec' for item in node.args[0].elts))
    elements = call.args[0].elts
    index = next(i for i, item in enumerate(elements) if isinstance(item, ast.Constant) and item.value == 'cloudbeaver')
    argv = [ast.literal_eval(item) for item in elements[index+1:]]
    query = next((node.value.args[0] for node in health.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == 'query' for target in node.targets)), None)
    reply = subprocess.run([*DOCKER, 'exec', '-i', ce_id, *argv],
        input=json.dumps(ast.literal_eval(query)) if query is not None else None,
        capture_output=True, text=True, timeout=15)
    write(ROOT/'runtime-health-command.json', json.dumps({'argv': argv, 'exit_code': reply.returncode,
          'stdout': reply.stdout, 'stderr': reply.stderr}))
    data = json.loads(reply.stdout)['data']['serverConfig'] if reply.returncode == 0 else {}
    record('exact_runtime_health_command_passes', reply.returncode == 0 and data.get('configurationMode') is False
           and data.get('anonymousAccessEnabled') is False
           and data.get('forceHttps') is True
           and set(data.get('enabledAuthProviders', [])) == {'local', 'reverseProxy'})
    return cfg


def combined_checks(cfg):
    forged = {name: 'admin' if name in {'X-Team', 'X-Role', 'X-Role-TE', 'X-Forwarded-Groups'} else 'local-recovery'
              for name in HEADERS}
    for name, headers in [('missing_session', forged),
                          ('bogus_session', forged | {'Cookie': '__Host-cloudbeaver=bogus'})]:
        status, _, _ = get(provider.public_url+'/', ROOT/(name+'-cookies.txt'), headers)
        record(name+'_forgery_requires_signin', status == 302, status=status)
    query = ('{activeUser{userId authRole teams{teamId}} sessionPermissions userConnections{id name} '
             'serverConfig{configurationMode anonymousAccessEnabled forceHttps}}')
    for username in ['fixture-user', cfg['cloudbeaver']['recovery_admin']]:
        jar, status, _, statuses = login(username=username)
        record('signed_pkce_login_for_'+username, status == 200, statuses=statuses)
        headers = forged | {name.replace('-', '_'): value for name, value in forged.items()}
        status, _, body = get(provider.public_url+'/api/gql', jar, headers, 'mutation{openSession{valid}}')
        value = json.loads(body)
        record('real_ce_open_session_for_'+username, status == 200 and not value.get('errors')
               and value['data']['openSession']['valid'])
        status, _, body = get(provider.public_url+'/api/gql', jar, headers, query)
        value = json.loads(body)
        if value.get('errors'):
            write(ROOT/'ce-query-errors.json', json.dumps(value))
            raise RuntimeError('Community query rejected declared read-only fields')
        data = value['data']; user = data['activeUser']
        record('real_ce_non_admin_namespaced_identity_for_'+username,
            user['userId'] == 'oidc.'+username and user['authRole'] != 'admin'
            and user['teams'] == [{'teamId': 'user'}] and data['sessionPermissions'] == [])
        record('both_metadata_connections_visible_for_'+username,
            {item['name'] for item in data['userConnections']} == {'PostgreSQL', 'MariaDB'})
        record('real_ce_setup_closed_anonymous_off_https_on_for_'+username,
            data['serverConfig'] == {'configurationMode': False, 'anonymousAccessEnabled': False, 'forceHttps': True})
    record('gateway_and_community_session_cookies_secure_httponly_without_samesite_none',
        any(row['name'].startswith('__Host-cloudbeaver') for row in cookie_records)
        and any(not row['name'].startswith('__Host-cloudbeaver') for row in cookie_records)
        and all(row['secure'] and row['httponly'] and row['samesite'].lower() != 'none' for row in cookie_records),
        cookies=[dict(row) for row in cookie_records])
    details = json.loads(docker('inspect', ce_id).stdout)[0]
    record('community_stays_capped_nonroot_without_oom', details['State']['Running']
        and not details['State']['OOMKilled'] and details['RestartCount'] == 0
        and details['HostConfig']['Memory'] == 1536*1024*1024)
    result['community_image_id'] = details['Image']


def start_gateway(common, stage):
    global container_id, gateway_port
    config_test = docker('run', '--rm', '--name', container_name+'-config',
                        '--label', 'org.homelab.fixture.owner='+run_id, *common,
                        IMAGE, '--config=/etc/oauth2-proxy/oauth2.cfg',
                       '--alpha-config=/etc/oauth2-proxy/alpha.json', '--config-test', check=False)
    write(ROOT/('config-test-'+stage+'.log'), config_test.stdout+config_test.stderr)
    record('pinned_generated_configuration_test'+('' if stage == 'echo' else '_community'), config_test.returncode == 0, exit_code=config_test.returncode)
    started = docker('run', '-d', '--name', container_name,
        '--label', 'org.homelab.fixture=cloudbeaver-signed-oidc', '--label', 'org.homelab.fixture.owner='+run_id,
        '--publish', '127.0.0.1::4180', *common, IMAGE,
        '--config=/etc/oauth2-proxy/oauth2.cfg', '--alpha-config=/etc/oauth2-proxy/alpha.json')
    container_id = started.stdout.strip()
    details = json.loads(docker('inspect', container_id).stdout)[0]
    gateway_port = int(details['NetworkSettings']['Ports']['4180/tcp'][0]['HostPort'])
    deadline = time.monotonic()+30
    while True:
        try:
            conn = http.client.HTTPConnection('127.0.0.1', gateway_port, timeout=2)
            conn.request('GET', '/ping'); response = conn.getresponse(); response.read(); conn.close()
            if response.status == 200:
                break
        except (ConnectionError, OSError, http.client.HTTPException):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError('Synthetic gateway did not become ready')
        time.sleep(.2)


def echo_checks():
    forged = {name: ('admin' if name in {'X-Team', 'X-Role', 'X-Role-TE', 'X-Forwarded-Groups'}
                     else 'forged-recovery-admin') for name in HEADERS}
    status, _, _ = get(provider.public_url+'/', ROOT/'anonymous-cookies.txt', forged)
    record('anonymous_with_forged_identity_does_not_reach_upstream', status == 302 and not seen_upstream, status=status)
    status, _, _ = get(provider.public_url+'/', ROOT/'bogus-cookies.txt',
                       forged | {'Cookie': '__Host-cloudbeaver=not-a-valid-session'})
    record('bogus_session_with_forged_identity_does_not_reach_upstream', status == 302 and not seen_upstream, status=status)
    jar, status, body, statuses = login()
    expected = {'x-user': ['oidc.fixture-user'], 'x-team': ['user']}
    record('signed_pkce_oidc_login_reaches_upstream', status == 200 and json.loads(body)['identity_headers'] == expected,
           statuses=statuses, verified_pkce=provider.pkce_verified > 0, signed_tokens=provider.signed_tokens)
    for name in HEADERS:
        status, _, body = get(provider.public_url+'/', jar, {name.swapcase(): forged[name]})
        record('authenticated_forgery_is_overwritten_or_removed_'+name,
               status == 200 and json.loads(body)['identity_headers'] == expected)
        status, _, body = get(provider.public_url+'/', jar, {name.replace('-', '_'): forged[name]})
        record('underscore_header_forgery_is_overwritten_or_removed_'+name,
               status == 200 and json.loads(body)['identity_headers'] == expected)
    status, _, body = get(provider.public_url+'/', jar, forged)
    record('all_forged_identity_headers_are_filtered_together', status == 200 and json.loads(body)['identity_headers'] == expected)
    jar, status, body, statuses = login(username='local-recovery')
    record('upstream_recovery_name_is_oidc_namespaced_and_static_user_team', status == 200 and
        json.loads(body)['identity_headers'] == {'x-user': ['oidc.local-recovery'], 'x-team': ['user']}, statuses=statuses)
    for mode in ['bad_signature', 'bad_nonce', 'wrong_audience', 'wrong_issuer']:
        before = len(seen_upstream)
        _, status, _, statuses = login(mode=mode)
        record(mode+'_token_refuses_authenticated_upstream', status != 200 and len(seen_upstream) == before,
               terminal_status=status, statuses=statuses)
    details = json.loads(docker('inspect', container_id).stdout)[0]
    record('capped_nonroot_gateway_stays_running_without_oom_or_restart',
        details['State']['Running'] and not details['State']['OOMKilled'] and details['RestartCount'] == 0
        and details['Config']['User'] == '65532:65532' and details['HostConfig']['ReadonlyRootfs'],
        running=details['State']['Running'], oom_killed=details['State']['OOMKilled'], restarts=details['RestartCount'])
    result['echo_gateway_image_id'] = details['Image']
    result['echo_authentication_controls_passed'] = 32


def main():
    global HEADERS, gateway_port, container_id
    runner = Path(__file__).resolve().read_bytes()
    if hashlib.sha256(runner).hexdigest() != result['fixture_source_sha256_at_start']:
        raise RuntimeError('Fixture source changed before snapshot')
    write(ROOT/'fixture-runner.py', runner)
    source = FRAMEWORK/'proxmox/applications/cloudbeaver.py'
    source_bytes = source.read_bytes()
    frozen = ROOT/'frozen-cloudbeaver.py'; write(frozen, source_bytes)
    java = source.with_name('CloudBeaverHealth.java')
    if java.is_file():
        write(ROOT/java.name, java.read_bytes())
        result['health_java_source_sha256'] = hashlib.sha256(java.read_bytes()).hexdigest()
    sys.path.insert(0, str(FRAMEWORK/'proxmox/applications'))
    spec = importlib.util.spec_from_file_location('frozen_gateway_source', frozen)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    HEADERS = module.HEADERS
    tree = ast.parse(source_bytes.decode())
    selected_source = '\n'.join(ast.get_source_segment(source_bytes.decode(), node)
        for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {'gateway', 'derive'})
    result['framework_module_sha256'] = hashlib.sha256(source_bytes).hexdigest()
    result['gateway_and_derive_source_sha256'] = hashlib.sha256(selected_source.encode()).hexdigest()
    issue_certificates()
    provider_port = server(OIDC, tls=True)
    echo_port = server(Echo)
    frontdoor_port = server(Frontdoor, tls=True)
    provider.issuer = f'https://host.docker.internal:{provider_port}/oidc/'
    provider.public_url = f'https://cloud.fixture.test:{frontdoor_port}'
    value = {'public_url': provider.public_url, 'auth_headers': {'user': 'X-User', 'team': 'X-Team'}}
    selected = {'oauth_name': 'Synthetic issuer', 'oauth_client_id': provider.client_id,
                'oidc_issuer': provider.issuer, 'user_claim': 'preferred_username'}
    cfg = start_community(module, selected, value) if REAL_CE else None
    alpha, options = module.gateway(value, selected, provider.client_secret.encode())
    material = module.derive(provider.client_secret.encode(), 'session-cookie')
    encoded_cookie = tomllib.loads(options)['cookie_secret']
    record('urlsafe_cookie_preserves_32byte_hmac_with_standard_base64_specials',
           len(material) == 32 and bool(set(base64.b64encode(material).decode()) & set('+/'))
           and not set(encoded_cookie) & set('+/')
           and base64.urlsafe_b64decode(encoded_cookie) == material)
    write(ROOT/'generated-alpha.json', json.dumps(alpha, indent=2), 0o444)
    # Only the destination is replaced for the finite local mock. Authentication
    # headers, providers and all cookie/login controls remain generated unchanged.
    generated_alpha = copy.deepcopy(alpha)
    alpha['upstreamConfig']['upstreams'][0]['uri'] = f'http://host.docker.internal:{echo_port}'
    write(ROOT/'fixture-alpha.json', json.dumps(alpha, indent=2), 0o444)
    write(ROOT/'echo-alpha.json', json.dumps(alpha, indent=2), 0o444)
    if REAL_CE:
        if tomllib.loads((ROOT/'oauth2.cfg').read_text()) != tomllib.loads(options):
            raise RuntimeError('Generated gateway options differ across source paths')
    else:
        write(ROOT/'oauth2.cfg', options, 0o444)
    result['fixture_only_config_delta'] = {'echo': ['upstreamConfig.upstreams[0].uri (local echo destination)'], 'community': [] if REAL_CE else None}
    mounts = ['--mount', f'type=bind,src={ROOT/"fixture-alpha.json"},dst=/etc/oauth2-proxy/alpha.json,readonly',
              '--mount', f'type=bind,src={ROOT/"oauth2.cfg"},dst=/etc/oauth2-proxy/oauth2.cfg,readonly',
              '--mount', f'type=bind,src={ROOT/"test-ca.pem"},dst=/etc/test-ca.pem,readonly']
    common = ['--pull=never', '--platform=linux/amd64', '--user=65532:65532', '--read-only', '--memory=128m', '--cpus=1',
              '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
              '--env=GOMEMLIMIT=96MiB', '--env=SSL_CERT_FILE=/etc/test-ca.pem', *mounts]
    if LINUX:
        common += ['--add-host=host.docker.internal:host-gateway']
    if REAL_CE:
        common += ['--network', network_name]
    start_gateway(common, 'echo')
    echo_checks()
    if REAL_CE:
        prior = json.loads(docker('inspect', container_id).stdout)[0]
        if prior['Config']['Labels'].get('org.homelab.fixture.owner') != run_id:
            raise RuntimeError('Owned synthetic gateway identity changed')
        logs = docker('logs', container_id, check=False)
        write(ROOT/'echo-gateway.log', logs.stdout+logs.stderr)
        docker('rm', '--force', container_id)
        container_id = None
        alpha['upstreamConfig']['upstreams'][0]['uri'] = 'http://cloudbeaver:8978'
        original = (ROOT/'oauth2-alpha.json').read_bytes()
        if json.loads(original) != alpha:
            raise RuntimeError('Generated Community gateway alpha differs')
        write(ROOT/'fixture-alpha.json', original, 0o444, replace_existing=True)
        write(ROOT/'community-alpha.json', original, 0o444)
        record('community_uses_exact_generated_alpha_configuration', alpha == generated_alpha)
        start_gateway(common, 'community')
        combined_checks(cfg)
        details = json.loads(docker('inspect', container_id).stdout)[0]
        record('gateway_stays_capped_nonroot_readonly_without_oom', details['State']['Running']
            and not details['State']['OOMKilled'] and details['RestartCount'] == 0
            and details['Config']['User'] == '65532:65532' and details['HostConfig']['ReadonlyRootfs'])
        result['actual_gateway_image_id'] = details['Image']
    result.update(status='PASS', real_signed_oidc=True, verified_pkce=provider.pkce_verified,
                  upstream_requests=len(seen_upstream), database_connection_actions_executed=False)



def execute():
    try:
        main()
    except Exception as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error))
        write(ROOT/'exception.log', traceback.format_exc())
    finally:
        for owned in (container_id or container_name, container_name+'-config', ce_id or ce_name):
            info = docker('inspect', owned, check=False)
            if info.returncode == 0:
                details = json.loads(info.stdout)[0]
                if details['Config']['Labels'].get('org.homelab.fixture.owner') == run_id:
                    logs = docker('logs', details['Id'], check=False)
                    logfile = 'community.log' if owned == (ce_id or ce_name) else 'config-container.log' if owned == container_name+'-config' else 'gateway.log'
                    write(ROOT/logfile, logs.stdout+logs.stderr)
                    removed = docker('rm', '--force', details['Id'], check=False)
                    result['owned_fixture_container_removed'] = removed.returncode == 0
        if network_id:
            info = docker('network', 'inspect', network_id, check=False)
            if info.returncode == 0:
                value = json.loads(info.stdout)[0]
                if value['Labels'].get('org.homelab.fixture.owner') == run_id and not value['Containers']:
                    result['owned_fixture_network_removed'] = docker('network', 'rm', network_id, check=False).returncode == 0
        for service in servers:
            service.shutdown(); service.server_close()
        result['source_files'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (ROOT/'fixture-runner.py', ROOT/'frozen-cloudbeaver.py', ROOT/'frozen-cloudbeaver-runtime.py', ROOT/'CloudBeaverHealth.java') if path.exists()}
        write(ROOT/'result.json', json.dumps(result, indent=2)+'\n')
        print(json.dumps({'status': result['status'], 'tests': len(result['tests']),
            'failed_tests': [row['name'] for row in result['tests'] if not row['passed']],
            'error_type': result.get('error_type'), 'error': result.get('error'),
            'result': str(ROOT/'result.json')}))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == "__main__":
    execute()
