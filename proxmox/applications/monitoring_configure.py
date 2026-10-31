"""Configure the owned Zabbix server through its guest-local API.

Run within the normal guest deployment attempt and failure hold. The first run
changes the factory password; subsequent runs use the retained private password.
No history import, unknown-host adoption, key rotation or destructive import.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROFILE_TEMPLATES = {
    'linux': 'Linux by Zabbix agent active',
    'docker': 'HomeLab Docker by active agent 2',
    'postgresql': 'PostgreSQL by Zabbix agent 2 active',
    'mysql': 'MySQL by Zabbix agent 2 active',
    'influxdb': 'InfluxDB by HTTP',
}


def require(value, message):
    if not value:
        raise ValueError(message)


class RefuseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Monitoring API redirects are not permitted')


class API:
    def __init__(self, port=8081):
        require(type(port) is int and 1024 <= port <= 65535, 'Use a guest-local API port')
        self.endpoint = 'http://127.0.0.1:' + str(port) + '/api_jsonrpc.php'
        self.opener = build_opener(ProxyHandler({}), RefuseRedirects())
        self.token = None
        self.last_error = None

    def __call__(self, method, params):
        headers = {'Content-Type': 'application/json-rpc'}
        if self.token and method not in {'user.login', 'apiinfo.version'}:
            headers['Authorization'] = 'Bearer ' + self.token
        request = Request(self.endpoint, headers=headers,
                          data=json.dumps({'jsonrpc': '2.0', 'id': 1,
                                           'method': method, 'params': params}).encode())
        with self.opener.open(request, timeout=20) as response:
            require(response.length is None or response.length <= 4_000_000,
                    'Monitoring API response exceeds its bound')
            raw = response.read(4_000_001)
        require(len(raw) <= 4_000_000, 'Monitoring API response exceeds its bound')
        value = json.loads(raw)
        if 'error' in value:
            self.last_error = {'method': method, 'code': value['error'].get('code'),
                               'data_sha256': hashlib.sha256(str(value['error'].get('data', '')).encode()).hexdigest()}
        require('result' in value and 'error' not in value, 'Monitoring API operation failed')
        return value['result']


def marker(kind, identity, secret):
    return ('HomeLab blueprint ' + kind + '; identity=' + identity
            + '; credential=' + hashlib.sha256(secret.encode()).hexdigest())


def template_ids(call, names):
    rows = call('template.get', {'filter': {'host': sorted(names)}, 'output': ['templateid', 'host']})
    require(len(rows) == len(names) and {r['host'] for r in rows} == set(names),
            'A selected monitoring template is missing')
    return {r['host']: r['templateid'] for r in rows}


def host(call, name, description, group, templates, **extra):
    rows = call('host.get', {'filter': {'host': [name]}, 'output': ['hostid', 'description'],
                             'selectParentTemplates': ['templateid'],
                             'selectMacros': ['hostmacroid', 'macro', 'type']})
    require(len(rows) <= 1, 'Duplicate monitoring host identity')
    selected = {'host': name, 'description': description,
                'groups': [{'groupid': group}], 'templates': [{'templateid': t} for t in templates],
                'status': 0, **extra}
    if rows:
        require(rows[0]['description'] == description,
                'Unknown monitoring identity or changed credential; no adoption or rotation')
        require({r['templateid'] for r in rows[0]['parentTemplates']} <= set(templates),
                'Preserve unexpected monitoring templates for review')
        # Zabbix does not return PSKs. The private record and ownership digest
        # bind their identity; never replay a write-only secret on an update.
        selected.pop('tls_psk', None)
        selected.pop('tls_psk_identity', None)
        selected.pop('host')
        macros = selected.pop('macros', [])
        call('host.update', {'hostid': rows[0]['hostid'], **selected})
        for macro in macros:
            old = [m for m in rows[0].get('macros', []) if m['macro'] == macro['macro']]
            require(len(old) <= 1, 'Duplicate monitored host macro identity')
            if old and macro.get('type') == 1:
                require(str(old[0]['type']) == '1', 'Preserve the existing secret macro type')
                continue
            if old:
                call('usermacro.update', {'hostmacroid': old[0]['hostmacroid'],
                                         'value': macro['value'], 'type': macro.get('type', 0)})
            else:
                call('usermacro.create', {'hostid': rows[0]['hostid'], **macro})
        return rows[0]['hostid']
    value = call('host.create', {'interfaces': [], **selected})
    return value['hostids'][0]


def configure(call, value, receipt):
    names = {'Proxmox VE by HTTP'}
    for member in value['members']:
        names.update(PROFILE_TEMPLATES[p] for p in member['profiles'])
    require(not receipt.is_symlink(), 'Refuse a linked monitoring ownership receipt')
    first = not receipt.exists()
    if not first:
        info = receipt.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and json.loads(receipt.read_text()) == value['owner'],
                'Monitoring server ownership changed; preserve its receipt')
    session = call('user.login', {'username': 'Admin',
                                 'password': 'zabbix' if first else value['admin_password']})
    if isinstance(call, API):
        call.token = session
    try:
        if first:
            defaults = call('host.get', {'filter': {'host': ['Zabbix server']}, 'output': ['hostid']})
            require(len(defaults) <= 1 and all(row['hostid'] == '10084' for row in defaults),
                    'Unexpected factory host; preserve it for review')
            if defaults:
                call('host.update', {'hostid': '10084', 'status': 1})
        for template in value['templates']:
            require(call('configuration.import', {
                'format': 'json', 'source': json.dumps(template),
                'rules': {key: {'createMissing': True, 'updateExisting': True}
                          for key in ['templates', 'items', 'discoveryRules', 'triggers',
                                      'graphs', 'valueMaps', 'template_groups']}
                         | {'templateLinkage': {'createMissing': True}}}) is True,
                    'Pinned template import failed')
        identifiers = template_ids(call, names)
        groups = call('hostgroup.get', {'filter': {'name': ['HomeLab']}})
        require(len(groups) <= 1, 'Duplicate monitoring host group')
        group = groups[0]['groupid'] if groups else call('hostgroup.create', {'name': 'HomeLab'})['groupids'][0]
        for member in value['members']:
            macros = []
            if 'postgresql' in member['profiles']:
                macros = [{'macro': '{$PG.CONNSTRING.AGENT2}', 'value': 'homelab'},
                          {'macro': '{$PG.USER}', 'value': ''}, {'macro': '{$PG.PASSWORD}', 'value': ''}]
            if 'mysql' in member['profiles']:
                macros = [{'macro': '{$MYSQL.DSN}', 'value': 'homelab'},
                          {'macro': '{$MYSQL.USER}', 'value': ''}, {'macro': '{$MYSQL.PASSWORD}', 'value': ''}]
            if 'influxdb' in member['profiles']:
                macros = [{'macro': '{$INFLUXDB.URL}', 'value': member['url']}]
            host(call, member['hostname'], marker('agent', member['psk_identity'], member['psk']), group,
                 [identifiers[PROFILE_TEMPLATES[p]] for p in member['profiles']],
                 tls_connect=2, tls_accept=2, tls_psk_identity=member['psk_identity'],
                 tls_psk=member['psk'], macros=macros)
        from urllib.parse import urlsplit
        proxmox = value['proxmox']
        endpoint = urlsplit(proxmox['endpoint'])
        host(call, proxmox['hostname'], marker('proxmox', proxmox['token_id'], proxmox['token_secret']),
             group, [identifiers['Proxmox VE by HTTP']], macros=[
                 {'macro': '{$PVE.URL.HOST}', 'value': endpoint.hostname},
                 {'macro': '{$PVE.URL.PORT}', 'value': str(endpoint.port)},
                 {'macro': '{$PVE.TOKEN.ID}', 'value': proxmox['token_id']},
                 {'macro': '{$PVE.TOKEN.SECRET}', 'value': proxmox['token_secret'], 'type': 1},
                 {'macro': '{$HTTP.TLS.VERIFY}', 'value': 'full'}])
        if first:
            admins = call('user.get', {'filter': {'username': ['Admin']}, 'output': ['userid']})
            require(len(admins) == 1, 'Expected one owned initial administrator')
            call('user.update', {'userid': admins[0]['userid'], 'passwd': value['admin_password'],
                                 'current_passwd': 'zabbix'})
            fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(value['owner'], stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return {'configured': True, 'agent_hosts': len(value['members']), 'first_install': first}
    finally:
        try:
            call('user.logout', [])
        except Exception:
            pass  # Logout failure cannot replace the actual configuration result.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    try:
        import os
        os.umask(0o077)
        value = json.loads(args.input.read_text())
        api = API()
        deadline = time.monotonic() + 120
        while True:
            try:
                api('apiinfo.version', {})
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise ValueError('Monitoring API did not become ready') from None
                time.sleep(2)
        print(json.dumps(configure(api, value, Path('/var/lib/homelab-monitoring/server.json'))))
    except Exception:
        raise SystemExit('Monitoring configuration held; preserve the current guest attempt and credentials.') from None


if __name__ == '__main__':
    main()
