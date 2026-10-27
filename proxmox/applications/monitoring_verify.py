"""Read-only acceptance: fresh PSK-only Linux samples and Proxmox API values."""
import argparse
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler
from deploy import RefuseRedirects


def verify(c):
    url = urlsplit(c['url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
        raise ValueError('Use the reviewed HTTPS frontend origin')
    opener = build_opener(ProxyHandler({}), RefuseRedirects(),
                          HTTPSHandler(context=ssl.create_default_context(cafile=c.get('ca_file'))))
    def call(method, params, token=None):
        headers = {'Content-Type': 'application/json-rpc'}
        if token: headers['Authorization'] = 'Bearer ' + token
        with opener.open(Request(c['url'].rstrip('/') + '/api_jsonrpc.php', headers=headers,
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()), timeout=20) as response:
            value = json.load(response)
        if 'error' in value: raise ValueError('Monitoring API readback failed')
        return value['result']
    token = call('user.login', {'username': 'Admin', 'password': Path(c['password_file']).read_text().strip()})
    try:
        cutoff = max(time.time() - c.get('max_age_seconds', 900), c['not_before'])
        for row in c['agents']:
            hosts = call('host.get', {'filter': {'host': [row['hostname']]}, 'output': 'extend'}, token)
            # Zabbix does not return PSK material/identity through host.get.
            # The immutable commissioning packet binds that secret; the visible
            # description binds the identity and fresh PSK-only data proves it.
            if len(hosts) != 1 or hosts[0]['tls_accept'] != '2' or hosts[0]['description'] != 'HomeLab active agent; PSK identity=' + row['psk_identity']:
                raise ValueError('An agent is missing or does not require its individual PSK')
            samples = call('item.get', {'hostids': [hosts[0]['hostid']], 'filter': {'key_': ['system.uptime']},
                                       'output': ['type', 'lastclock', 'lastvalue', 'state']}, token)
            if len(samples) != 1 or samples[0]['type'] != '7' or int(samples[0]['lastclock']) < cutoff or samples[0]['state'] != '0' or float(samples[0]['lastvalue']) <= 0:
                raise ValueError('An agent has no fresh authenticated active uptime sample')
        host = call('host.get', {'filter': {'host': [c['proxmox_hostname']]}, 'output': ['hostid'], 'selectMacros': 'extend'}, token)
        if len(host) != 1 or not any(m['macro'] == '{$HTTP.TLS.VERIFY}' and m['value'] == 'full' for m in host[0]['macros']):
            raise ValueError('Proxmox monitoring must require full API TLS verification')
        items = call('item.get', {'hostids': [host[0]['hostid']],
                     'filter': {'key_': ['proxmox.api.available', 'proxmox.cluster.resources']}, 'output': 'extend'}, token)
        by_key = {row['key_']: row for row in items}
        if len(by_key) != 2 or any(row['state'] != '0' or int(row['lastclock']) < cutoff for row in items) or by_key['proxmox.api.available']['lastvalue'] != '200':
            raise ValueError('No fresh successful Proxmox API result')
        resources = json.loads(by_key['proxmox.cluster.resources']['lastvalue'])['data']
        if not set(c['commissioned_vmids']) <= {row.get('vmid') for row in resources}:
            raise ValueError('Commissioned guests are missing from the Proxmox API sample')
        if not any(row.get('type') == 'node' for row in resources):
            raise ValueError('No Proxmox node values arrived')
        with opener.open(c['url'], timeout=20) as response:
            if response.status != 200 or b'Zabbix' not in response.read(1024 * 1024):
                raise ValueError('Monitoring HTTPS UI did not respond')
        return {'status': 'passed', 'fresh_agents': len(c['agents']), 'proxmox_api_data': True, 'https_ui': True,
                'browser_sign_in_verified': False}
    finally:
        call('user.logout', [], token)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(json.loads(args.config.read_text()))))
    except Exception:
        raise SystemExit('Monitoring acceptance failed; retain the private readback evidence.') from None
