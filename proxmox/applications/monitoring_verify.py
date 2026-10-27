"""Read-only acceptance: fresh PSK-only Linux samples and Proxmox API values."""
import argparse
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler
from deploy import RefuseRedirects


class FreshnessPending(ValueError):
    pass


def _verify_once(c):
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
        pending = False
        for row in c['agents']:
            hosts = call('host.get', {'filter': {'host': [row['hostname']]}, 'output': 'extend'}, token)
            # Zabbix does not return PSK material/identity through host.get.
            # The immutable commissioning packet binds that secret; the visible
            # description binds the identity and fresh PSK-only data proves it.
            if len(hosts) != 1 or hosts[0]['tls_accept'] != '2' or hosts[0]['description'] != 'HomeLab active agent; PSK identity=' + row['psk_identity']:
                raise ValueError('An agent is missing or does not require its individual PSK')
            samples = call('item.get', {'hostids': [hosts[0]['hostid']], 'filter': {'key_': ['system.uptime']},
                                       'output': ['type', 'lastclock', 'lastvalue', 'state']}, token)
            if len(samples) != 1 or samples[0]['type'] != '7' or samples[0]['state'] != '0':
                raise ValueError('An agent does not have its supported active uptime item')
            if int(samples[0]['lastclock']) < cutoff or float(samples[0]['lastvalue']) <= 0:
                pending = True
        host = call('host.get', {'filter': {'host': [c['proxmox_hostname']]}, 'output': ['hostid'], 'selectMacros': 'extend'}, token)
        if len(host) != 1 or not any(m['macro'] == '{$HTTP.TLS.VERIFY}' and m['value'] == 'full' for m in host[0]['macros']):
            raise ValueError('Proxmox monitoring must require full API TLS verification')
        items = call('item.get', {'hostids': [host[0]['hostid']],
                     'filter': {'key_': ['proxmox.api.available', 'proxmox.cluster.resources']}, 'output': 'extend'}, token)
        by_key = {row['key_']: row for row in items}
        for method in ('item.get', 'itemprototype.get'):
            http = call(method, {'hostids': [host[0]['hostid']], 'filter': {'type': 19},
                                'output': ['verify_peer', 'verify_host']}, token)
            if not http or any(row.get('verify_peer') != '1' or row.get('verify_host') != '1' for row in http):
                raise ValueError('A Proxmox HTTP item or prototype does not require full TLS verification')
        if len(by_key) != 2 or any(row['state'] != '0' for row in items):
            raise ValueError('Proxmox API items are missing or unsupported')
        if any(int(row['lastclock']) < cutoff for row in items):
            pending = True
        else:
            if by_key['proxmox.api.available']['lastvalue'] != '200':
                raise ValueError('The Proxmox API returned an unsuccessful status')
            resources = json.loads(by_key['proxmox.cluster.resources']['lastvalue'])['data']
            if not set(c['commissioned_vmids']) <= {row.get('vmid') for row in resources}:
                raise ValueError('Commissioned guests are missing from the Proxmox API sample')
            if not any(row.get('type') == 'node' for row in resources):
                raise ValueError('No Proxmox node values arrived')
        if pending:
            raise FreshnessPending('Waiting for fresh agent and Proxmox samples')
        with opener.open(c['url'], timeout=20) as response:
            if response.status != 200 or b'Zabbix' not in response.read(1024 * 1024):
                raise ValueError('Monitoring HTTPS UI did not respond')
        return {'status': 'passed', 'fresh_agents': len(c['agents']), 'proxmox_api_data': True, 'https_ui': True,
                'browser_sign_in_verified': False}
    finally:
        call('user.logout', [], token)


def verify(c):
    wait_seconds = c.get('collection_wait_seconds', 600)
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 600:
        raise ValueError('Bound the initial read-only collection wait to ten minutes')
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            return _verify_once(c)
        except FreshnessPending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Fresh monitoring samples did not arrive within the approved collection wait') from None
            time.sleep(min(5, remaining))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(json.loads(args.config.read_text()))))
    except Exception:
        raise SystemExit('Monitoring acceptance failed; retain the private readback evidence.') from None
