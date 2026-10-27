"""Reconcile one isolated backend bridge and explicit application-token grants."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.parse import quote, urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

import provider_access


class BootstrapDiagnostic(ValueError):
    """An approved, fixed refusal message safe to show in a job log."""


def require(condition, message):
    if not condition:
        raise BootstrapDiagnostic(message)


def save(path, value):
    require(not path.is_symlink(), 'Refusing a symlink receipt')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def validate(c):
    fields = {'schema', 'endpoint', 'node', 'deploy', 'bridge', 'applications',
              'existing_grants', 'backup_source'}
    require(set(c) in (fields, fields | {'service_discovery'}), 'Use the closed bootstrap CD configuration')
    require(c['schema'] == 'homelab-bootstrap-cd-v1', 'Unsupported bootstrap CD schema')
    endpoint = urlsplit(c['endpoint'])
    require(endpoint.scheme == 'https' and endpoint.hostname and endpoint.port == 8006
            and not endpoint.username and not endpoint.password and endpoint.path in ('', '/')
            and not endpoint.query and not endpoint.fragment, 'Use a pinned HTTPS Proxmox endpoint')
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', c['node']), 'Invalid node')
    d = c['deploy']
    require(set(d) == {'vmid', 'mac'} and type(d['vmid']) is int and d['vmid'] == 900
            and re.fullmatch(r'02(:[0-9a-fA-F]{2}){5}', d['mac']), 'Select the existing deployment guest 900')
    require(re.fullmatch(r'vmbr[1-9][0-9]{0,3}', c['bridge']) and c['bridge'] not in ('vmbr0', 'vmbr1'),
            'Choose a separate private bridge')
    require(isinstance(c['applications'], list) and 1 <= len(c['applications']) <= 32,
            'Declare a finite application list')
    seen = {900, 4914, 4915, 4920}
    for app in c['applications']:
        require(set(app) == {'vmid', 'hostname'} and type(app['vmid']) is int
                and 100 <= app['vmid'] <= 999999999 and app['vmid'] not in seen
                and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', app['hostname']), 'Invalid or protected application identity')
        seen.add(app['vmid'])
    require(isinstance(c['existing_grants'], list) and c['existing_grants'], 'Declare the current token ACL baseline')
    for row in c['existing_grants']:
        require(set(row) == {'path', 'role', 'propagate'} and row['propagate'] == 0
                and type(row['propagate']) is int and re.fullmatch(
                    r'/(?:vms/[0-9]+|storage/[A-Za-z0-9_-]+|nodes/[A-Za-z0-9-]+|sdn/zones/localnetwork/vmbr[0-9]+(?:/[0-9]+)?)', row['path'])
                and row['role'] in ('PVEVMAdmin', 'PVEAuditor', 'PVEDatastoreUser', 'PVESDNUser'),
                'Invalid nonpropagating baseline ACL')
    require(len(rows(c['existing_grants'])) == len(c['existing_grants']), 'Duplicate baseline ACL')
    require(isinstance(c['backup_source'], str) and ':' in c['backup_source'], 'Declare the existing NAS backup source')
    if 'service_discovery' in c:
        provider_access.validate(c)


def rows(items):
    return {(r['path'], r['role'], r['propagate']) for r in items}


def desired(c):
    return rows(c['existing_grants']) | {('/vms/' + str(a['vmid']), 'PVEVMAdmin', 0)
                                      for a in c['applications']} | {
        ('/sdn/zones/localnetwork/' + c['bridge'], 'PVESDNUser', 0)}


def network_state(data):
    # These fields describe runtime enumeration, not pending interface configuration.
    return {r['iface']: {k: v for k, v in r.items() if k not in ('active', 'exists', 'priority')}
            for r in data}


def isolated(row, active=False):
    require(row.get('type') == 'bridge' and row.get('autostart') == 1
            and row.get('bridge_ports', '') in ('', 'none')
            and row.get('bridge_stp') == 'off' and str(row.get('bridge_fd')) == '0'
            and not row.get('bridge_vlan_aware') and row.get('method') == 'manual'
            and row.get('method6') == 'manual' and not any(row.get(k) for k in
                ('address', 'address6', 'cidr', 'cidr6', 'gateway', 'gateway6', 'bridge_vids', 'slaves')),
            'The backend bridge must have no uplink, configured IP, gateway or VLAN trunk')
    if active:
        require(row.get('active') == 1, 'The backend bridge is not active')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BootstrapDiagnostic('Proxmox redirects are forbidden')


class API:
    def __init__(self, endpoint, token, ca):
        require(re.fullmatch(r'root@pam!homelab-bootstrap-cd-900=[A-Za-z0-9-]+', token),
                'Use the separate bootstrap CD token')
        self.configure(endpoint, token, ca)

    def configure(self, endpoint, token, ca):
        self.endpoint, self.ca = endpoint, ca
        self.base = endpoint.rstrip('/') + '/api2/json'
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect(),
                                  HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))

    def discovery(self, token):
        return DiscoveryAPI(self.endpoint, token, self.ca)

    def call(self, path, method='GET', values=None):
        request = Request(self.base + path, method=method,
                          data=None if values is None else urlencode(values).encode(),
                          headers={'Authorization': 'PVEAPIToken=' + self.token})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                require(len(raw) <= 8 * 1024 * 1024, 'Oversized API response')
                return json.loads(raw)
        except HTTPError as exc:
            raise BootstrapDiagnostic('Proxmox API returned HTTP ' + str(exc.code) + ': ' + method + ' ' + path) from None
        except Exception as exc:
            # Never include credential headers or response bodies in job output.
            raise BootstrapDiagnostic('Proxmox API request failed: ' + method + ' ' + path) from exc


class DiscoveryAPI(API):
    """Authenticate the retained provider secret without offering a write path."""
    def __init__(self, endpoint, token, ca):
        require(re.fullmatch(r'root@pam!homelab-traefik-[0-9]+=[A-Za-z0-9-]+', token),
                'Use the selected service discovery token')
        self.configure(endpoint, token, ca)

    def call(self, path, method='GET', values=None):
        require(method == 'GET' and values is None, 'Service discovery verification is read-only')
        return super().call(path, method, values)


def inspect(api, c):
    node = '/nodes/' + c['node']
    require(c['node'] in {r['node'] for r in api.call('/nodes')['data']}, 'Selected node is absent')
    guests = api.call('/cluster/resources?type=vm')['data']
    owner = [r for r in guests if r['vmid'] == 900]
    require(len(owner) == 1 and owner[0]['node'] == c['node'] and owner[0]['name'] == 'deploy'
            and owner[0]['type'] == 'lxc' and owner[0]['status'] == 'running', 'Deployment guest identity differs')
    cfg = api.call(node + '/lxc/900/config')['data']
    nic = dict(p.split('=', 1) for p in cfg.get('net0', '').split(',') if '=' in p)
    require(cfg.get('hostname') == 'deploy' and cfg.get('unprivileged') == 1 and cfg.get('protection') == 1
            and nic.get('hwaddr', '').lower() == c['deploy']['mac'].lower(), 'Deployment guest configuration differs')
    token = 'homelab-deploy-900'
    meta = api.call('/access/users/root@pam/token/' + token)['data']
    require(meta.get('privsep') == 1 and meta.get('expire') == 0, 'Application token metadata differs')
    acl = api.call('/access/acl')['data']
    selected = [r for r in acl if r.get('ugid') == 'root@pam!' + token]
    require(all(r.get('type') == 'token' for r in selected), 'Unexpected token ACL type')
    actual = {(r['path'], r['roleid'], int(r.get('propagate', 1))) for r in selected}
    require(len(selected) == len(actual) and rows(c['existing_grants']) <= actual <= desired(c),
            'Application-token ACL drift needs review')
    missing = desired(c) - actual
    for app in c['applications']:
        present = [r for r in guests if r['vmid'] == app['vmid']]
        require(not present or (('/vms/' + str(app['vmid']), 'PVEVMAdmin', 0) in actual
                and len(present) == 1 and present[0]['node'] == c['node'] and present[0]['type'] == 'lxc'
                and present[0]['name'] == app['hostname']), 'Selected application ID is occupied; no adoption')
    network = api.call(node + '/network')
    require(not network.get('changes'), 'Unrelated pending host-network changes need review')
    interfaces = network['data']
    bridge = [r for r in interfaces if r['iface'] == c['bridge']]
    require(len(bridge) <= 1, 'Duplicate bridge identity')
    if bridge:
        isolated(bridge[0], active=True)
    return {'networks': network_state(interfaces), 'bridge_exists': bool(bridge),
            'token_metadata': meta, 'acl': [list(r) for r in sorted(actual)],
            'missing': [list(r) for r in sorted(missing)]}


def reconcile(api, c, before, evidence, root=None, backup=None):
    base_before = {key: value for key, value in before.items() if key != 'service_discovery'}
    require(inspect(api, c) == base_before, 'Host changed after the saved plan')
    if 'service_discovery' in c:
        require(root is not None and backup is not None, 'Service discovery needs its private state and NAS backup')
        require(provider_access.inspect(api, c, root, backup) == before['service_discovery'],
                'Service discovery changed after the saved plan')
    node = '/nodes/' + c['node']
    if not before['bridge_exists']:
        # Omit bridge_ports: the API treats 'none' as a literal device name.
        # PVE serializes an absent port list as `bridge-ports none` itself.
        api.call(node + '/network', 'POST', {'iface': c['bridge'], 'type': 'bridge',
                 'autostart': 1,
                 'comments': 'HomeLab CD private backend; no physical uplink'})
        pending = api.call(node + '/network')
        proposed = network_state(pending['data'])
        require(set(proposed) == set(before['networks']) | {c['bridge']}
                and {k: v for k, v in proposed.items() if k != c['bridge']} == before['networks'],
                'Network delta contains more than the isolated bridge; reload refused')
        isolated(proposed[c['bridge']])
        save(evidence / 'network-before-reload.json', pending)
        task = api.call(node + '/network', 'PUT', {})['data']
        require(isinstance(task, str) and task.startswith('UPID:'), 'Missing network task identity')
        save(evidence / 'network-task.json', {'upid': task})
        deadline = time.monotonic() + 120
        while True:
            status = api.call(node + '/tasks/' + quote(task, safe='') + '/status')['data']
            save(evidence / 'network-status.json', status)
            if status['status'] == 'stopped':
                require(status.get('exitstatus') == 'OK', 'Network reload failed; no automatic retry')
                break
            require(time.monotonic() < deadline, 'Network task outcome UNKNOWN; no automatic retry')
            time.sleep(2)
    for path, role, propagate in before['missing']:
        api.call('/access/acl', 'PUT', {'path': path, 'roles': role,
                 'tokens': 'root@pam!homelab-deploy-900', 'propagate': propagate})
    after = inspect(api, c)
    require(after['bridge_exists'] and not after['missing'] and after['token_metadata'] == before['token_metadata'],
            'Bootstrap CD readback failed')
    require({k: v for k, v in after['networks'].items() if k != c['bridge']}
            == {k: v for k, v in before['networks'].items() if k != c['bridge']}, 'Existing host networks changed')
    permissions = api.call('/access/permissions?' + urlencode({'userid': 'root@pam!homelab-deploy-900'}))['data']
    for path, role, _ in desired(c):
        required = {'PVEVMAdmin': 'VM.Allocate', 'PVEAuditor': 'Sys.Audit' if path.startswith('/nodes/') else 'Datastore.Audit',
                    'PVEDatastoreUser': 'Datastore.AllocateSpace', 'PVESDNUser': 'SDN.Use'}[role]
        require(required in permissions.get(path, {}) and permissions[path][required] == 0,
                'Application-token effective permissions failed readback')
    save(evidence / 'after.json', after)
    result = {'status': 'passed', 'bridge': c['bridge'], 'bridge_created': not before['bridge_exists'],
            'new_acl_rows': len(before['missing']), 'token_lifetime_changed': False,
            'guest_lifecycle_changed': False, 'trigger_commit': os.environ.get('GITHUB_SHA')}
    if 'service_discovery' in c:
        result['service_discovery'] = provider_access.reconcile(
            api, c, before['service_discovery'], root, backup)
    return result


def resume_discovery(c, api, root, backup, packet):
    """One reviewed continuation of a preserved mint response; no credential rotation."""
    require(isinstance(packet, dict) and set(packet) == {'attempt', 'plan_sha256', 'minted_sha256'}
            and isinstance(packet.get('attempt'), str) and re.fullmatch(r'cd-[0-9]+', packet['attempt'])
            and all(isinstance(packet.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', packet[key])
                    for key in ('plan_sha256', 'minted_sha256')), 'Use the exact reviewed discovery continuation packet')
    hold, marker = root / 'BOOTSTRAP-CD-HOLD.json', root / 'CONFIGURING'
    expected = {'attempt':packet['attempt'], 'automatic_retry':False}
    require(json.loads(provider_access.read_private(hold)) == expected
            and json.loads(provider_access.read_private(marker)) == expected,
            'Continuation does not own both failed-operation markers')
    evidence, destination = root / packet['attempt'], backup / packet['attempt']
    for folder in (evidence, destination):
        provider_access.private_directory(folder)
        require(not (folder / 'continuation-started.json').exists(), 'The one continuation was already consumed')
    raw = provider_access.read_private(evidence / 'plan.json')
    require(raw == provider_access.read_private(destination / 'plan.json')
            and hashlib.sha256(raw).hexdigest() == packet['plan_sha256'], 'Failed plan or NAS copy differs')
    saved = json.loads(raw)
    require(saved['configuration'] == c and 'service_discovery' in c, 'Continuation configuration differs')
    failed = provider_access.read_private(evidence / 'failure.json')
    require(failed == provider_access.read_private(destination / 'failure.json')
            and json.loads(failed) == {'status':'held', 'automatic_retry':False,
                'error':'Created discovery token response differs; preserve its private partial receipt'},
            'Continuation is only for the recorded mint-response failure')
    after = json.loads(provider_access.read_private(evidence / 'after.json'))
    original = saved['plan']
    require(inspect(api, c) == after and after['bridge_exists'] and not after['missing']
            and after['token_metadata'] == original['token_metadata']
            and {k:v for k,v in after['networks'].items() if k != c['bridge']} ==
                {k:v for k,v in original['networks'].items() if k != c['bridge']},
            'Base bootstrap changed or did not finish; continuation refused')
    minted = provider_access.admit_minted_continuation(api, c, saved['plan']['service_discovery'],
                                                     root, backup, packet['minted_sha256'])
    # Persist the one-shot claim before any native continuation write. A partial
    # claim is also a hold; neither caller nor later merges may replay it.
    for folder in (evidence, destination):
        provider_access.save_new(folder / 'continuation-started.json', packet)
    try:
        result = {'status':'passed', 'plan_sha256':packet['plan_sha256'], 'bridge_created':False,
                  'new_acl_rows':0, 'token_lifetime_changed':False, 'guest_lifecycle_changed':False,
                  'trigger_commit':os.environ.get('GITHUB_SHA'), 'resumed_attempt':packet['attempt'],
                  'service_discovery':provider_access.finish_minted(
                      api, c, saved['plan']['service_discovery'], root, backup, minted)}
        result['service_discovery'].update(created=False, resumed=True)
        for folder in (evidence, destination):
            provider_access.save_new(folder / 'continuation-result.json', result)
        require(provider_access.read_private(evidence / 'continuation-result.json') ==
                provider_access.read_private(destination / 'continuation-result.json'),
                'Continuation result NAS readback differs')
        require(json.loads(provider_access.read_private(hold)) == expected
                and json.loads(provider_access.read_private(marker)) == expected, 'Failed marker ownership changed')
        for path in (hold, marker):
            archived = evidence / (path.name + '.original')
            require(not archived.exists(), 'Failed marker archive already exists')
            path.rename(archived)
        return result
    except Exception as exc:
        for folder in (evidence, destination):
            save(folder / 'continuation-failure.json', {'status':'held', 'error':str(exc), 'automatic_retry':False})
        raise


def run(c, api, root=Path('/var/lib/homelab-bootstrap'), backup=Path('/srv/homelab-backups'), resume=None):
    validate(c)
    require(root.is_dir() and not root.is_symlink(), 'Existing bootstrap state directory is required')
    hold, marker = root / 'BOOTSTRAP-CD-HOLD.json', root / 'CONFIGURING'
    require(resume is not None or not hold.exists() and not marker.exists(),
            'Existing bootstrap hold or maintenance marker needs review')
    mount = json.loads(subprocess.check_output(['findmnt', '-J', '-M', str(backup), '-o', 'TARGET,SOURCE,FSTYPE'], timeout=10))
    entries = mount.get('filesystems', [])
    require(len(entries) == 1 and entries[0]['target'] == str(backup)
            and entries[0]['source'] == c['backup_source'] and entries[0]['fstype'] in ('nfs', 'nfs4'),
            'The declared NAS backup must be an actual mounted filesystem')
    if resume is not None and (hold.exists() or marker.exists()):
        return resume_discovery(c, api, root, backup, resume)
    evidence = root / ('cd-' + str(time.time_ns()))
    evidence.mkdir(mode=0o700)
    before = inspect(api, c)
    if 'service_discovery' in c:
        before['service_discovery'] = provider_access.inspect(api, c, root, backup)
    payload = {'configuration': c, 'plan': before}
    save(evidence / 'plan.json', payload)
    destination = backup / evidence.name
    destination.mkdir(mode=0o700)
    save(destination / 'plan.json', payload)
    require((destination / 'plan.json').read_bytes() == (evidence / 'plan.json').read_bytes(), 'NAS plan readback failed')
    receipt = {'attempt': evidence.name, 'automatic_retry': False}
    with marker.open('x') as stream:
        json.dump(receipt, stream)
    marker.chmod(0o600)
    save(hold, receipt)
    try:
        result = reconcile(api, c, before, evidence, root, backup)
    except Exception as exc:
        failure = {'status': 'held', 'error': str(exc), 'automatic_retry': False}
        save(evidence / 'failure.json', failure)
        save(destination / 'failure.json', failure)
        raise
    result['plan_sha256'] = hashlib.sha256((evidence / 'plan.json').read_bytes()).hexdigest()
    save(evidence / 'result.json', result)
    save(destination / 'result.json', result)
    require((destination / 'result.json').read_bytes() == (evidence / 'result.json').read_bytes(), 'NAS result readback failed')
    require(json.loads(marker.read_text()) == receipt, 'Bootstrap maintenance ownership changed')
    hold.unlink()
    marker.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--ca', type=Path, default=Path('/usr/local/share/ca-certificates/homelab-pve.crt'))
    parser.add_argument('--resume-discovery', type=Path, help='Exact separately reviewed failed-mint continuation packet')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        c = json.loads(args.config.read_text())
        validate(c)
        api = API(c['endpoint'], os.environ['PROXMOX_BOOTSTRAP_TOKEN'], args.ca)
        resume = json.loads(args.resume_discovery.read_text()) if args.resume_discovery else None
        print(json.dumps(run(c, api, resume=resume)))
    except (BootstrapDiagnostic, provider_access.ProviderAccessError) as exc:
        raise SystemExit('Bootstrap CD stopped: ' + str(exc) + '. Inspect its private plan/hold; do not automatically rerun.') from None
    except Exception:
        raise SystemExit('Bootstrap CD stopped. Inspect its private plan/hold; do not automatically rerun.') from None


if __name__ == '__main__':
    main()
