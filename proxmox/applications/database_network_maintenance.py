"""Read-only DB network maintenance planning, separate from first installation.

No apply/deploy/restore entry point exists. Plan uses the original installed
source and authoritative backend, under its existing workflow/deployment locks.
Its private candidate/evidence directory never replaces installation receipts.
A successful plan is a review candidate, not permission or proof of cutover.
"""
import argparse
import copy
from contextlib import ExitStack
import fcntl
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import database_networks as networks
from database_network_server import clients

STATE = Path('/var/lib/homelab-applications')
BOOTSTRAP_HOLD = Path('/var/lib/homelab-bootstrap/CONFIGURING')
CONTAINER = 'module.guest.proxmox_virtual_environment_container.guest'
OPTIONS = 'module.guest.proxmox_virtual_environment_firewall_options.guest'
RULES = 'module.guest.proxmox_virtual_environment_firewall_rules.guest'
RESOURCES = {CONTAINER: 'vm_id', OPTIONS: 'container_id', RULES: 'container_id'}
SCHEMA = 'homelab-database-network-plan-v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def selected_catalogue(value, engine, client_vmids):
    selected = copy.deepcopy(value)
    selected['networks'][engine]['clients'] = clients(value, engine, client_vmids)
    return selected


def candidate_guest(guest, value, engine, *, phase, client_vmids, legacy_server_address=None):
    """Pure exact guest overlay, preserving all unrelated installed inputs.

    PG server replaces its one untagged vmbr30 NIC in place; selected clients
    retain vmbr30 for HTTP and append the new DB NIC. Old SQL allowances are
    removed. Other engines remain additive. No guest/config is written here.
    """
    chosen = selected_catalogue(value, engine, client_vmids)
    net, member = networks.selected(chosen, engine, guest['vmid'])
    require(member['hostname'] == guest['hostname'], 'Catalogue and installed hostname differ')
    require(phase == ('cutover' if engine == 'postgresql' else 'additive'),
            'Only PostgreSQL cutover and other-engine additive planning are selected')
    if phase == 'additive':
        require(legacy_server_address is None, 'No legacy removal is selected for this engine')
        return networks.attach(guest, chosen, [engine])
    old = ipaddress.IPv4Address(legacy_server_address)
    legacy = [(i, nic) for i, nic in enumerate(guest['interfaces']) if nic['bridge'] == 'vmbr30']
    require(len(legacy) == 1, 'Require the one existing private backend NIC')
    index, nic = legacy[0]
    subnet = ipaddress.IPv4Interface(nic['ipv4'])
    require(index > 0 and nic.get('vlan') is None and not nic.get('gateway')
            and subnet.network.prefixlen == 24 and old in subnet.network
            and old not in (subnet.network.network_address, subnet.network.broadcast_address)
            and subnet.network != ipaddress.IPv4Network(net['cidr']),
            'Preserve management/default route and bind the legacy private backend')
    is_server = member == net['server']
    require(not is_server or old == subnet.ip, 'Legacy server address differs from its installed NIC')
    require(not any(n['bridge'] == net['bridge'] or n['mac'].lower() == member['mac']
                    for n in guest['interfaces']), 'New database NIC is already present or occupied')
    result = copy.deepcopy(guest)
    new = networks.interface(chosen, engine, guest['vmid'])
    if is_server:
        result['interfaces'][index] = new
    else:
        result['interfaces'].append(new)
    # Require the commissioned exact single SQL rule. Mixed ports or broader
    # policies need a concrete reviewed extension, never silent subtraction.
    port = str(networks.PORTS[engine])
    relevant = [r for r in result['rules'] if r.get('proto') == 'tcp' and port in str(r.get('port', '')).split(',')]
    require(len(relevant) == 1, 'Review ambiguous/missing legacy SQL rules')
    rule = relevant[0]
    require(rule.get('direction') == ('in' if is_server else 'out') and rule.get('port') == port
            and rule.get('destination') == str(old) + '/32'
            and (rule.get('source') == str(subnet.network) if is_server else not rule.get('source')),
            'Legacy SQL rule differs from the selected cutover')
    result['rules'].remove(rule)
    result['rules'].extend(networks.rules(chosen, engine, guest['vmid']))
    return result


def unknown(value):
    return any(unknown(v) for v in value.values()) if isinstance(value, dict) else (
        any(unknown(v) for v in value) if isinstance(value, list) else value is True)


def nic_projection(nic):
    return {key: nic.get(field) for key, field in [('bridge', 'bridge'), ('vlan', 'vlan_id'), ('mac', 'mac_address')]}


def ip_projection(value):
    require(isinstance(value, dict) and len(value.get('ipv4', [])) == len(value.get('ipv6', [])) == 1,
            'Review unsupported provider IP configuration')
    return {'ipv4': value['ipv4'][0].get('address'), 'gateway': value['ipv4'][0].get('gateway'),
            'ipv6': value['ipv6'][0].get('address')}


def rule_projection(row):
    require(row.get('action') == 'ACCEPT', 'Unexpected installed firewall action')
    return {key: row.get(field) for key, field in [('direction', 'type'), ('proto', 'proto'), ('port', 'dport'),
            ('source', 'source'), ('destination', 'dest'), ('comment', 'comment')]}


def normal_rule(row):
    return {key: row.get(key) for key in ('direction', 'proto', 'port', 'source', 'destination', 'comment')}


def expected_container(before, original, candidate):
    result = copy.deepcopy(before)
    nics = before.get('network_interface', [])
    initialization = before.get('initialization', [])
    require(len(nics) == len(original['interfaces']) and len(initialization) == 1
            and len(initialization[0].get('ip_config', [])) == len(nics), 'Installed NIC/IP shape differs')
    ips = initialization[0]['ip_config']
    for i, nic in enumerate(original['interfaces']):
        actual = nic_projection(nics[i])
        # Proxmox may expose untagged VLAN as null or zero; preserve that exact
        # representation, and accept no other normalisation or computed drift.
        vlan = nics[i].get('vlan_id')
        require(nic.get('vlan') is not None or vlan in (None, 0), 'Unexpected installed VLAN')
        expected = {'bridge': nic['bridge'], 'vlan': vlan if nic.get('vlan') is None else nic['vlan'], 'mac': nic['mac']}
        require(actual == expected and nics[i].get('name') == 'eth' + str(i) and nics[i].get('firewall') is True,
                'Installed bridge/MAC/interface name/firewall differs')
        require(ip_projection(ips[i]) == {k: nic.get(k) for k in ('ipv4', 'gateway', 'ipv6')},
                'Installed IP/default route differs')
    for i, nic in enumerate(candidate['interfaces']):
        if i < len(original['interfaces']) and nic == original['interfaces'][i]:
            continue
        template = i if i < len(nics) else next((j for j, old in enumerate(original['interfaces'])
            if old.get('vlan') is None and not old.get('gateway') and old['bridge'] == 'vmbr30'), None)
        require(template is not None and nic.get('vlan') is None and not nic.get('gateway'),
                'Require an existing untagged private NIC template with no gateway')
        new_nic, new_ip = copy.deepcopy(nics[template]), copy.deepcopy(ips[template])
        new_nic.update(name='eth' + str(i), bridge=nic['bridge'], mac_address=nic['mac'])
        new_ip['ipv4'][0].update(address=nic['ipv4'], gateway=None)
        new_ip['ipv6'][0]['address'] = nic['ipv6']
        if i == len(result['network_interface']):
            result['network_interface'].append(new_nic); result['initialization'][0]['ip_config'].append(new_ip)
        else:
            result['network_interface'][i] = new_nic; result['initialization'][0]['ip_config'][i] = new_ip
    return result


def expected_rules(before, original, candidate, engine):
    result = copy.deepcopy(before)
    rows = before.get('rule', [])
    require([rule_projection(r) for r in rows] == [normal_rule(r) for r in original['rules']],
            'Installed firewall rules differ from commissioned inputs')
    templates = [row for row in rows if row.get('proto') == 'tcp' and row.get('dport') == str(networks.PORTS[engine])]
    require(len(templates) == 1, 'Require one exact existing SQL rule template')
    expected = []
    for rule in candidate['rules']:
        if rule in original['rules']:
            expected.append(copy.deepcopy(rows[original['rules'].index(rule)]))
        else:
            row = copy.deepcopy(templates[0])
            row.update(type=rule['direction'], proto=rule['proto'], dport=rule['port'], action='ACCEPT',
                       source=rule.get('source'), dest=rule.get('destination'), comment=rule.get('comment'))
            expected.append(row)
    result['rule'] = expected
    return result


def check_plan(value, original_cfg, catalogue, engine, *, phase, client_vmids, legacy_server_address=None):
    """Accept only exact NIC/IP/SQL-rule changes on an existing known guest.

    All other raw provider attributes must be byte-for-byte JSON-equal. Unknown
    values, state drift, replacements and provider-shape surprises are holds.
    """
    guest = original_cfg['guest']; vmid = guest['vmid']; node = original_cfg['site']['node']
    require(type(vmid) is int and vmid >= 100 and vmid not in {900, 4914, 4915, 4920}, 'Invalid maintenance guest')
    candidate = candidate_guest(guest, catalogue, engine, phase=phase, client_vmids=client_vmids,
                                legacy_server_address=legacy_server_address)
    rows = value.get('resource_changes', [])
    require(len(rows) == len(RESOURCES) and {row.get('address') for row in rows} == set(RESOURCES),
            'Plan must contain only the existing guest and its two firewall resources')
    require(not value.get('resource_drift') and not value.get('deferred_changes') and not value.get('errored'),
            'Review state drift, deferred changes or planning errors')
    for row in rows:
        change = row['change']; before, after = change.get('before'), change.get('after')
        require(change.get('actions') in (['update'], ['no-op']) and not change.get('replace_paths')
                and not change.get('importing') and not unknown(change.get('after_unknown', {}))
                and not row.get('previous_address') and row.get('mode', 'managed') == 'managed',
                'No creation, deletion, replacement, import, move or unknown values in maintenance')
        require(isinstance(before, dict) and isinstance(after, dict) and all(
            data.get('node_name') == node and str(data.get(RESOURCES[row['address']])) == str(vmid)
            for data in (before, after)), 'The maintenance guest/node changed')
        if row['address'] == CONTAINER:
            expected = expected_container(before, guest, candidate)
        elif row['address'] == RULES:
            expected = expected_rules(before, guest, candidate, engine)
        else:
            expected = before
        require(after == expected and (before == after) == (change['actions'] == ['no-op']),
                'Saved plan contains unrelated or inexact resource changes')
    return {'status': 'review_required', 'vmid': vmid, 'engine': engine, 'phase': phase,
            'client_vmids': sorted(client_vmids), 'candidate_guest': candidate, 'apply_supported': False,
            'lifecycle_effects_verified': False}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def regular(path, *, private=True):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in ({0o600} if private else {0o600, 0o644})
                and info.st_size <= 16 * 1024 * 1024, 'Use bounded owned private regular maintenance inputs')
        value = stream.read(16 * 1024 * 1024 + 1)
    require(len(value) <= 16 * 1024 * 1024, 'Oversized maintenance input')
    return value


def write_new(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(value); stream.flush(); os.fsync(stream.fileno())


def no_holds(work):
    require(not BOOTSTRAP_HOLD.exists() and not BOOTSTRAP_HOLD.is_symlink()
            and not BOOTSTRAP_HOLD.with_name('BOOTSTRAP-CD-HOLD.json').exists()
            and not BOOTSTRAP_HOLD.with_name('BOOTSTRAP-CD-HOLD.json').is_symlink()
            and not any(work.glob('*HOLD.json'))
            and not any(work.glob('database-network-plan-*/HOLD.json')),
            'An existing bootstrap/deployment or failed planning hold blocks maintenance planning')


def bindings(deployment, cfg, site, work):
    """Read original custody only; never adopt, rewrite or refresh a receipt."""
    paths = {'site': site, **{name: work / name for name in (
        'plan.json', 'applied.json', 'started.json', 'rollout-complete.json',
        'guest.tfplan', 'guest.tfplan.json', 'terraform.tfstate', 'ssh-trust.json')},
        'tfvars': work / 'tofu/site.auto.tfvars.json'}
    if (work / 'foundation-complete.json').exists():
        paths['foundation-complete.json'] = work / 'foundation-complete.json'
    raw = {key: regular(path) for key, path in paths.items()}
    receipt = json.loads(raw['plan.json']); complete = json.loads(raw['rollout-complete.json'])
    require(json.loads(raw['site']) == cfg and receipt.get('vmid') == cfg['guest']['vmid']
            and receipt.get('site_sha256') == digest(raw['site'])
            and receipt.get('source_sha256') == deployment.source_hash()
            and receipt.get('input_hashes') == deployment.input_hashes(cfg)
            and receipt.get('plan_sha256') == digest(raw['guest.tfplan'])
            and receipt.get('plan_json_sha256') == digest(raw['guest.tfplan.json'])
            and json.loads(raw['applied.json']) == json.loads(raw['started.json']) == receipt
            and complete.get('status') == 'passed' and complete.get('vmid') == cfg['guest']['vmid']
            and complete.get('plan_sha256') == receipt['plan_sha256'],
            'Original source/input/installation/completion bindings differ')
    variables = json.loads(raw['tfvars'])
    expected = {key: copy.deepcopy(cfg[key]) for key in ('site', 'guest', 'ssh_public_keys')}
    expected['guest']['routing_labels'] = deployment.discovery.labels(cfg)
    require(variables == expected, 'Original installed OpenTofu variables differ')
    state = json.loads(raw['terraform.tfstate'])
    require(isinstance(state.get('lineage'), str) and state['lineage'] and type(state.get('serial')) is int,
            'Require the original authoritative state lineage and serial')
    return {'files': {key: digest(value) for key, value in raw.items()},
            'source_sha256': receipt['source_sha256'], 'input_hashes': receipt['input_hashes'],
            'state_lineage': state['lineage'], 'state_serial': state['serial']}, variables


def tofu(command, environment, log, output=None):
    """One bounded ordinary command; neither arguments nor environment are printed."""
    with log.open('ab') as errors:
        if output:
            with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
                subprocess.run(command, env=environment, stdout=stream, stderr=errors, check=True, timeout=180, umask=0o077)
        else:
            subprocess.run(command, env=environment, stdout=errors, stderr=errors, check=True, timeout=180, umask=0o077)


def plan(deployment, installed_config_path, catalogue_path, evidence, engine, *, phase,
         client_vmids, legacy_server_address=None):
    """Prepare a private read-only plan using the ORIGINAL deployment module.

    Calling this contacts the existing pinned PVE API for planning. Source tests
    mock that boundary; this function has not been run against a native guest.
    Caller supplies an unused directory directly below that guest's state dir.
    """
    site, catalogue_path, evidence = map(Path, (installed_config_path, catalogue_path, evidence))
    cfg = json.loads(regular(site)); catalogue_raw = regular(catalogue_path, private=False); catalogue = json.loads(catalogue_raw)
    deployment.validate(cfg)
    require(cfg['paths']['state_root'] == str(STATE), 'Use the original authoritative application state root')
    work = STATE / str(cfg['guest']['vmid'])
    require(evidence.parent == work and evidence.name.startswith('database-network-plan-')
            and not evidence.exists() and not evidence.is_symlink(), 'Use a fresh separate guest maintenance evidence directory')
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'Use the existing private guest state directory')
    candidate = candidate_guest(cfg['guest'], catalogue, engine, phase=phase, client_vmids=client_vmids,
                                legacy_server_address=legacy_server_address)
    with ExitStack() as stack:
        for name in ('workflow.lock', 'deployment.lock'):
            lock = stack.enter_context(os.fdopen(os.open(work / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+'))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        no_holds(work)
        original, variables = bindings(deployment, cfg, site, work)
        evidence.mkdir(mode=0o700)
        request = {'schema': SCHEMA, 'engine': engine, 'phase': phase, 'vmid': cfg['guest']['vmid'],
                   'client_vmids': sorted(client_vmids), 'legacy_server_address': legacy_server_address,
                   'catalogue_sha256': digest(catalogue_raw), 'original': original,
                   'helper_sha256': {p.name: digest(p.read_bytes()) for p in [Path(__file__),
                       Path(networks.__file__), Path(__file__).with_name('database_network_server.py')]},
                   'apply_supported': False, 'lifecycle_effects_verified': False}
        write_new(evidence / 'request.json', encoded(request))
        try:
            source = Path(deployment.SOURCE) / 'tofu'
            require(not any(p.is_symlink() for p in source.rglob('*')), 'Original ToFu source contains symlinks')
            shutil.copytree(source, evidence / 'tofu', ignore=shutil.ignore_patterns(
                '.terraform', '*.tfstate*', '*.tfplan*', '*.auto.tfvars*'))
            variables['guest'] = dict(candidate, routing_labels=variables['guest']['routing_labels'])
            write_new(evidence / 'tofu/site.auto.tfvars.json', encoded(variables))
            write_new(evidence / 'candidate-guest.json', encoded(candidate))
            log = evidence / 'plan.log'; write_new(log, b'')
            environment = os.environ.copy()
            environment.update(TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1',
                SSL_CERT_FILE=cfg['paths']['ca_file'], PROXMOX_VE_API_TOKEN=regular(Path(cfg['paths']['api_token'])).decode().strip())
            command = ['tofu', '-chdir=' + str(evidence / 'tofu')]
            tofu(command + ['init', '-input=false', '-lockfile=readonly', '-backend-config=path=' + str(work / 'terraform.tfstate')], environment, log)
            tofu(command + ['plan', '-input=false', '-lock-timeout=30s', '-out=' + str(evidence / 'guest.tfplan')], environment, log)
            tofu(command + ['show', '-json', str(evidence / 'guest.tfplan')], environment, log, evidence / 'guest.tfplan.json')
            saved = regular(evidence / 'guest.tfplan'); shown = regular(evidence / 'guest.tfplan.json')
            checked = check_plan(json.loads(shown), cfg, catalogue, engine, phase=phase,
                                 client_vmids=client_vmids, legacy_server_address=legacy_server_address)
            no_holds(work)
            require(bindings(deployment, cfg, site, work)[0] == original and regular(catalogue_path, private=False) == catalogue_raw,
                    'State, original inputs or catalogue drifted during planning')
            result = {**request, 'status': checked['status'], 'plan_sha256': digest(saved),
                      'plan_json_sha256': digest(shown), 'candidate_guest_sha256': digest(encoded(candidate))}
            write_new(evidence / 'review-packet.json', encoded(result))
            return result
        except Exception as error:
            write_new(evidence / 'HOLD.json', encoded({'status': 'held', 'phase': 'read-only-plan',
                       'error_type': type(error).__name__, 'automatic_retry': False}))
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Unchanged original commissioned installer checkout')
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--catalogue', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--engine', choices=networks.PORTS, required=True)
    parser.add_argument('--phase', choices=('additive', 'cutover'), required=True)
    parser.add_argument('--client-vmid', type=int, action='append', required=True)
    parser.add_argument('--legacy-server-address')
    args = parser.parse_args(); os.umask(0o077)
    try:
        # Load the original installer only now, after this helper's imports have
        # resolved to its own pinned contract/checker. Private CD supplies both pins.
        require('deploy' not in sys.modules, 'Use a fresh process for the original installer')
        # database_networks imports only read() from the helper's site_config.
        # Do not accidentally give the original installer that cached module.
        sys.modules.pop('site_config', None)
        sys.path.insert(0, str(args.source.resolve() / 'proxmox/applications'))
        deployment = importlib.import_module('deploy')
        require(Path(deployment.__file__).resolve() == args.source.resolve() / 'proxmox/applications/deploy.py',
                'The loaded installer differs from the selected original checkout')
        result = plan(deployment, args.config, args.catalogue, args.evidence, args.engine,
                      phase=args.phase, client_vmids=args.client_vmid, legacy_server_address=args.legacy_server_address)
        print(json.dumps({k: result[k] for k in ('status', 'vmid', 'engine', 'phase', 'plan_sha256', 'apply_supported')}))
    except Exception as error:
        raise SystemExit('Maintenance plan held (' + type(error).__name__ + '); inspect private evidence') from None


if __name__ == '__main__':
    main()
