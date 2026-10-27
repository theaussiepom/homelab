"""Prepare the foundation's declared Pi-hole hosts and Unbound domain redirects.

Uses Pi-hole's supported FTL config CLI, then its DNS cache reload command:
https://docs.pi-hole.net/ftldns/configfile/#hosts
https://docs.pi-hole.net/main/pihole-command/
The declared Pi-hole names and selected Unbound apex A values point to the
static proxy. Only their selected ACME challenge children resolve transparently
upstream. Declared preserved zones and unrelated text remain intact. No UDM, WAN, guest creation or service recreation is included.
"""
import argparse
import base64
import hashlib
import fcntl
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

# Site values must be supplied explicitly, including on the remote half.
SETTINGS = None
RECORDS = REDIRECTS = UNCHANGED = {}
ADDRESS = SITE = TARGET = LEGACY_PROXY = None
ACME_EXCEPTIONS = ()
INPUT = Path('/var/lib/homelab-inputs/dns.json')
HOSTS = Path('/var/lib/homelab-inputs/known_hosts')
KEY = Path('/home/homelab-runner/.ssh/applications')
WORK = None
REMOTE_ROOT = Path('/var/lib/homelab-foundation-dns')
IDENTITY = Path('/etc/homelab-application.json')
COMPOSE = Path('/opt/homelab-app/compose.yml')
COMPOSE_ARGV = ['docker', 'compose', '-f', str(COMPOSE)]
UNBOUND = Path('/srv/homelab/data/unbound/unbound.conf')
UNBOUND_CONTAINER = '/opt/unbound/etc/unbound/unbound.conf'


def configure(value):
    """Closed non-secret settings travel with the exact streamed helper source."""
    global SETTINGS, RECORDS, REDIRECTS, UNCHANGED, ADDRESS, SITE, TARGET, LEGACY_PROXY, ACME_EXCEPTIONS, WORK
    fields = {'schema', 'site', 'target', 'records', 'redirects', 'unchanged', 'legacy_proxy', 'acme_exceptions'}
    require(isinstance(value, dict) and fields <= set(value) and not set(value) - fields - {'extra_records'}
            and value['schema'] == 'homelab-foundation-dns-v1',
            'Expected the closed rendered DNS settings')
    def address(item):
        require(isinstance(item, str), 'Expected a literal DNS IPv4 address')
        parsed = ipaddress.IPv4Address(item)
        require(parsed.is_private and not parsed.is_unspecified and not parsed.is_loopback
                and not parsed.is_link_local and not parsed.is_multicast, 'Expected a private DNS IPv4 address')
    def hostname(item):
        require(isinstance(item, str) and len(item) <= 253
                and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', item) is not None,
                'Expected a lowercase DNS name')
    site, target = value['site'], value['target']
    require(isinstance(site, dict) and set(site) == {'node', 'api_endpoint'}
            and isinstance(site['node'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', site['node']) is not None
            and isinstance(site['api_endpoint'], str), 'Expected a pinned Proxmox site')
    match = re.fullmatch(r'https://([0-9.]+):8006/', site['api_endpoint'])
    require(match is not None, 'Expected the existing literal Proxmox API endpoint'); address(match[1])
    require(isinstance(target, dict) and set(target) == {'vmid', 'hostname', 'mac', 'address'}
            and type(target['vmid']) is int and 100 <= target['vmid'] <= 999999999
            and target['vmid'] not in {4914, 4915, 4920}
            and isinstance(target['hostname'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', target['hostname']) is not None
            and isinstance(target['mac'], str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', target['mac']) is not None,
            'Expected the commissioned DNS identity')
    address(target['address']); address(value['legacy_proxy'])
    for key in ('records', 'redirects', 'unchanged'):
        mapping = value[key]
        require(isinstance(mapping, dict) and 1 <= len(mapping) <= 16, 'Expected bounded selected DNS records')
        for name, ip in mapping.items():
            hostname(name); address(ip)
    require(len(set(value['records'].values()) | set(value['redirects'].values())) == 1,
            'Selected names and redirects must use the same declared proxy')
    require(not set(value['redirects']) & set(value['unchanged']), 'Selected and preserved redirects overlap')
    require(isinstance(value['acme_exceptions'], list)
            and all(isinstance(name, str) and len(name) <= 253 for name in value['acme_exceptions'])
            and len(value['acme_exceptions']) == len(value['records'])
            and set(value['acme_exceptions']) == {'_acme-challenge.' + name for name in value['records']},
            'ACME transparency must match only the selected names')
    for name in value['records']:
        require(sum(name.endswith('.' + zone) for zone in value['redirects']) == 1,
                'Each selected name must belong to one redirect zone')
    extra = value.get('extra_records', {})
    require(isinstance(extra, dict) and len(extra) <= 16
            and not set(extra) & (set(value['records']) | set(value['redirects']) | set(value['unchanged'])),
            'Additional application hosts must be bounded and cannot replace foundation names or zones')
    for name, ip in extra.items():
        hostname(name); address(ip)
    # Round-trip makes an independent copy; later caller mutations cannot alter admission.
    SETTINGS = json.loads(json.dumps(value))
    SITE, TARGET = SETTINGS['site'], SETTINGS['target']
    RECORDS, REDIRECTS, UNCHANGED = (SETTINGS[key] for key in ('records', 'redirects', 'unchanged'))
    RECORDS = {**RECORDS, **extra}
    ADDRESS, LEGACY_PROXY = TARGET['address'], SETTINGS['legacy_proxy']
    ACME_EXCEPTIONS = tuple(SETTINGS['acme_exceptions'])
    WORK = Path('/var/lib/homelab-applications') / str(TARGET['vmid'])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_read(path, owner=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == (os.getuid() if owner is None else owner)
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024 * 1024,
                'Expected a bounded owned private regular file')
        content = stream.read(1024 * 1024 + 1)
        require(len(content) <= 1024 * 1024, 'Private input grew beyond its bounded size')
        return content


def private_write(path, value, exclusive=True):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o600), 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def owned_directory(path, owner=None):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == (os.getuid() if owner is None else owner)
            and stat.S_IMODE(info.st_mode) == 0o700, 'Expected an owned private evidence directory')


def merge_hosts(current):
    """Preserve unrelated entries and same-line aliases; change only two names."""
    require(isinstance(current, list) and len(current) <= 4096, 'Expected a bounded FTL dns.hosts array')
    parsed, found = [], {name: [] for name in RECORDS}
    for line in current:
        require(isinstance(line, str) and len(line) <= 4096 and not any(c in line for c in '\r\n\x00'),
                'Unexpected FTL hosts record')
        fields = line.split()
        require(len(fields) >= 2, 'Expected an IP and literal hostnames in each FTL hosts record')
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            raise ValueError('FTL hosts contains an invalid IP address') from None
        for name in fields[1:]:
            require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'Unexpected FTL hostname syntax')
            normalized = name.lower().removesuffix('.')
            if normalized in found:
                found[normalized].append(address)
        parsed.append((line, fields))
    # Keep exact whitespace, ordering and shared aliases on an already-correct run.
    if all(found[name] == [address] for name, address in RECORDS.items()):
        return list(current)
    result = []
    for line, fields in parsed:
        remaining = [name for name in fields[1:] if name.lower().removesuffix('.') not in RECORDS]
        if len(remaining) == len(fields) - 1:
            result.append(line)
        elif remaining:
            result.append(' '.join([fields[0], *remaining]))
    result.extend(address + ' ' + name for name, address in RECORDS.items())
    return result


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    require(result.returncode == 0, 'The selected DNS command failed; preserve its hold')
    return result.stdout


def parse_hosts(output):
    """FTL's pinned CLI prints unquoted records; its setter accepts JSON.

    Only HOSTS records admitted by merge_hosts are accepted. This is not a
    general parser for arbitrary CLI/TOML configuration values.
    """
    require(isinstance(output, str) and len(output) <= 1024 * 1024, 'Unexpected FTL hosts output')
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        text = output.strip()
        require(text.startswith('[') and text.endswith(']'), 'Unexpected FTL hosts array framing')
        inside = text[1:-1].strip()
        value = [line.strip() for line in inside.split(',')] if inside else []
    merge_hosts(value)
    return value


def get_hosts():
    output = command(COMPOSE_ARGV + ['exec', '-T', 'pihole', 'pihole-FTL', '--config', 'dns.hosts'])
    return parse_hosts(output)  # Validate before creating a mutation hold or write command.


def verify_records():
    for name, address in RECORDS.items():
        output = command(COMPOSE_ARGV + ['exec', '-T', 'pihole', 'dig', '+short', '+time=2', '+tries=1',
                                         '@127.0.0.1', name, 'A'])
        require(output.split() == [address], 'A selected foundation name does not resolve to the declared proxy')


def merge_unbound(text):
    """Change two known apex A values; retain every other original character."""
    require(isinstance(text, str) and len(text) <= 131072 and '\x00' not in text,
            'Unexpected Unbound configuration')
    lines = text.splitlines(keepends=True)
    zones, records, missing = {}, {}, list(ACME_EXCEPTIONS)
    for index, line in enumerate(lines):
        match = re.fullmatch(r'([ \t]*)(local-zone|local-data):[ \t]*(["\'])(.*?)\3([^\r\n]*)(\r?\n)?', line)
        if not match:
            continue
        indent, kind, quote, content, suffix, ending = match.groups()
        fields = content.split()
        if kind == 'local-zone':
            name = content.removesuffix('.')
            zone_type = suffix.strip().split('#', 1)[0].strip()
            if name in REDIRECTS or name in UNCHANGED or name in ACME_EXCEPTIONS:
                require(name not in zones, 'Duplicate selected Unbound zone')
                zones[name] = zone_type
            if name in ACME_EXCEPTIONS:
                require(zone_type == 'transparent', 'An ACME exception has conflicting local-zone policy')
                missing.remove(name)
        elif fields:
            name = fields[0].removesuffix('.')
            require(name not in ACME_EXCEPTIONS, 'ACME challenges must not contain local data')
            if name in REDIRECTS or name in UNCHANGED:
                require(name not in records and len(fields) == 3 and fields[1] == 'A',
                        'Unexpected selected Unbound apex record')
                records[name] = fields[2]
                wanted = REDIRECTS.get(name, UNCHANGED.get(name))
                allowed = {LEGACY_PROXY, wanted} if name in REDIRECTS else {wanted}
                require(fields[2] in allowed, 'Selected Unbound apex drift needs review')
                if name in REDIRECTS and fields[2] != wanted:
                    start = line.index(content) + content.rfind(fields[2])
                    lines[index] = line[:start] + wanted + line[start + len(fields[2]):]
    for name in (*REDIRECTS, *UNCHANGED):
        require(zones.get(name) == 'redirect' and name in records,
                'Expected the declared original redirect zones and apex A records')
    if missing:
        # Place the narrow children next to their parent inside the same server
        # section. No general transparency or alternate forwarding is added.
        parent = next(zone for zone in REDIRECTS if missing[0].endswith('.' + zone))
        anchor = next(index for index, line in enumerate(lines)
                      if re.match(r'[ \t]*local-zone:[ \t]*["\']' + re.escape(parent) + r'\.?["\']', line))
        indentation = re.match('[ \t]*', lines[anchor]).group()
        ending = '\r\n' if lines[anchor].endswith('\r\n') else '\n'
        additions = [indentation + 'local-zone: "' + name + '." transparent' + ending for name in missing]
        lines[anchor + 1:anchor + 1] = additions
    return ''.join(lines)


def unbound_metadata(fd):
    require(hasattr(os, 'listxattr'), 'Linux ACL/xattr support is required before an Unbound write')
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 131072,
            'Expected the original bounded Unbound configuration inode')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns,
            'xattrs': {name: base64.b64encode(os.getxattr(fd, name)).decode()
                       for name in os.listxattr(fd)}}


def read_unbound():
    with os.fdopen(os.open(UNBOUND, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        metadata = unbound_metadata(stream.fileno())
        content = stream.read(131073)
        require(len(content) <= 131072 and unbound_metadata(stream.fileno()) == metadata,
                'Unbound configuration changed during its read')
    return content.decode('utf-8'), metadata


def private_bytes(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(content); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def stage_unbound(evidence, before, metadata, after):
    private_bytes(evidence / 'unbound-before.conf', before.encode())
    private_write(evidence / 'unbound-before.metadata.json', dict(metadata, sha256=hashlib.sha256(before.encode()).hexdigest()))
    command(COMPOSE_ARGV + ['exec', '-T', 'unbound', 'unbound-control', '-c', UNBOUND_CONTAINER, 'status'])
    if before == after:
        return None
    candidate = UNBOUND.parent / ('.foundation-dns-' + str(time.time_ns()) + '.conf')
    private_bytes(candidate, after.encode())
    container_candidate = str(Path(UNBOUND_CONTAINER).parent / candidate.name)
    command(COMPOSE_ARGV + ['exec', '-T', 'unbound', 'unbound-checkconf', container_candidate])
    return candidate


def apply_unbound(before, metadata, after, candidate):
    if before == after:
        return False
    with os.fdopen(os.open(UNBOUND, os.O_RDWR | os.O_NOFOLLOW), 'r+b') as stream:
        require(unbound_metadata(stream.fileno()) == metadata and stream.read() == before.encode(),
                'Unbound configuration drifted before mutation')
        stream.seek(0); stream.write(after.encode()); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        actual = unbound_metadata(stream.fileno())
        require(all(actual[key] == metadata[key] for key in ('device', 'inode', 'uid', 'gid', 'mode', 'xattrs')),
                'Unbound metadata changed; preserve its hold')
    command(COMPOSE_ARGV + ['exec', '-T', 'unbound', 'unbound-control', '-c', UNBOUND_CONTAINER, 'reload'])
    return True


def verify_unbound(after, metadata):
    actual, attributes = read_unbound()
    require(actual == after and all(attributes[key] == metadata[key]
            for key in ('device', 'inode', 'uid', 'gid', 'mode', 'xattrs')), 'Unbound readback or metadata differs')
    zones = command(COMPOSE_ARGV + ['exec', '-T', 'unbound', 'unbound-control', '-c', UNBOUND_CONTAINER, 'list_local_zones'])
    for name in ACME_EXCEPTIONS:
        require(re.search(r'(?m)^' + re.escape(name) + r'\.\s+transparent\s*$', zones) is not None,
                'Unbound did not load its selected ACME exception')
    for domain, address in {**REDIRECTS, **UNCHANGED}.items():
        output = command(COMPOSE_ARGV + ['exec', '-T', 'pihole', 'dig', '+short', '+time=2', '+tries=1',
                                         '@127.0.0.1', '-p', '5335', 'foundation-probe.' + domain, 'A'])
        require(output.split() == [address], 'An Unbound domain redirect readback differs')


def remote_run():
    """Runs as root only on the pinned guest; interrupted writes remain held."""
    require(SETTINGS is not None, 'Supply the reviewed DNS settings')
    require(os.geteuid() == 0, 'Run only through the existing DNS guest root SSH account')
    identity = json.loads(private_read(IDENTITY, owner=0))
    require(identity.get('vmid') == TARGET['vmid'] and identity.get('kind') == 'dns' and identity.get('hostname') == TARGET['hostname'],
            'The target is not the commissioned DNS guest')
    compose = json.loads(private_read(COMPOSE, owner=0))
    require(compose.get('name') == 'homelab-dns' and set(compose.get('services', {})) == {'pihole', 'unbound'},
            'Expected the existing DNS Compose stack')
    cid = command(COMPOSE_ARGV + ['ps', '-q', 'pihole']).strip()
    require(re.fullmatch('[0-9a-f]{12,64}', cid) is not None, 'Expected exactly one running Pi-hole container')
    environment = json.loads(command(['docker', 'inspect', '--format', '{{json .Config.Env}}', cid]))
    require(isinstance(environment, list) and all(isinstance(value, str) for value in environment),
            'Unexpected Pi-hole container environment')
    require(not any(value.partition('=')[0] == 'FTLCONF_dns_hosts' for value in environment),
            'FTL dns.hosts is controlled by environment; review that source before changing records')
    require('/srv/homelab/data/unbound:/opt/unbound/etc/unbound' in
            compose['services']['unbound'].get('volumes', []), 'Unexpected commissioned Unbound configuration mount')
    owned_directory(REMOTE_ROOT, owner=0)
    hold = REMOTE_ROOT / 'HOLD.json'
    with os.fdopen(os.open(REMOTE_ROOT / 'operation.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not hold.exists() and not hold.is_symlink(), 'A failed DNS operation is held; no automatic retry')
        before = get_hosts()
        after = merge_hosts(before)
        unbound_before, metadata = read_unbound()
        unbound_after = merge_unbound(unbound_before)
        evidence = REMOTE_ROOT / str(time.time_ns())
        owned_directory(evidence, owner=0)
        private_write(evidence / 'hosts-before.json', {'hosts': before})
        private_write(hold, {'operation': 'foundation-dns', 'evidence': str(evidence),
                             'records': RECORDS, 'unbound_redirects': REDIRECTS,
                             'preserved_redirects': UNCHANGED, 'acme_transparent': list(ACME_EXCEPTIONS),
                             'automatic_retry': False, 'remote_closure': 'unconfirmed'})
        # Refuse a concurrent UI/CLI edit after the private backup, rather than
        # overwrite it while normalizing only the selected names.
        require(get_hosts() == before, 'DNS hosts changed during admission; preserve the hold')
        candidate = stage_unbound(evidence, unbound_before, metadata, unbound_after)
        private_write(evidence / 'unbound-apply-started.json',
                      {'changed': unbound_before != unbound_after, 'remote_closure': 'unconfirmed'})
        unbound_changed = apply_unbound(unbound_before, metadata, unbound_after, candidate)
        private_write(evidence / 'unbound-apply-completed.json', {'changed': unbound_changed})
        changed = after != before
        if changed:
            # Unbound staging/reload can take time; recheck before replacing the FTL array.
            require(get_hosts() == before, 'DNS hosts changed before FTL write; preserve the hold')
            private_write(evidence / 'pihole-apply-started.json', {'remote_closure': 'unconfirmed'})
            command(COMPOSE_ARGV + ['exec', '-T', 'pihole', 'pihole-FTL', '--config', 'dns.hosts',
                                    json.dumps(after, separators=(',', ':'))])
            command(COMPOSE_ARGV + ['exec', '-T', 'pihole', 'pihole', 'reloaddns'])
        require(get_hosts() == after, 'FTL hosts readback differs; preserve the hold')
        verify_records()
        verify_unbound(unbound_after, metadata)
        if candidate is not None:
            candidate.unlink(); sync(candidate.parent)
        result = {'status': 'passed', 'vmid': TARGET['vmid'], 'records': RECORDS,
                  'changed': changed or unbound_changed, 'verified': True, 'remote_closure': 'completed',
                  'unbound_redirects': REDIRECTS, 'preserved_redirects': UNCHANGED,
                  'acme_transparent': list(ACME_EXCEPTIONS)}
        private_write(evidence / 'result.json', result)
        hold.unlink(); sync(REMOTE_ROOT)
        return result


def run(shared):
    """Anchor this existing guest through PVE and its existing SSH trust first."""
    require(SETTINGS is not None, 'Supply the reviewed DNS settings')
    cfg = json.loads(private_read(INPUT))
    require(cfg.get('site') == SITE
            and cfg['guest']['vmid'] == cfg['app']['vmid'] == TARGET['vmid']
            and cfg['guest']['hostname'] == cfg['app']['hostname'] == TARGET['hostname']
            and cfg['app']['kind'] == 'dns' and cfg['app']['mac'] == TARGET['mac']
            and cfg['paths']['known_hosts'] == str(HOSTS) and cfg['paths']['private_key'] == str(KEY)
            and cfg['paths']['state_root'] == str(WORK.parent), 'Unexpected commissioned DNS target or route')
    shared.validate(cfg)
    require(not Path('/var/lib/homelab-bootstrap/CONFIGURING').exists(), 'Bootstrap maintenance is active')
    require((WORK / 'started.json').is_file(), 'The existing DNS guest has not completed startup')
    hold = WORK / 'DNS-FOUNDATION-HOLD.json'
    require(not any((WORK / name).exists() or (WORK / name).is_symlink() for name in
                    ('HOLD.json', 'ROLLOUT-HOLD.json', 'DNS-STARTUP-HOLD.json', hold.name)),
            'A failed operation is held; no automatic retry')
    private_read(KEY); private_read(HOSTS)
    anchor = json.loads(private_read(WORK / 'ssh-trust.json'))
    require(anchor.get('address') == ADDRESS and len(anchor.get('keys', [])) == 1
            and anchor['keys'][0][0] == 'ssh-ed25519', 'Expected the current pinned DNS SSH identity')
    lookup = subprocess.run(['ssh-keygen', '-F', ADDRESS, '-f', str(HOSTS)],
                            capture_output=True, text=True, timeout=10, check=False)
    entries = [line.split()[1:3] for line in lookup.stdout.splitlines()
               if line and not line.startswith('#')]
    require(lookup.returncode == 0 and entries == anchor['keys'], 'The DNS address lacks its exact existing SSH key')
    require(shared.application_address(cfg) == ADDRESS, 'DNS address changed; no scan or alternate target')
    evidence = WORK / ('foundation-dns-' + str(time.time_ns()))
    owned_directory(evidence)
    shared.guest_identity.pin(cfg, evidence, ADDRESS, lambda path: shared.api_get(cfg, path), shared.write)
    private_write(hold, {'operation': 'foundation-dns', 'records': RECORDS,
                         'unbound_redirects': REDIRECTS, 'preserved_redirects': UNCHANGED,
                         'acme_transparent': list(ACME_EXCEPTIONS),
                         'evidence': str(evidence), 'automatic_retry': False, 'remote_closure': 'unconfirmed'})
    argv = ['ssh', '-F', '/dev/null', '-i', str(KEY), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(HOSTS),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no',
            '-o', 'ControlMaster=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'ConnectTimeout=8', 'root@' + ADDRESS, 'python3 - --remote ' + base64.urlsafe_b64encode(
                json.dumps(SETTINGS, separators=(',', ':')).encode()).decode()]
    result = subprocess.run(argv, input=Path(__file__).read_bytes(), capture_output=True, timeout=150, check=False)
    for name, output in (('ssh.stdout.log', result.stdout), ('ssh.stderr.log', result.stderr)):
        with os.fdopen(os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(output); stream.flush(); os.fsync(stream.fileno())
    require(result.returncode == 0, 'DNS execution failed or closure is unconfirmed; preserve both holds')
    outcome = json.loads(result.stdout)
    require(outcome == {'status': 'passed', 'vmid': TARGET['vmid'], 'records': RECORDS,
                        'changed': outcome.get('changed'), 'verified': True, 'remote_closure': 'completed',
                        'unbound_redirects': REDIRECTS, 'preserved_redirects': UNCHANGED,
                        'acme_transparent': list(ACME_EXCEPTIONS)}
            and type(outcome['changed']) is bool, 'DNS completion receipt is incomplete; preserve its hold')
    private_write(evidence / 'result.json', outcome)
    hold.unlink(); sync(WORK)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--remote', help=argparse.SUPPRESS)
    parser.add_argument('--settings', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.remote:
            require(len(args.remote) <= 32768, 'Oversized DNS settings transport')
            configure(json.loads(base64.b64decode(args.remote, altchars=b'-_', validate=True)))
            result = remote_run()
        else:
            require(args.settings is not None and args.settings.stat().st_size <= 16384, 'Supply bounded DNS settings')
            configure(json.loads(args.settings.read_text()))
            require(args.source is not None, 'Supply the existing pinned application source checkout')
            sys.path.insert(0, str(args.source.resolve() / 'proxmox/applications'))
            result = run(importlib.import_module('deploy'))
        print(json.dumps(result))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit('Foundation DNS stopped; preserve private evidence and holds. No automatic retry.') from None


if __name__ == '__main__':
    main()
