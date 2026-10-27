#!/usr/bin/env python3
"""Prove selective ACME transparency using pinned Unbound and a local authority.

Both Unbound instances share a network=none container. The upstream is a
controlled static authoritative zone on loopback15353, containing synthetic TXT
values. No public DNS, guest or Ubuntu container is contacted. The only bind
mount is a fresh synthetic config directory; the supplied baseline is copied.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import sys
import os
from pathlib import Path
import subprocess
import time
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation_dns as cd
import site_config

SETTINGS = site_config.render(site_config.read(site_config.ROOT / 'examples/foundation.site.example.json'))['dns-settings.json']
cd.configure(SETTINGS)

IMAGE = 'mvance/unbound@sha256:76906da36d1806f3387338f15dcf8b357c51ce6897fb6450d6ce010460927e90'
CLIENT = 'pihole/pihole@sha256:70a9c11171ded2eee735d88c127996da209284a329d50f5ae59c06b861d401b3'


def cli(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=35, check=False)
    if check and result.returncode:
        raise RuntimeError('Offline fixture command failed: ' + result.stderr[-2500:])
    return result


def run(baseline, output):
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = output / 'config'; config.mkdir(mode=0o700)
    before = baseline.read_text() if baseline else (
        'remote-control:\n    control-enable: yes\nserver:\n    interface: 127.0.0.1\n    port: 53\n'
        '    access-control: 127.0.0.1/32 allow\n    do-ip6: no\n'
        + ''.join('    local-zone: \"' + name + '\" redirect\n' for name in (*cd.REDIRECTS, *cd.UNCHANGED))
        + ''.join('    local-data: \"' + name + ' A ' + address + '\"\n' for name, address in
                  {**{name: cd.LEGACY_PROXY for name in cd.REDIRECTS}, **cd.UNCHANGED}.items()))
    baseline_hash = hashlib.sha256(before.encode()).hexdigest()
    cd.merge_unbound(before)
    before = before.replace('    port: 53\n', '    port: 5335\n')
    before += ('\n    # Offline fixture transport only; production settings stay unchanged.\n'
               '    username: ""\n    chroot: ""\n    directory: "/opt/unbound/etc/unbound"\n'
               '    do-not-query-localhost: no\n    module-config: "iterator"\n'
               '    use-syslog: no\n    logfile: "/tmp/recursive.log"\n    pidfile: "/tmp/recursive.pid"\n'
               '    msg-cache-size: 1m\n    rrset-cache-size: 2m\n'
               'forward-zone:\n    name: "lab.example.org."\n    forward-addr: 127.0.0.1@15353\n'
               '    forward-first: no\n')
    active = config / 'unbound.conf'; active.write_text(before); active.chmod(0o640)
    authority = ('server:\n    interface: 127.0.0.1\n    port: 15353\n    username: ""\n    chroot: ""\n'
        '    directory: "/opt/unbound/etc/unbound"\n    access-control: 127.0.0.1/32 allow\n'
        '    use-syslog: no\n    logfile: "/tmp/authority.log"\n    log-queries: yes\n'
        '    pidfile: "/tmp/authority.pid"\n    do-ip6: no\n    module-config: "iterator"\n'
        '    local-zone: "lab.example.org." static\n'
        '    local-data: \'lab.example.org. 60 IN SOA ns.lab.example.org. hostmaster.lab.example.org. 1 60 60 60 60\'\n'
        '    local-data: \'_acme-challenge.sso.lab.example.org. 60 IN TXT "synthetic-sso-txt"\'\n'
        '    local-data: \'_acme-challenge.pgadmin.lab.example.org. 60 IN TXT "synthetic-pgadmin-txt"\'\n')
    (config / 'authority.conf').write_text(authority)
    for image in (IMAGE, CLIENT): cli(['docker', 'image', 'inspect', image])
    name = 'homelab-unbound-fixture-' + uuid.uuid4().hex[:12]
    calls = []
    try:
        cli(['docker', 'run', '--detach', '--pull', 'never', '--platform', 'linux/amd64', '--name', name,
             '--network', 'none', '--memory', '384m', '--cpus', '1', '--pids-limit', '96',
             '-v', str(config.resolve()) + ':/opt/unbound/etc/unbound', '--entrypoint', '/bin/sh', IMAGE, '-c',
             'set -e; unbound-control-setup -d /opt/unbound/etc/unbound >/tmp/control-setup.log 2>&1; '
             'unbound-checkconf /opt/unbound/etc/unbound/authority.conf; '
             'unbound-checkconf /opt/unbound/etc/unbound/unbound.conf; '
             'unbound -d -c /opt/unbound/etc/unbound/authority.conf >/tmp/authority.stdout 2>&1 & '
             'exec unbound -d -c /opt/unbound/etc/unbound/unbound.conf'])
        deadline = time.monotonic() + 40
        while True:
            status = cli(['docker', 'exec', name, 'unbound-control', '-c', cd.UNBOUND_CONTAINER, 'status'], check=False)
            if status.returncode == 0: break
            if time.monotonic() > deadline: raise RuntimeError('Offline Unbound control did not become ready')
            time.sleep(1)
        version = cli(['docker', 'exec', name, 'unbound', '-V']).stdout.splitlines()[0]
        def dig(domain, qtype, port=5335):
            return cli(['docker', 'run', '--rm', '--pull', 'never', '--platform', 'linux/amd64',
                '--network', 'container:' + name, '--entrypoint', 'dig', CLIENT,
                '+short', '+time=2', '+tries=1', '@127.0.0.1', '-p', str(port), domain, qtype]).stdout.split()
        assert dig('foundation-probe.lab.example.org', 'A') == ['192.168.200.254']
        assert dig(cd.ACME_EXCEPTIONS[0], 'TXT') == []  # Parent redirect blocks it before the patch.
        assert dig(cd.ACME_EXCEPTIONS[0], 'TXT', 15353) == ['"synthetic-sso-txt"']
        def transport(argv):
            calls.append(argv)
            prefix = cd.COMPOSE_ARGV + ['exec', '-T', 'unbound']
            if argv[:len(prefix)] == prefix:
                return cli(['docker', 'exec', name, *argv[len(prefix):]]).stdout
            prefix = cd.COMPOSE_ARGV + ['exec', '-T', 'pihole', 'dig']
            if argv[:len(prefix)] == prefix:
                return cli(['docker', 'run', '--rm', '--pull', 'never', '--platform', 'linux/amd64',
                    '--network', 'container:' + name, '--entrypoint', 'dig', CLIENT, *argv[len(prefix):]]).stdout
            raise RuntimeError('Offline fixture refused an unrelated command')
        with ExitStack() as context:
            context.enter_context(patch.multiple(cd, UNBOUND=active, command=transport))
            # Native helper runs on Linux, where fd ACL/xattr APIs are present.
            # On macOS only this transport fixture stubs absent xattr APIs;
            # a separate actual Linux metadata test exercises ACL/xattr bytes.
            if not hasattr(os, 'listxattr'):
                context.enter_context(patch.object(cd.os, 'listxattr', return_value=[], create=True))
            original, metadata = cd.read_unbound(); after = cd.merge_unbound(original)
            evidence = output / 'first'; evidence.mkdir(mode=0o700)
            cd.private_write(output / 'HOLD.json', {'fixture': True, 'automatic_retry': False})
            candidate = cd.stage_unbound(evidence, original, metadata, after)
            assert cd.apply_unbound(original, metadata, after, candidate) is True
            cd.verify_unbound(after, metadata)
            candidate.unlink()
            assert dig(cd.ACME_EXCEPTIONS[0], 'TXT') == ['"synthetic-sso-txt"']
            assert dig(cd.ACME_EXCEPTIONS[1], 'TXT') == ['"synthetic-pgadmin-txt"']
            # Transparency is limited to two children, not every TXT name.
            assert dig('unselected.lab.example.org', 'TXT') == []
            current, attributes = cd.read_unbound()
            evidence = output / 'second'; evidence.mkdir(mode=0o700)
            assert cd.stage_unbound(evidence, current, attributes, current) is None
            assert cd.apply_unbound(current, attributes, current, None) is False
            cd.verify_unbound(current, attributes)
            assert cd.read_unbound() == (current, attributes)
            (output / 'HOLD.json').unlink()
        reloads = sum(argv[-1] == 'reload' for argv in calls)
        assert reloads == 1
        result = {'status': 'passed', 'image': IMAGE, 'version': version,
            'baseline_sha256': baseline_hash,
            'redirects': cd.REDIRECTS, 'unchanged_redirects': cd.UNCHANGED,
            'transparent_acme_children': list(cd.ACME_EXCEPTIONS), 'controlled_authority_txt': 'passed',
            'parent_txt_blocked_before_patch': True, 'unselected_txt_not_forwarded': True,
            'candidate_checkconf': 'passed', 'control_reload_count': reloads,
            'second_run_verify_only': True, 'inode_owner_mode_preserved': True,
            'network': 'none', 'published_ports': [], 'public_dns_contacted': False,
            'native_guest_contacted': False, 'linux_acl_xattr_test': 'separate focused Linux unit fixture'}
        cd.private_write(output / 'result.json', result)
        return result
    except BaseException:
        for filename in ('recursive.log', 'authority.log', 'authority.stdout', 'control-setup.log'):
            data = cli(['docker', 'exec', name, 'cat', '/tmp/' + filename], check=False)
            (output / filename).write_text(data.stdout + data.stderr)
        data = cli(['docker', 'logs', name], check=False)
        (output / 'container.log').write_text(data.stdout + data.stderr)
        raise
    finally:
        result = cli(['docker', 'rm', '--force', name], check=False)
        cd.private_write(output / 'cleanup.json', {'container': name, 'removed': result.returncode == 0})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, help='Optional synthetic fixture baseline')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.baseline, args.output)))
