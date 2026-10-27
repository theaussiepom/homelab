#!/usr/bin/env python3
"""Opt-in actual Pi-hole CLI fixture, isolated from household DNS and networking.

Run: python3 proxmox/applications/tests/foundation_dns_docker_fixture.py --output /private/tmp/foundation-dns-fixture
Requires the exact commissioned image to have been pulled already. The fixture
uses network=none, no published ports, no host service/data mounts, and ephemeral
container filesystems. Guest identity and SSH/PVE transport are synthetic; the
prepared helper's FTL getter/setter/cache-reload/dig operations run unmodified
against the real pinned Pi-hole binary via a Docker-exec transport adapter.
"""
import argparse
from contextlib import ExitStack
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

IMAGE = 'pihole/pihole@sha256:70a9c11171ded2eee735d88c127996da209284a329d50f5ae59c06b861d401b3'
INITIAL = ['192.168.200.5 sso.lab.example.org old-proxy.example.invalid',
           '192.168.200.5 pgadmin.lab.example.org another.example.invalid',
           '10.88.25.2\tnas.example.invalid nas']


def cli(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
    if check and result.returncode:
        raise RuntimeError('Synthetic container command failed: ' + result.stderr[-3000:])
    return result


def run(output):
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli(['docker', 'image', 'inspect', IMAGE])  # Never pull implicitly.
    name = 'homelab-dns-fixture-' + uuid.uuid4().hex[:12]
    mutations, reloads, probes = [], [], []
    cleanup = None
    try:
        cli(['docker', 'run', '--detach', '--pull', 'never', '--platform', 'linux/amd64', '--name', name, '--network', 'none',
             '--cpus', '1', '--memory', '512m', '--pids-limit', '128',
             '--tmpfs', '/etc/pihole:rw,nosuid,nodev,size=64m',
             '--tmpfs', '/var/log/pihole:rw,nosuid,nodev,size=32m',
             '-e', 'TZ=UTC', '-e', 'FTLCONF_dns_upstreams=127.0.0.1#9',
             '-e', 'FTLCONF_ntp_ipv4_active=false', '-e', 'FTLCONF_ntp_ipv6_active=false',
             '-e', 'FTLCONF_webserver_api_password=synthetic-offline-fixture',
             '--entrypoint', '/bin/sh', IMAGE, '-c',
             'pihole-FTL sqlite3 /etc/pihole/gravity.db < /etc/.pihole/advanced/Templates/gravity.db.sql && exec /usr/bin/start.sh'])
        deadline = time.monotonic() + 60
        while True:
            probe = cli(['docker', 'exec', name, 'pihole-FTL', '--config', 'dns.hosts'], check=False)
            service = cli(['docker', 'exec', name, 'dig', '+short', '+time=1', '+tries=1', '@127.0.0.1', 'pi.hole', 'A'], check=False)
            if probe.returncode == service.returncode == 0:
                cd.parse_hosts(probe.stdout)
                break
            if time.monotonic() > deadline:
                raise RuntimeError('Synthetic Pi-hole did not become ready')
            time.sleep(1)
        version = cli(['docker', 'exec', name, 'pihole-FTL', '--version']).stdout.strip()
        cli(['docker', 'exec', name, 'pihole-FTL', '--config', 'dns.hosts', json.dumps(INITIAL)])
        cli(['docker', 'exec', name, 'pihole', 'reloaddns'])
        original = cd.parse_hosts(cli(['docker', 'exec', name, 'pihole-FTL', '--config', 'dns.hosts']).stdout)
        # FTL normalizes HOSTS whitespace while saving. Establish the actual
        # getter baseline before the helper; every hostname/IP must still match.
        if [line.split() for line in original] != [line.split() for line in INITIAL]:
            raise RuntimeError('Synthetic setup hosts readback differs')
        identity, compose, remote = output / 'identity.json', output / 'compose.json', output / 'remote-evidence'
        identity.write_text(json.dumps({'vmid': 6101, 'kind': 'dns', 'hostname': 'dns'})); identity.chmod(0o600)
        compose.write_text(json.dumps({'name': 'homelab-dns', 'services': {'pihole': {}, 'unbound': {
            'volumes': ['/srv/homelab/data/unbound:/opt/unbound/etc/unbound']}}})); compose.chmod(0o600)
        original_read, original_directory = cd.private_read, cd.owned_directory
        fixture_uid = os.getuid()
        container_id = cli(['docker', 'inspect', '--format', '{{.Id}}', name]).stdout.strip()
        unbound_fixture = 'server:\n' + ''.join(
            f'    local-zone: "{domain}" redirect\n    local-data: "{domain} A {address}"\n'
            for domain, address in {**cd.REDIRECTS, **cd.UNCHANGED}.items())
        unbound_fixture = cd.merge_unbound(unbound_fixture)
        def transport(argv):
            if argv == cd.COMPOSE_ARGV + ['ps', '-q', 'pihole']:
                return container_id + '\n'
            if argv[:3] == ['docker', 'inspect', '--format']:
                return cli(argv).stdout
            prefix = cd.COMPOSE_ARGV + ['exec', '-T', 'pihole']
            if argv[:len(prefix)] != prefix:
                raise RuntimeError('Fixture refused an unrelated command')
            operation = argv[len(prefix):]
            if operation[:3] == ['pihole-FTL', '--config', 'dns.hosts'] and len(operation) == 4:
                mutations.append(operation)
            if operation == ['pihole', 'reloaddns']:
                reloads.append(operation)
            if operation[0] == 'dig':
                probes.append(operation)
            return cli(['docker', 'exec', name, *operation]).stdout
        with ExitStack() as context:
            context.enter_context(patch.multiple(cd, IDENTITY=identity, COMPOSE=compose, REMOTE_ROOT=remote,
                command=transport,
                read_unbound=lambda: (unbound_fixture, {}), stage_unbound=lambda *args: None,
                apply_unbound=lambda *args: False, verify_unbound=lambda *args: None,
                private_read=lambda path, owner=None: original_read(path, owner=fixture_uid),
                owned_directory=lambda path, owner=None: original_directory(path, owner=fixture_uid)))
            context.enter_context(patch.object(cd.os, 'geteuid', return_value=0))
            first = cd.remote_run()
            first_counts = {'sets': len(mutations), 'reloads': len(reloads), 'dig_probes': len(probes)}
            second = cd.remote_run()
        final = cd.parse_hosts(cli(['docker', 'exec', name, 'pihole-FTL', '--config', 'dns.hosts']).stdout)
        expected = cd.merge_hosts(original)
        assert first['changed'] is True and second['changed'] is False
        assert first_counts == {'sets': 1, 'reloads': 1, 'dig_probes': 2}
        assert len(mutations) == 1 and len(reloads) == 1 and len(probes) == 4
        assert final == expected and final[:3] == ['192.168.200.5 old-proxy.example.invalid',
                '192.168.200.5 another.example.invalid', original[2]]
        assert not (remote / 'HOLD.json').exists()
        result = {'status': 'passed', 'image': IMAGE, 'ftl_version': version,
                  'first': first, 'second': second, 'hosts_before': original, 'hosts_after': final,
                  'configuration_writes': len(mutations), 'cache_reloads': len(reloads), 'dns_probes': len(probes),
                  'unrelated_aliases_preserved': True, 'second_run_verify_only': True,
                  'network': 'none', 'published_ports': [], 'native_target_contacted': False,
                  'unbound_component': 'Stubbed here; actual Unbound has a separate pinned fixture',
                  'scope': 'Actual pinned FTL CLI/reload/dig with synthetic guest identity and Docker-exec transport'}
        cd.private_write(output / 'result.json', result)
        return result
    except BaseException:
        logs = cli(['docker', 'logs', name], check=False)
        (output / 'container.stdout.log').write_text(logs.stdout)
        (output / 'container.stderr.log').write_text(logs.stderr)
        raise
    finally:
        cleanup = cli(['docker', 'rm', '--force', name], check=False)
        cd.private_write(output / 'cleanup.json', {'container': name, 'removed': cleanup.returncode == 0})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output)))


if __name__ == '__main__':
    main()
