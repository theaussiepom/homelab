#!/usr/bin/env python3
"""Render one application guest from private inputs; never print its credentials."""
import argparse
import json
import ipaddress
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

KINDS = {'automation': {'homeassistant', 'node_red', 'mqtt'},
         'identity': {'server', 'worker', 'redis'},
         'dns': {'pihole', 'unbound'}, 'ingress': {'traefik'}}


def positive(value, name, minimum=1):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < minimum:
        raise ValueError(f'{name} must be a positive number')
    return value


def literal(value):
    """Compose interpolates dollar signs even in quoted YAML/JSON scalars."""
    if not isinstance(value, (str, int, float, bool)):
        raise ValueError('Environment values must be scalar')
    return str(value).replace('$', '$$')


def required(cfg, key):
    value = cfg.get(key)
    if not isinstance(value, str) or not value or '\n' in value or '\x00' in value:
        raise ValueError(f'Missing or invalid {key}')
    return value


def preserved(value, field):
    """Keep container-shell expansion literal through Compose interpolation."""
    if value is None and field in ('command', 'entrypoint'):
        return None
    if isinstance(value, str):
        return literal(value)
    if field in ('command', 'entrypoint') and isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [literal(v) for v in value]
    raise ValueError(f'Use a string, string argv or null for {field}; user requires a string')


def compose(cfg):
    """Keep placement fixed; site-specific images, restored data and routes are inputs."""
    kind = cfg.get('kind')
    if kind not in KINDS:
        raise ValueError('Choose dns, identity, ingress or automation; databases are native')
    inputs = cfg.get('services', {})
    if set(inputs) != KINDS[kind]:
        raise ValueError('Supply exactly the services for this guest')
    root = cfg.get('data_root', '/srv/homelab/data')
    if root != '/srv/homelab/data':
        raise ValueError('Restored application data belongs under /srv/homelab/data')
    budget = positive(cfg.get('guest_memory_mib'), 'guest_memory_mib')
    total = sum(positive(s.get('memory_mib'), 'memory_mib') for s in inputs.values())
    if total + 256 > budget:
        raise ValueError('Leave at least 256 MiB for the guest OS outside container limits')
    result = {'name': f'homelab-{kind}', 'services': {}}
    for name, value in inputs.items():
        image = value.get('image', '')
        if re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            if not str(value.get('archive', '')).startswith('/') or not re.fullmatch(r'[0-9a-f]{64}', value.get('archive_sha256', '')):
                raise ValueError('A local image needs its SHA256-verified image archive')
            policy = 'never'
        elif re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', image):
            policy = 'missing'
        else:
            raise ValueError('Pin each image by registry digest or verified local image ID')
        restart = value.get('restart', 'no')
        if restart not in ('no', 'unless-stopped'):
            raise ValueError('Select no restart for qualification, or the explicitly accepted ongoing policy')
        service = {'image': image, 'pull_policy': policy, 'restart': restart,
                   'mem_limit': f"{value['memory_mib']}m", 'cpus': positive(value.get('cpus'), 'cpus'),
                   'pids_limit': positive(value.get('pids_limit'), 'pids_limit'),
                   'stop_grace_period': '60s',
                   'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
                   'environment': {k: literal(v) for k, v in value.get('environment', {}).items()},
                   'volumes': [], 'network_mode': 'host'}
        service['environment']['TZ'] = literal(cfg.get('timezone', 'Etc/UTC'))
        # These paths refer to the restored capture, never to the source production host.
        mounts = {'homeassistant': [('homeassistant/config', '/config')],
                  'node_red': [('node-red/data', '/data'), ('node-red/config', '/config')],
                  'mqtt': [('mqtt/config', '/mosquitto/config'), ('mqtt/data', '/mosquitto/data'), ('mqtt/log', '/mosquitto/log')],
                  'server': [('authentik/media', '/media'), ('authentik/templates', '/templates')],
                  'worker': [('authentik/media', '/media'), ('authentik/templates', '/templates'), ('authentik/certs', '/certs')],
                  'redis': [('redis', '/data')], 'pihole': [('pihole', '/etc/pihole')],
                  'unbound': [('unbound', '/opt/unbound/etc/unbound')],
                  'traefik': [('traefik', '/etc/traefik')]}[name]
        service['volumes'] = [f'{root}/{src}:{target}' for src, target in mounts]
        for mount in value.get('extra_mounts', []):
            src, target = mount.get('source', ''), mount.get('target', '')
            if not re.fullmatch(re.escape(root) + r'/[A-Za-z0-9_./-]+', src) or '..' in src.split('/') or ':' in target or not target.startswith('/') or '..' in target.split('/'):
                raise ValueError('Extra mounts must come from the captured /srv/homelab/data tree')
            if target in {'/var/run/docker.sock', '/run/docker.sock', '/run/avahi-daemon/socket'} or target in [t for _, t in mounts]:
                raise ValueError('Do not expose host control sockets or override data mounts')
            service['volumes'].append(f"{src}:{target}:{'ro' if mount.get('read_only', True) else 'rw'}")
        if name in {'homeassistant', 'node_red', 'mqtt'}:
            # Existing custom images and helper entrypoints are preserved, not replaced.
            for key in ('command', 'entrypoint', 'user'):
                if key in value:
                    service[key] = preserved(value[key], key)
        capabilities = value.get('cap_add', [])
        if capabilities:
            if name != 'homeassistant' or capabilities != ['NET_ADMIN']:
                raise ValueError('Only the explicitly selected HA mDNS NET_ADMIN capability is supported')
            service['cap_add'] = capabilities
        if name == 'homeassistant' and 'HOMELAB_HA_IPV4' in value.get('environment', {}):
            if ipaddress.ip_address(value['environment']['HOMELAB_HA_IPV4']).version != 4 or capabilities != ['NET_ADMIN']:
                raise ValueError('The selected mDNS helper needs an explicit IPv4 address and guest network capability')
            if f'{root}/ha-startup:/startup:ro' not in service['volumes']:
                raise ValueError('Mount the captured HA startup directory read-only for the mDNS helper')
        result['services'][name] = service
    services = result['services']
    if kind == 'identity':
        env = {'AUTHENTIK_SECRET_KEY': required(cfg, 'authentik_secret_key'),
               'AUTHENTIK_POSTGRESQL__HOST': required(cfg, 'postgresql_host'),
               'AUTHENTIK_POSTGRESQL__USER': required(cfg, 'postgresql_user'),
               'AUTHENTIK_POSTGRESQL__PASSWORD': required(cfg, 'postgresql_password'),
               'AUTHENTIK_POSTGRESQL__NAME': required(cfg, 'postgresql_database'),
               'AUTHENTIK_REDIS__HOST': 'redis'}
        for name in ('server', 'worker'):
            del services[name]['network_mode']
            services[name]['command'] = name
            services[name]['environment'].update({k: literal(v) for k, v in env.items()})
            services[name]['depends_on'] = ['redis']
        del services['redis']['network_mode']
        services['redis']['command'] = ['redis-server', '--appendonly', 'yes']
        services['server']['ports'] = ['9000:9000', '9443:9443']
    if kind == 'dns':
        services['pihole']['environment'].update({'FTLCONF_dhcp_active': 'false',
                                                'FTLCONF_dns_upstreams': '127.0.0.1#5335'})
        del services['unbound']['network_mode']
        services['unbound']['ports'] = ['127.0.0.1:5335:53/tcp', '127.0.0.1:5335:53/udp']
    if kind == 'ingress':
        services['traefik']['command'] = ['--configFile=/etc/traefik/traefik.yml']
    return result


def ingress(cfg):
    """A file provider reaches other guests without a Docker socket or HA SSO."""
    if cfg.get('kind') != 'ingress':
        raise ValueError('Ingress settings belong to the ingress guest')
    routers, services = {}, {}
    for name in ('homeassistant', 'node_red', 'identity'):
        host, url = required(cfg, f'{name}_host'), required(cfg, f'{name}_url')
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host):
            raise ValueError('Use literal DNS names for routes')
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Use credential-free backend HTTP URLs')
        routers[name] = {'rule': f'Host(`{host}`)', 'entryPoints': ['websecure'], 'tls': {}, 'service': name}
        services[name] = {'loadBalancer': {'servers': [{'url': url}], 'passHostHeader': True}}
    routers['node_red']['middlewares'] = ['authentik']
    routers['outpost'] = {'rule': f"Host(`{cfg['node_red_host']}`) && PathPrefix(`/outpost.goauthentik.io/`)",
                          'priority': 100, 'entryPoints': ['websecure'], 'tls': {}, 'service': 'identity'}
    middleware = {'authentik': {'forwardAuth': {
        'address': cfg['identity_url'].rstrip('/') + '/outpost.goauthentik.io/auth/traefik',
        'trustForwardHeader': False,
        'authResponseHeaders': ['X-authentik-username', 'X-authentik-groups', 'X-authentik-email', 'X-authentik-name', 'X-authentik-uid']}}}
    return {'http': {'routers': routers, 'services': services, 'middlewares': middleware}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    documents = {'compose.yml': compose(cfg)}
    if cfg['kind'] == 'ingress':
        documents['routes.yml'] = ingress(cfg)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, document in documents.items():
        path = args.output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')


if __name__ == '__main__':
    main()
