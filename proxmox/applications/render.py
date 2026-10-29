#!/usr/bin/env python3
"""Render one application guest from private inputs; never print its credentials."""
import argparse
import ast
import json
import ipaddress
import importlib.util
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
_bitwarden_spec = importlib.util.spec_from_file_location('homelab_bitwarden', Path(__file__).with_name('bitwarden.py'))
bitwarden = importlib.util.module_from_spec(_bitwarden_spec)
_bitwarden_spec.loader.exec_module(bitwarden)
_monitoring_spec = importlib.util.spec_from_file_location('homelab_monitoring', Path(__file__).with_name('monitoring.py'))
monitoring = importlib.util.module_from_spec(_monitoring_spec)
_monitoring_spec.loader.exec_module(monitoring)
_foundation_spec = importlib.util.spec_from_file_location('homelab_foundation', Path(__file__).with_name('foundation.py'))
foundation = importlib.util.module_from_spec(_foundation_spec)
_foundation_spec.loader.exec_module(foundation)

foundation_files = foundation.files
foundation_source_files = foundation.source_files

_zigbee_spec = importlib.util.spec_from_file_location('homelab_zigbee', Path(__file__).with_name('zigbee2mqtt.py'))
zigbee2mqtt = importlib.util.module_from_spec(_zigbee_spec)
_zigbee_spec.loader.exec_module(zigbee2mqtt)

KINDS = {'automation': {'homeassistant', 'node_red', 'mqtt'},
         'identity': {'server', 'worker', 'redis'},
         'dns': {'pihole', 'unbound'}, 'ingress': {'traefik'},
         'db-tools': {'pgadmin'}, 'bitwarden': {'bitwarden'}, 'zigbee2mqtt': {'zigbee2mqtt'}}


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


def pgadmin_environment(value):
    """Check the retained native OAuth2 contract without evaluating config code."""
    env = value.get('environment', {})
    try:
        sources = ast.literal_eval(env.get('PGADMIN_CONFIG_AUTHENTICATION_SOURCES', ''))
        providers = ast.literal_eval(env.get('PGADMIN_CONFIG_OAUTH2_CONFIG', ''))
    except (ValueError, SyntaxError, TypeError):
        raise ValueError('Supply the existing pgAdmin OAuth2 settings as Python literals') from None
    if sources != ['oauth2'] or not isinstance(providers, list) or not providers or any(
            not isinstance(p, dict) or not all(isinstance(p.get(k), str) and p[k]
                for k in ('OAUTH2_NAME', 'OAUTH2_CLIENT_ID', 'OAUTH2_CLIENT_SECRET')) for p in providers):
        raise ValueError('Preserve OAuth2-only authentication and the existing provider/client credentials')
    if 'PGADMIN_CONFIG_SERVER_MODE' in env and env['PGADMIN_CONFIG_SERVER_MODE'] not in ('True', True):
        raise ValueError('pgAdmin requires server mode for OAuth2-only login')
    if any(p.get('OAUTH2_SSL_CERT_VERIFICATION', True) is not True for p in providers):
        raise ValueError('pgAdmin OAuth2 certificate verification must remain enabled')
    if env.get('PGADMIN_LISTEN_ADDRESS', '0.0.0.0') != '0.0.0.0':
        raise ValueError('pgAdmin container listener must accept the published bridge port')
    if (value.get('extra_mounts') or any(k in env for k in
            ('PGADMIN_ENABLE_TLS', 'PGADMIN_CUSTOM_CONFIG_DISTRO_FILE'))
            or str(env.get('PGADMIN_LISTEN_PORT', '80')) != '80'):
        raise ValueError('pgAdmin uses its retained environment, data mount and HTTP port 80')


def compose(cfg):
    """Keep placement fixed; site-specific images, restored data and routes are inputs."""
    if cfg.get('kind') == 'monitoring':
        return monitoring.compose(cfg)
    kind = cfg.get('kind')
    if kind == 'pegaprox':
        import pegaprox
        return pegaprox.compose(cfg)
    if kind not in KINDS:
        raise ValueError('Choose a supported application kind; databases are native')
    inputs = cfg.get('services', {})
    if set(inputs) != KINDS[kind]:
        raise ValueError('Supply exactly the services for this guest')
    if kind == 'zigbee2mqtt':
        zigbee2mqtt.validate(cfg.get('zigbee'))
        radio = inputs['zigbee2mqtt']
        if (set(radio.get('environment', {})) - {'TZ'} or radio.get('extra_mounts') or
                any(key in radio for key in ('command', 'entrypoint', 'user'))):
            raise ValueError('Preserve Zigbee configuration without environment, command or mount overrides')
    if kind == 'identity' and inputs['server'].get('image') != inputs['worker'].get('image'):
        raise ValueError('Authentik server and worker require the same pinned image')
    root = cfg.get('data_root', '/srv/homelab/data')
    if root != '/srv/homelab/data':
        raise ValueError('Restored application data belongs under /srv/homelab/data')
    budget = positive(cfg.get('guest_memory_mib'), 'guest_memory_mib')
    total = sum(positive(s.get('memory_mib'), 'memory_mib') for s in inputs.values())
    if total + 256 > budget:
        raise ValueError('Leave at least 256 MiB for the guest OS outside container limits')
    foundation.validate(cfg)
    if kind == 'bitwarden':
        bitwarden.validate(cfg)
    if kind == 'db-tools' and 'foundation' not in cfg:
        pgadmin_environment(inputs['pgadmin'])
    result = {'name': f'homelab-{kind}', 'services': {}}
    for name, value in inputs.items():
        image = value.get('image', '')
        if kind == 'bitwarden' and image == 'ghcr.io/bitwarden/lite:latest':
            # Explicit service policy: the operator selected latest, without a version pin.
            policy = 'always'
        elif re.fullmatch(r'sha256:[0-9a-f]{64}', image):
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
        if 'extra_hosts' in value:
            hosts = value['extra_hosts']
            if (kind != 'automation' or not isinstance(hosts, dict) or len(hosts) > 32
                    or any(not isinstance(host, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,252}', host) for host in hosts)):
                raise ValueError('Use a finite automation hostname-to-address map')
            for address in hosts.values():
                ip = ipaddress.IPv4Address(address)
                if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                    raise ValueError('Automation host aliases require usable literal IPv4 addresses')
            service['extra_hosts'] = dict(hosts)
        # These paths refer to the restored capture, never to the source production host.
        mounts = {'homeassistant': [('homeassistant/config', '/config')],
                  'node_red': [('node-red/data', '/data'), ('node-red/config', '/config')],
                  'mqtt': [('mqtt/config', '/mosquitto/config'), ('mqtt/data', '/mosquitto/data'), ('mqtt/log', '/mosquitto/log')],
                  'server': [('authentik/media', '/media'), ('authentik/templates', '/templates')],
                  'worker': [('authentik/media', '/media'), ('authentik/templates', '/templates'), ('authentik/certs', '/certs')],
                  'redis': [('redis', '/data')], 'pihole': [('pihole', '/etc/pihole')],
                  'unbound': [('unbound', '/opt/unbound/etc/unbound')],
                  'traefik': [('traefik', '/etc/traefik')],
                  'pgadmin': [('pgadmin', '/var/lib/pgadmin')],
                  'zigbee2mqtt': [('zigbee2mqtt', '/app/data')],
                  'bitwarden': [('bitwarden/data', '/etc/bitwarden'), ('bitwarden/logs', '/var/log/bitwarden')]}[name]
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
        if kind == 'identity' and 'user' in value:
            service['user'] = preserved(value['user'], 'user')
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
    if kind == 'automation' and 'node_red_oidc' in cfg:
        oidc = cfg['node_red_oidc']
        if (not isinstance(oidc, dict) or set(oidc) != {'identity_url', 'node_red_url', 'client_id', 'provider_slug'}
                or not isinstance(oidc['client_id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', oidc['client_id'])
                or not isinstance(oidc['provider_slug'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', oidc['provider_slug'])):
            raise ValueError('Preserve the selected native Node-RED OIDC client and provider')
        for name in ('identity_url', 'node_red_url'):
            origin = oidc[name]
            if (not isinstance(origin, str)
                    or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in origin)):
                raise ValueError('Node-RED OIDC requires literal HTTPS origins')
            parsed = urlsplit(origin)
            if (parsed.scheme != 'https' or not dns_name(parsed.hostname) or parsed.port is not None
                    or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
                raise ValueError('Node-RED OIDC requires literal HTTPS origins')
        node = services['node_red']
        if (node.get('command') != ['--settings', '/runtime-settings.js']
                or f'{root}/node-red/runtime-settings.js:/runtime-settings.js:ro' not in node['volumes']):
            raise ValueError('Native Node-RED OIDC must use the preserved settings wrapper')
        node['environment'].update({
            'NODE_RED_IDENTITY_URL': oidc['identity_url'].rstrip('/'),
            'NODE_RED_EXTERNAL_URL': oidc['node_red_url'].rstrip('/'),
            'NODE_RED_OIDC_CLIENT_ID': oidc['client_id'],
            'NODE_RED_OIDC_PROVIDER': oidc['provider_slug']})
    if kind == 'identity':
        env = foundation.identity_environment(cfg) if 'foundation' in cfg else {'AUTHENTIK_SECRET_KEY': required(cfg, 'authentik_secret_key'),
               'AUTHENTIK_POSTGRESQL__HOST': required(cfg, 'postgresql_host'),
               'AUTHENTIK_POSTGRESQL__USER': required(cfg, 'postgresql_user'),
               'AUTHENTIK_POSTGRESQL__PASSWORD': required(cfg, 'postgresql_password'),
               'AUTHENTIK_POSTGRESQL__NAME': required(cfg, 'postgresql_database'),
               'AUTHENTIK_REDIS__HOST': 'redis'}
        for name in ('server', 'worker'):
            del services[name]['network_mode']
            services[name]['command'] = name
            services[name]['environment'].update({k: literal(v) for k, v in env.items()})
            services[name]['depends_on'] = {'redis': {'condition': 'service_healthy'}}
        del services['redis']['network_mode']
        services['redis']['command'] = preserved(
            inputs['redis'].get('command', ['redis-server', '--appendonly', 'yes']), 'command')
        command = services['redis']['command']
        if (command == [] or isinstance(command, str) and not command.strip()
                or isinstance(command, list) and not command[0].strip()):
            raise ValueError('Redis command must not replace the image startup with an empty command')
        services['redis']['healthcheck'] = {
            'test': ['CMD-SHELL', 'redis-cli ping | grep -qx PONG'],
            'start_period': '20s', 'interval': '30s', 'retries': 5, 'timeout': '3s'}
        services['server']['ports'] = ['9000:9000', '9443:9443']
    if kind == 'dns':
        services['pihole']['environment'].update({'FTLCONF_dhcp_active': 'false',
                                                'FTLCONF_dns_upstreams': '127.0.0.1#5335'})
        del services['unbound']['network_mode']
        services['unbound']['ports'] = ['127.0.0.1:5335:53/tcp', '127.0.0.1:5335:53/udp']
    if kind == 'ingress':
        services['traefik']['command'] = ['--configFile=/etc/traefik/traefik.yml']
    if kind == 'db-tools':
        address = ipaddress.IPv4Address(required(cfg, 'pgadmin_bind_address'))
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
            raise ValueError('Publish pgAdmin only on the selected backend IPv4 address')
        del services['pgadmin']['network_mode']
        services['pgadmin']['ports'] = [f'{address}:80:80']
        # A missing capture must fail, rather than initializing a fresh profile.
        services['pgadmin']['volumes'] = [{'type': 'bind', 'source': f'{root}/pgadmin',
            'target': '/var/lib/pgadmin', 'bind': {'create_host_path': False}}]
    if kind == 'zigbee2mqtt':
        radio = cfg['zigbee']
        service = services['zigbee2mqtt']
        del service['network_mode']
        service['ports'] = [f"{radio['bind_address']}:{radio['frontend_port']}:{radio['frontend_port']}"]
        service['devices'] = [f"{radio['serial_device']}:/dev/ttyACM0:rw"]
        service['volumes'] = [{'type': 'bind', 'source': f'{root}/zigbee2mqtt',
            'target': '/app/data', 'bind': {'create_host_path': False}}]
    if kind == 'bitwarden':
        return bitwarden.configure(cfg, result)
    if kind == 'zigbee2mqtt':
        selected_alias = zigbee2mqtt.mqtt_alias(cfg)
        if selected_alias:
            services['zigbee2mqtt']['extra_hosts'] = selected_alias
    return foundation.configure_compose(cfg, result)


def dns_name(host):
    return (isinstance(host, str) and len(host) <= 253 and
            all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in host.split('.')))


def route_hosts(cfg, name):
    """Keep old single-host inputs while admitting explicit hostname aliases."""
    single, multiple = f'{name}_host', f'{name}_hosts'
    if single in cfg and multiple in cfg:
        raise ValueError('Supply either a single route host or a host list')
    hosts = cfg[multiple] if multiple in cfg else [required(cfg, single)]
    if not isinstance(hosts, list) or not hosts or any(not dns_name(host) for host in hosts):
        raise ValueError('Use literal DNS names for routes')
    if len(set(hosts)) != len(hosts):
        raise ValueError('Route hostnames must be unique')
    return hosts


def backend_url(cfg, name):
    url = required(cfg, f'{name}_url')
    if any(c.isspace() for c in url) or '\\' in url:
        raise ValueError('Use credential-free backend HTTP origins')
    parsed = urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            parsed.path not in ('', '/') or parsed.query or parsed.fragment or
            (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        raise ValueError('Use credential-free backend HTTP origins')
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if not dns_name(parsed.hostname):
            raise ValueError('Use a literal backend address or DNS name') from None
    return url


def ingress(cfg):
    """Reach guest backends; only Node-RED delegates login to forward-auth."""
    if cfg.get('kind') != 'ingress':
        raise ValueError('Ingress settings belong to the ingress guest')
    entrypoint = cfg.get('ingress_entrypoint', 'websecure')
    resolver = cfg.get('ingress_cert_resolver')
    for value in [entrypoint] + ([resolver] if 'ingress_cert_resolver' in cfg else []):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
            raise ValueError('Use literal entrypoint and certificate resolver names')
    tls = {'certResolver': resolver} if resolver else {}
    names = ['homeassistant', 'node_red', 'identity']
    if any(key in cfg for key in ('pgadmin_host', 'pgadmin_hosts', 'pgadmin_url', 'pgadmin_middlewares')):
        names.append('pgadmin')
    routers, services, claimed = {}, {}, set()
    for name in names:
        hosts, url = route_hosts(cfg, name), backend_url(cfg, name)
        if claimed.intersection(hosts):
            raise ValueError('Different applications cannot share a route hostname')
        claimed.update(hosts)
        rule = ' || '.join(f'Host(`{host}`)' for host in hosts)
        if len(hosts) > 1:
            rule = f'({rule})'
        routers[name] = {'rule': rule, 'priority': 10, 'entryPoints': [entrypoint],
                         'tls': dict(tls), 'service': name}
        services[name] = {'loadBalancer': {'servers': [{'url': url}], 'passHostHeader': True}}
    if 'pgadmin' in names:
        middlewares = cfg.get('pgadmin_middlewares', [])
        if (not isinstance(middlewares, list) or any(
                not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+(?:@file)?', value) or
                value in ('authentik', 'authentik@file') for value in middlewares)):
            raise ValueError('pgAdmin uses native OAuth2; supply only its restored file middlewares')
        if middlewares:
            routers['pgadmin']['middlewares'] = list(middlewares)
    routers['node_red']['middlewares'] = ['authentik']
    routers['outpost'] = {'rule': routers['node_red']['rule'] + ' && PathPrefix(`/outpost.goauthentik.io/`)',
                          'priority': 100, 'entryPoints': [entrypoint], 'tls': dict(tls), 'service': 'identity'}
    middleware = {'authentik': foundation.authentik_middleware(cfg['identity_url'])}
    return {'http': {'routers': routers, 'services': services, 'middlewares': middleware}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    documents = {'compose.yml': compose(cfg)}
    if cfg['kind'] == 'pegaprox':
        import pegaprox
        documents['compose-bootstrap.yml'] = pegaprox.bootstrap_compose(cfg)
    if cfg['kind'] == 'ingress' and 'foundation' not in cfg:
        documents['routes.yml'] = ingress(cfg)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, document in documents.items():
        path = args.output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')
    if 'foundation' in cfg or cfg['kind'] == 'monitoring':
        manifest = []
        for artifact in (monitoring.files(cfg) if cfg['kind'] == 'monitoring' else foundation_files(cfg)):
            path = args.output / artifact['path']
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(artifact['content'])
            manifest.append({key: artifact[key] for key in ('path', 'uid', 'gid', 'mode')})
        path = args.output / 'runtime-files.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(manifest, stream)
            stream.write('\n')


if __name__ == '__main__':
    main()
