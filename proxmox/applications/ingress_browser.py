"""Closed Influx browser policy for the existing Traefik file provider.

This module renders nonsecret objects only. Network membership, restored SSO
provider policy and authority to install them remain separate inputs.
"""
import copy
import ipaddress
import json
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

SCHEMA = 'homelab-influx-browser-v1'
EVIDENCE_ROOT = PurePosixPath('/var/lib/homelab-applications')
PRIVATE = tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
AUTH_HEADERS = ['X-authentik-' + name for name in (
    'username', 'groups', 'entitlements', 'email', 'name', 'uid', 'jwt',
    'meta-jwks', 'meta-outpost', 'meta-provider', 'meta-app', 'meta-version')]


def require(value, message):
    if not value:
        raise ValueError(message)


def dns(value):
    return (isinstance(value, str) and 3 <= len(value) <= 253 and '.' in value and
            all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', n) for n in value.split('.')))


def address(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError('Select a literal private backend address') from None
    require(str(ip) == value and any(ip in n for n in PRIVATE), 'Select a literal private backend address')
    return ip


def origin(value, port):
    require(isinstance(value, str) and not any(c.isspace() for c in value) and '\\' not in value,
            'Select a credential-free HTTP backend origin')
    parsed = urlsplit(value)
    require(parsed.scheme == 'http' and parsed.username is None and parsed.password is None
            and parsed.path == '' and not parsed.query and not parsed.fragment and parsed.port == port,
            'Select a credential-free HTTP backend origin on the declared port')
    address(parsed.hostname)
    return parsed


def validate(value):
    require(isinstance(value, dict) and set(value) == {
        'schema', 'host', 'backend', 'authentik', 'issuer', 'proxy_address', 'frontend_address', 'source_cidrs',
        'header_domain', 'cors_allow_origin'}
        and value['schema'] == SCHEMA, 'Use the closed Influx browser policy')
    require(dns(value['host']) and dns(value['header_domain']), 'Select literal browser and header DNS names')
    require(value['cors_allow_origin'] in ('*', 'https://' + value['host']),
            'Select the same browser origin or the explicitly reviewed historical wildcard')
    backend = origin(value['backend'], 8086)
    origin(value['authentik'], 9000)
    proxy = address(value['proxy_address'])
    address(value['frontend_address'])
    require(proxy != address(backend.hostname) and proxy in ipaddress.IPv4Network(backend.hostname + '/24', strict=False),
            'The proxy must be a distinct admitted client on the Influx private subnet')
    issuer = urlsplit(value['issuer'])
    require(issuer.scheme == 'https' and dns(issuer.hostname) and issuer.username is None
            and issuer.password is None and issuer.port is None and issuer.path == ''
            and not issuer.query and not issuer.fragment and value['issuer'] == 'https://' + issuer.hostname
            and issuer.hostname != value['host'], 'Select the existing distinct HTTPS issuer origin')
    cidrs = value['source_cidrs']
    require(isinstance(cidrs, list) and 1 <= len(cidrs) <= 16, 'Declare a finite browser-source allowlist')
    networks = []
    for cidr in cidrs:
        require(isinstance(cidr, str), 'Use canonical private browser CIDRs')
        net = ipaddress.IPv4Network(cidr, strict=True)
        require(str(net) == cidr and any(net.subnet_of(n) for n in PRIVATE) and net not in networks,
                'Use unique canonical private browser CIDRs')
        networks.append(net)
    return value


def objects(settings):
    value = validate(settings)
    rule = f"Host(`{value['host']}`)"
    common = {'entryPoints': ['websecure'], 'tls': {'certResolver': 'letsencrypt'}}
    return {'http': {
        'routers': {
            'influx-browser': dict(copy.deepcopy(common), rule=rule, priority=10,
                                   service='influx-private', middlewares=['influx-local', 'influx-authentik', 'influx-security']),
            'influx-outpost': dict(copy.deepcopy(common), rule=rule + ' && PathPrefix(`/outpost.goauthentik.io/`)',
                                   priority=100, service='influx-identity', middlewares=['influx-local', 'influx-security'])},
        'services': {name: {'loadBalancer': {'servers': [{'url': url}], 'passHostHeader': True}}
                     for name, url in [('influx-private', value['backend']), ('influx-identity', value['authentik'])]},
        'middlewares': {
            # Direct internal browser access: the socket peer is authoritative.
            # The retired Cloudflare normalization plugin is not installed here.
            'influx-local': {'ipAllowList': {'sourceRange': list(value['source_cidrs'])}},
            'influx-authentik': {'forwardAuth': {
                'address': value['authentik'] + '/outpost.goauthentik.io/auth/traefik',
                'trustForwardHeader': True, 'authResponseHeaders': list(AUTH_HEADERS)}},
            'influx-security': {'headers': {
                'customResponseHeaders': {'Server': value['header_domain'], 'X-Powered-By': value['header_domain']},
                'accessControlAllowMethods': ['GET', 'POST'], 'accessControlMaxAge': 100,
                'accessControlAllowOriginList': [value['cors_allow_origin']], 'addVaryHeader': True,
                'contentSecurityPolicy': "child-src 'self'; frame-ancestors 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
                'contentTypeNosniff': True, 'referrerPolicy': 'origin-when-cross-origin',
                'stsSeconds': 63072000, 'stsIncludeSubdomains': True, 'stsPreload': True,
                'forceSTSHeader': True}}}}}


def merge(original, settings):
    """Add only reserved objects; existing definitions and collisions are holds."""
    validate(settings)
    require(isinstance(original, dict), 'Expected the existing dynamic configuration')
    result = copy.deepcopy(original)
    for router in result.get('tcp', {}).get('routers', {}).values():
        if 'websecure' in router.get('entryPoints', ['websecure']):
            rule = router.get('rule', '')
            require(re.fullmatch(r'HostSNI\(`[a-z0-9.-]+`\)', rule) and settings['host'] not in rule,
                    'An existing TLS router may capture the browser host; review its exact scope')
    http = result.setdefault('http', {})
    require(isinstance(http, dict), 'Expected an HTTP configuration object')
    for router in http.get('routers', {}).values():
        rule = router.get('rule', '')
        require(re.fullmatch(r'Host\(`[a-z0-9.-]+`\)', rule) and settings['host'] not in rule,
                'An existing router claims or may capture the browser host; review its exact scope')
    for section, values in objects(settings)['http'].items():
        destination = http.setdefault(section, {})
        require(isinstance(destination, dict) and not set(destination).intersection(values),
                'A reserved Influx object already exists; preserve it for review')
        destination.update(values)
    return result


def candidate(original, settings):
    return (json.dumps(merge(json.loads(original), settings), indent=2) + '\n').encode()


def packet(value):
    """Bind one exact route installation; absence of a packet grants no action."""
    fields = {'schema', 'revision', 'vmid', 'plan_sha256', 'state_sha256', 'foundation_complete_sha256',
              'compose_sha256', 'runtime_sha256', 'shared_before_sha256', 'shared_after_sha256',
              'image', 'route', 'network_evidence', 'policy_evidence', 'startup'}
    require(isinstance(value, dict) and set(value) == fields
            and value['schema'] == 'homelab-ingress-browser-update-v1', 'Use the closed route maintenance packet')
    require(type(value['vmid']) is int and value['vmid'] >= 100 and value['vmid'] not in {900,4914,4915,4920},
            'Select the commissioned ingress guest')
    require(isinstance(value['revision'], str) and re.fullmatch('[0-9a-f]{40}', value['revision'])
            and isinstance(value['image'], str) and re.fullmatch(r'traefik@sha256:[0-9a-f]{64}', value['image']),
            'Bind immutable maintenance source and unchanged image')
    for key in fields:
        if key.endswith('_sha256'):
            require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{64}', value[key]), 'Bind every exact file digest')
    require(value['shared_before_sha256'] != value['shared_after_sha256'], 'Select an actual route addition')
    validate(value['route'])
    startup = value['startup']
    require(isinstance(startup, dict) and set(startup) == {'interfaces', 'gate_sha256',
            'docker_dependency_sha256', 'routing_unit_sha256', 'routing_dependency_sha256'}
            and startup['interfaces'] == ['eth0','eth1','eth2','eth3']
            and all(isinstance(startup[k],str) and re.fullmatch('[0-9a-f]{64}',startup[k])
                    for k in startup if k != 'interfaces'), 'Bind the reviewed permanent four-interface startup files')
    for key in ('network_evidence', 'policy_evidence'):
        row = value[key]
        require(isinstance(row, dict) and set(row) == {'path', 'sha256'} and isinstance(row['path'], str)
                and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                'Bind the separately admitted network and access evidence')
        path = PurePosixPath(row['path'])
        require(path.is_absolute() and '..' not in path.parts
                and path.is_relative_to(EVIDENCE_ROOT / str(value['vmid']))
                and len(path.parts) > len((EVIDENCE_ROOT / str(value['vmid'])).parts) + 1,
                'Prerequisite evidence belongs to this ingress state')
    return value


def admission(settings, network, policy):
    """Check the exact completed network and separately reviewed restored SSO."""
    packet(settings)
    require(isinstance(network, dict) and network.get('schema') == 'homelab-database-network-overlay-v1'
            and network.get('status') == 'network_overlay_verified' and network.get('vmid') == settings['vmid']
            and network.get('state_sha256') == settings['state_sha256'], 'Use the completed current ingress network overlay')
    checks = {'provider_host_confirmed', 'outpost_membership_confirmed', 'access_policy_confirmed',
              'issuer_alignment_confirmed', 'direct_peer_allowlist_approved'}
    require(isinstance(policy, dict) and set(policy) == checks | {
                'schema', 'vmid', 'route_sha256', 'cors_allow_origin', 'cors_wildcard_approved'}
            and policy['schema'] == 'homelab-influx-browser-policy-evidence-v1'
            and policy['vmid'] == settings['vmid'] and all(policy[name] is True for name in checks),
            'Restored SSO and the explicit local access policy need their separate exact review')
    require(policy['cors_allow_origin'] == settings['route']['cors_allow_origin']
            and policy['cors_wildcard_approved'] is (policy['cors_allow_origin'] == '*'),
            'The exact wildcard CORS value needs explicit access-policy approval')
    import hashlib
    require(policy['route_sha256'] == hashlib.sha256(
        (json.dumps(settings['route'], sort_keys=True, indent=2) + '\n').encode()).hexdigest(),
        'Restored SSO evidence belongs to different browser settings')
