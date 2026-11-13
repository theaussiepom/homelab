"""Independent application ownership identities for component source contracts.

These keys identify profile-owned fragments, not guest layouts. Instance identity
maps supply persistent runtime names; no site allocation belongs in this table.
"""
import re

ADAPTERS = {
    'homeassistant': {'services': ('homeassistant',), 'networks': (), 'native': ()},
    'node_red': {'services': ('node_red',), 'networks': (), 'native': ()},
    'bitwarden': {'services': ('bitwarden',), 'networks': ('default',), 'native': ()},
    'cloudbeaver': {'services': ('cloudbeaver', 'auth_gateway'),
                    'networks': ('database_tools',), 'native': ()},
    'pihole': {'services': ('pihole',), 'networks': (), 'native': ()},
    'unbound': {'services': ('unbound',), 'networks': ('default',), 'native': ()},
    'authentik': {'services': ('server', 'worker', 'redis'),
                  'networks': ('default',), 'native': ()},
    'influxdb': {'services': (), 'networks': (), 'native': ('influxdb',)},
    'traefik': {'services': ('traefik',), 'networks': (), 'native': ()},
    'mariadb': {'services': (), 'networks': (), 'native': ('mariadb',)},
    'zabbix': {'services': ('zabbix_server', 'zabbix_web'),
               'networks': ('default',), 'native': ()},
    'mqtt': {'services': ('mqtt',), 'networks': (), 'native': ()},
    'mqtt_explorer': {'services': ('mqtt_explorer', 'explorer_gateway'),
                      'networks': ('explorer',), 'native': ()},
    'music_assistant': {'services': ('music_assistant',), 'networks': (), 'native': ()},
    'pegaprox': {'services': ('pegaprox',), 'networks': ('default',), 'native': ()},
    'postgresql': {'services': (), 'networks': (), 'native': ('postgresql',)},
    'zigbee2mqtt': {'services': ('zigbee2mqtt',), 'networks': ('default',), 'native': ()},
    'winet': {'services': ('winet',), 'networks': (), 'native': ()},
}

# Closed adapter-owned runtime leaves. Source resolution reserves them before
# rendering; selected input preparation checks actual emitted files against the
# same authority. Neither caller accepts authored filenames or directory mounts.
RUNTIME_FILES = {
    'authentik': {'authentik-secret-key', 'postgresql-password', 'smtp-password'},
    'traefik': {'traefik.yml', 'shared.yml', 'pve-ca.pem', 'cloudflare-dns-token'},
    'cloudbeaver': {'cloudbeaver.conf', 'cloudbeaver.auto.conf', 'cloudbeaver-connections.json',
        'cloudbeaver-permissions.json', 'cloudbeaver-public.json', 'CloudBeaverHealth.java',
        'oauth2-alpha.json', 'oauth2.cfg'},
    'mqtt_explorer': {'explorer-traefik.json', 'explorer-routes.yml', 'mqtt-explorer-public.json',
                      },
    'zabbix': {'database-password', 'proxmox-ca.pem'},
    'pegaprox': {'pegaprox-db-key'}, 'winet': {'winet-options.json'},
    'mqtt': {'mqtt-probe.json'},
}
CUSTODY_ROOTS = {'cloudbeaver':'/var/lib/homelab-db-tools',
                 'mqtt_explorer':'/var/lib/homelab-mqtt-explorer'}
SIDECAR_FILES = {
    'pihole':{'dns-records.json':{'destination':'/opt/homelab-app/dns-records.json',
                                'uid':0,'gid':0,'mode':'0600'}},
    'zigbee2mqtt':{'zigbee-settings.json':{'destination':'/opt/homelab-app/zigbee-settings.json',
                                        'uid':0,'gid':0,'mode':'0600'}},
}


def custody_directory(name, value):
    root=CUSTODY_ROOTS.get(name)
    if not (root is not None and isinstance(value,str) and (value==root or re.fullmatch(
            re.escape(root)+'/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',value))):
        raise ValueError('Use only the selected adapter owned custody directory')
    return value


def runtime_files(app):
    """Return only the selected adapter's finite leaf ownership, without I/O."""
    name = app['adapter']
    adapter(name)
    result = set(RUNTIME_FILES.get(name, set()))
    settings = app.get('settings', {})
    if name == 'authentik' and 'smtp_password' not in app.get('secret_bindings', {}):
        result.discard('smtp-password')
    if name == 'authentik' and 'allowed_callback_additions' in settings:
        result.add('identity-callbacks.json')
    if name == 'cloudbeaver' and settings.get('managed_connections'):
        result.update({'cloudbeaver-admin-connections.json', 'CloudBeaverDatabaseHealth.java'})
        artifact = settings.get('mariadb_jdbc')
        if artifact:
            result.add('mariadb-java-client-' + artifact['version'] + '.jar')
    if name == 'traefik':
        result.update(row['filename'] for row in settings.get('route_ca_files', {}).values())
        if settings.get('cloudflare'):
            result.update({'cloudflare-origin-token', 'cloudflare.go', 'cloudflare-go.mod', 'cloudflare-LICENSE', 'cloudflare-manifest.yml'})
        result.update(row['filename'] for row in settings.get('route_ca_certificates', {}).values())
    if name == 'zabbix' and app.get('authentication_resolved', {}).get('default_login') == 'saml':
        result.add('saml-login.php')
    if name=='mqtt_explorer':
        result.add('mqtt-explorer-profile.json' if 'credential' in settings.get('broker',{})
                   else 'mqtt-explorer-account.json')
    return result


def adapter(name):
    """Return only a supported independent adapter, without a fallback bundle."""
    if not isinstance(name, str) or name not in ADAPTERS:
        raise ValueError('Select a supported independent application adapter')
    return ADAPTERS[name]


def ordered_services(app):
    """Resolve runtime names in explicit owned-role order, including after JSON."""
    roles=adapter(app['adapter'])['services']
    names=app['identity']['services']
    if not (isinstance(names,dict) and set(names)==set(roles)
            and all(isinstance(name,str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',name)
                    for name in names.values()) and len(set(names.values()))==len(names)):
        raise ValueError('Bind the exact adapter-owned service roles and identities')
    return [names[role] for role in roles]
