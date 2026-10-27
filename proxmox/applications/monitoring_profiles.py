"""Closed workload profiles shared by guest CD and Zabbix server CD."""
import argparse
import json
from pathlib import Path
import sys
import ipaddress
from urllib.parse import urlsplit

from foundation_cd import regular

PROFILES = {
    'linux': ('template_os_linux_active.yaml', 'Linux by Zabbix agent active'),
    'docker': ('template_app_docker.yaml', 'HomeLab Docker by active agent 2'),
    'postgresql': ('template_db_postgresql_agent2_active.yaml', 'PostgreSQL by Zabbix agent 2 active'),
    'mysql': ('template_db_mysql_agent2_active.yaml', 'MySQL by Zabbix agent 2 active'),
    'influxdb': ('template_db_influxdb_http.yaml', 'InfluxDB by HTTP'),
}
POSTGRESQL_PLUGIN = {'version': '1:7.0.32-1+debian13',
    'sha256': '5d3d4ef1089c80cbefd52b4d8dc15aa9c4ab77b5678f8bf9952ca65f4c2983a2',
    'url': 'https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-agent2-plugin-postgresql/zabbix-agent2-plugin-postgresql_7.0.32-1%2Bdebian13_amd64.deb'}


def selected(value):
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value) or len(value) != len(set(value)) or not set(value) <= set(PROFILES):
        raise ValueError('Select distinct supported workload profiles')
    return value


def templates(value):
    return [PROFILES[name][1] for name in selected(value)]


def plugin_config(value):
    if not isinstance(value, dict) or not set(value) <= {'docker', 'postgresql', 'mysql'}:
        raise ValueError('Use the closed local monitoring plugin configuration')
    lines = []
    if 'docker' in value:
        if value['docker'] != {'socket_access_approved': True}:
            raise ValueError('Docker socket access needs an explicit guest-scoped decision')
        lines.append('Plugins.Docker.Endpoint=unix:///var/run/docker.sock')
    for name, plugin, port in [('postgresql', 'PostgreSQL', 5432), ('mysql', 'Mysql', 3306)]:
        if name not in value: continue
        config = value[name]
        if set(config) != {'uri', 'password_file'}:
            raise ValueError('Use one file-backed credential for the local monitoring account')
        uri = urlsplit(config['uri'])
        address = ipaddress.ip_address(uri.hostname)
        if (uri.scheme != 'tcp' or uri.username or uri.password or uri.port != port
                or uri.path or uri.query or uri.fragment or not address.is_private
                or address.is_unspecified or address.is_multicast or address.is_link_local):
            raise ValueError('Bind the database plugin to one reviewed local guest address and fixed port')
        if not Path(config['password_file']).is_absolute():
            raise ValueError('Use an absolute protected password file')
        password = regular(Path(config['password_file']), private=True).decode().rstrip('\n')
        if not 32 <= len(password) <= 128 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in password):
            raise ValueError('Use a URL-safe monitoring password of at least 32 characters')
        if name == 'postgresql':
            lines.append('Plugins.PostgreSQL.System.Path=/usr/sbin/zabbix-agent2-plugin/zabbix-agent2-plugin-postgresql')
        prefix = 'Plugins.' + plugin + '.Sessions.homelab.'
        lines.extend([prefix + 'Uri=' + config['uri'], prefix + 'User=zbx_monitor', prefix + 'Password=' + password])
        if name == 'postgresql': lines.append(prefix + 'Database=postgres')
    return '\n'.join(lines) + ('\n' if lines else '')


def host_macros(profiles):
    result = []
    if 'postgresql' in selected(profiles):
        result += [{'macro': '{$PG.CONNSTRING.AGENT2}', 'value': 'homelab'},
                   {'macro': '{$PG.USER}', 'value': ''}, {'macro': '{$PG.PASSWORD}', 'value': ''}]
    if 'mysql' in profiles:
        result += [{'macro': '{$MYSQL.DSN}', 'value': 'homelab'},
                   {'macro': '{$MYSQL.USER}', 'value': ''}, {'macro': '{$MYSQL.PASSWORD}', 'value': ''}]
    return result


def host_profile(value):
    if set(value) != {'profiles', 'settings'}:
        raise ValueError('Use the closed server-side profile selection')
    profiles, settings = selected(value['profiles']), value['settings']
    if not isinstance(settings, dict) or not set(settings) <= {'docker', 'influxdb'} or not set(settings) <= set(profiles):
        raise ValueError('Profile settings must match selected workloads')
    macros = host_macros(profiles)
    if 'docker' in settings:
        if set(settings['docker']) != {'matches', 'not_matches'}:
            raise ValueError('Declare finite discovery filters for permanent and transient containers')
        for key, macro in [('matches', '{$DOCKER.LLD.FILTER.CONTAINER.MATCHES}'), ('not_matches', '{$DOCKER.LLD.FILTER.CONTAINER.NOT_MATCHES}')]:
            text = settings['docker'][key]
            if not isinstance(text, str) or not 1 <= len(text) <= 512 or any(c in text for c in '\r\n\x00'):
                raise ValueError('Invalid container discovery filter')
            macros.append({'macro': macro, 'value': text})
    if 'influxdb' in profiles:
        c = settings.get('influxdb', {})
        if set(c) != {'url', 'token_file'}:
            raise ValueError('InfluxDB needs an approved HTTPS route and file-backed API token')
        url = urlsplit(c['url'])
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
            raise ValueError('Use a trusted HTTPS origin for InfluxDB monitoring')
        if not Path(c['token_file']).is_absolute():
            raise ValueError('Use an absolute protected token file')
        token = regular(Path(c['token_file']), private=True).decode().strip()
        if not 16 <= len(token) <= 512 or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise ValueError('Invalid private InfluxDB monitoring token')
        macros += [{'macro': '{$INFLUXDB.URL}', 'value': c['url'].rstrip('/')},
                   {'macro': '{$INFLUXDB.API.TOKEN}', 'value': token, 'type': 'secret'}]
    return {'link_templates': templates(profiles), 'profile_macros': macros}


if __name__ == '__main__':
    # Credential-bearing renderers are library functions used by no_log filters.
    # The public CLI exposes only this nonsecret catalog.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps({name: {'file': value[0], 'template': value[1]} for name, value in PROFILES.items()}))
