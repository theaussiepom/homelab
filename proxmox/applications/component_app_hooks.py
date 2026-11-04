"""Closed lifecycle descriptors for three existing owned application helpers.

This module never executes commands or reads configured files. The component
Ansible caller installs the fixed helpers, runs Music/Zigbee validation before
the selected services start, and runs Pi-hole reconciliation after startup. Only
Pi-hole's reported changed=true permits its one selected service to restart.
Zigbee retains the provider's one-coordinator-per-guest capability and the two
fixed settings/identity paths; no coordinator is initialized here.
"""
import json

import dns_records
import music_assistant
import zigbee2mqtt
from component_runtime import _mount_path, _name
from private_io import require

ROOT = '/opt/homelab-app/'
ZIGBEE_DATA = '/srv/homelab/data/zigbee2mqtt'


def _helper(name):
    return {'source': name, 'destination': ROOT + name,
            'uid': 0, 'gid': 0, 'mode': '0700'}


def _data(app, target):
    storage = app.get('storage_paths', {})
    require(set(storage) == {'data'}, 'Bind only the selected owned data role')
    row = storage['data']
    require(row.get('target') == target and row.get('kind') == 'directory'
            and row.get('read_only') is False, 'Preserve the writable owned data directory')
    source = _mount_path(row.get('source'))
    require(source != '/', 'Bind a nonroot owned data directory')
    return source


def _pihole(app, compose_file):
    dns_records.validate(app['settings']['dns_records'])
    compose = _mount_path(compose_file)
    service = _name(app['identity']['services']['pihole'])
    argv = ['python3', ROOT + 'dns_records.py', 'reconcile',
            '--records', ROOT + 'dns-records.json', '--compose', compose]
    if service != 'pihole':
        argv += ['--service', service]
    return {'helpers': [_helper('dns_records.py')], 'pihole_records': {
        'reconcile_argv': argv,
        'restart_argv': ['docker', 'compose', '-f', compose, 'restart', '--no-deps', service]}}


def _music(app, compose_file):
    require(app.get('lifecycle') == 'retained', 'Fresh Music commissioning is not implemented')
    address = music_assistant.address(app['role_addresses']['web'])
    source = str(music_assistant.data_path(_data(app, '/data')))
    argv = ['python3', ROOT + 'music_assistant.py', '--address', address]
    if source != str(music_assistant.DATA):
        argv += ['--data-root', source]
    return {'helpers': [_helper('music_assistant.py')], 'music_state': {'argv': argv}}


def zigbee_argv(app, mode):
    """Use the existing helper's selected-data option with its fixed receipt."""
    require(mode in ('validate', 'health'), 'Select an existing Zigbee helper mode')
    require(app.get('lifecycle') == 'retained', 'Fresh Zigbee commissioning is not implemented')
    source = _data(app, '/app/data')
    argv = ['python3', ROOT + 'zigbee2mqtt.py', mode,
            '--settings', ROOT + 'zigbee-settings.json']
    if source != ZIGBEE_DATA:
        argv += ['--data', source]
    return argv


def _zigbee(app, compose_file):
    settings = zigbee2mqtt.validate(app['settings'])
    return {'helpers': [_helper('zigbee2mqtt.py')], 'zigbee_state': {
        'settings_file': {'path': ROOT + 'zigbee-settings.json',
                          'content': json.dumps(settings) + '\n',
                          'uid': 0, 'gid': 0, 'mode': '0600'},
        'identity_file': ROOT + 'zigbee-network.json',
        'validate_argv': zigbee_argv(app, 'validate'),
        'health_argv': zigbee_argv(app, 'health'),
        'single_coordinator_per_guest': True}}


HANDLERS = {'pihole': _pihole, 'music_assistant': _music, 'zigbee2mqtt': _zigbee}


def descriptors(app, *, compose_file):
    """Return one adapter-owned hook record, without a user-defined argv API."""
    require(isinstance(app, dict) and app.get('adapter') in HANDLERS,
            'Select an existing component application hook')
    return HANDLERS[app['adapter']](app, compose_file)
