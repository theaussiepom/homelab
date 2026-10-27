#!/usr/bin/env python3
"""Read-only admission of the restored Music Assistant listener and providers."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import stat

# This MVP has no storage mounts. Additional providers need an explicit review.
PROVIDERS = {'fanarttv', 'builtin', 'musicbrainz', 'theaudiodb', 'player_group',
             'hass', 'apple_music', 'spotify', 'airplay', 'builtin_player',
             'chromecast', 'lrclib', 'universal_player', 'sync_group', 'sendspin',
             'coverartarchive', 'dlna', 'party'}


def configure_compose(cfg, service):
    selected = cfg['services']['music_assistant']
    bind_address = str(ipaddress.IPv4Address(cfg['music_bind_address']))
    if any(selected.get(key) for key in ('cap_add', 'extra_mounts', 'security_opt',
                                        'privileged', 'user', 'command', 'entrypoint')):
        raise ValueError('Music Assistant retains the image identity without extra mounts or privileges')
    service['volumes'] = [{'type': 'bind',
        'source': f"{cfg.get('data_root', '/srv/homelab/data')}/music-assistant", 'target': '/data',
        'bind': {'create_host_path': False}}]
    # /info is local metadata only: no authentication, provider or player commands.
    service['healthcheck'] = {
        'test': ['CMD', 'python3', '-c',
                 f"import socket, urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({{}})).open('http://{bind_address}:8095/info', timeout=3).close(); socket.create_connection(('{bind_address}', 8097), timeout=3).close()"],
        'interval': '30s', 'timeout': '5s', 'retries': 5, 'start_period': '60s'}


def validate_settings(settings, address):
    ip = ipaddress.IPv4Address(address)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError('Select the assigned player-facing IPv4 address')
    if not settings.get('server_id') or settings.get('onboard_done') is not True:
        raise ValueError('Restore the commissioned server identity and onboarding state')
    core = settings.get('core', {})
    web = core.get('webserver', {}).get('values', {})
    streams = core.get('streams', {}).get('values', {})
    if (web.get('bind_ip') != address or web.get('bind_port', 8095) != 8095
            or streams.get('bind_ip') != address or streams.get('publish_ip') != address
            or streams.get('bind_port', 8097) != 8097):
        raise ValueError('Review the restored UI/stream bind and published player address before startup')
    providers = settings.get('providers')
    if not isinstance(providers, dict) or not providers:
        raise ValueError('Restore the provider configuration before startup')
    if any(value.get('enabled', True) and value.get('domain') not in PROVIDERS
           for value in providers.values()):
        raise ValueError('An additional provider needs capability and reachability review')


def check_directory(root, address):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Use the restored Music Assistant data directory')
    fd = os.open(root / 'settings.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
            raise ValueError('Expected a bounded regular settings file')
        settings = json.loads(stream.read(4 * 1024 * 1024 + 1))
    validate_settings(settings, address)
    for name in ('library.db', 'auth.db'):
        with os.fdopen(os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.read(16) != b'SQLite format 3\x00':
                raise ValueError('Restore both the existing library and authentication databases')
    if (root / 'playlists').is_symlink() or not (root / 'playlists').is_dir():
        raise ValueError('Restore the existing playlists directory')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    args = parser.parse_args()
    try:
        check_directory(Path('/srv/homelab/data/music-assistant'), args.address)
    except (OSError, ValueError, TypeError, AttributeError):
        raise SystemExit('Music Assistant configuration held; review restored state privately') from None
    print('Music Assistant restored listener/provider checks passed; speaker/provider acceptance pending')
