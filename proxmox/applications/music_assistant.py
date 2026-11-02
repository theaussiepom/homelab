"""Verify retained Music Assistant state and its selected listener; never rewrite it."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import stat

PROVIDERS = {'fanarttv', 'builtin', 'musicbrainz', 'theaudiodb', 'player_group',
             'hass', 'apple_music', 'spotify', 'airplay', 'builtin_player',
             'chromecast', 'lrclib', 'universal_player', 'sync_group', 'sendspin',
             'coverartarchive', 'dlna', 'party'}
DATA = Path('/srv/homelab/data/music-assistant/data')


def address(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError('Select the assigned Music Assistant player-facing IPv4 address')
    return str(ip)


def validate(cfg):
    if cfg.get('kind') != 'music':
        if 'music_bind_address' in cfg:
            raise ValueError('Music listener selection belongs to its dedicated guest')
        return None
    selected = cfg['services']['music_assistant']
    if (set(selected.get('environment', {})) - {'TZ'}
            or any(key in selected for key in ('cap_add', 'extra_mounts', 'security_opt',
                'privileged', 'user', 'command', 'entrypoint', 'devices', 'ports', 'network_mode'))):
        raise ValueError('Retain the upstream Music Assistant identity without privilege or mount overrides')
    return address(cfg['music_bind_address'])


def configure(cfg, document):
    selected = validate(cfg)
    if selected is not None:
        service = document['services']['music_assistant']
        service['volumes'] = [{'type': 'bind', 'source': str(DATA), 'target': '/data',
                               'bind': {'create_host_path': False}}]
        service['healthcheck'] = {
            'test': ['CMD', 'python3', '-c',
                     "import socket,urllib.request;urllib.request.build_opener(urllib.request.ProxyHandler({})).open("
                     + repr('http://' + selected + ':8095/info')
                     + ",timeout=3).close();socket.create_connection((" + repr(selected)
                     + ",8097),timeout=3).close()"],
            'interval': '30s', 'timeout': '8s', 'retries': 5, 'start_period': '60s'}
    return document


def validate_settings(settings, selected):
    selected = address(selected)
    if (not isinstance(settings, dict) or not isinstance(settings.get('server_id'), str)
            or not settings['server_id'] or settings.get('onboard_done') is not True):
        raise ValueError('Preserve the commissioned Music Assistant identity and onboarding')
    core = settings.get('core', {})
    web = core.get('webserver', {}).get('values', {})
    streams = core.get('streams', {}).get('values', {})
    if (web.get('bind_ip') != selected or web.get('bind_port', 8095) != 8095
            or streams.get('bind_ip') != selected or streams.get('publish_ip') != selected
            or streams.get('bind_port', 8097) != 8097):
        raise ValueError('Review the retained Music Assistant UI and player listeners before startup')
    providers = settings.get('providers')
    if (not isinstance(providers, dict) or not providers or len(providers) > 128
            or any(not isinstance(value, dict) or value.get('enabled', True)
                   and value.get('domain') not in PROVIDERS for value in providers.values())):
        raise ValueError('Retain only the reviewed existing Music Assistant providers')


def read_file(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('Use bounded regular retained Music Assistant files')
        raw = stream.read(limit + 1)
        if os.fstat(stream.fileno()) != info or len(raw) != info.st_size:
            raise ValueError('Retained Music Assistant state changed during verification')
    return raw


def check_directory(root, selected):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Use the separately prepared Music Assistant data directory')
    validate_settings(json.loads(read_file(root / 'settings.json', 4 * 1024 * 1024)), selected)
    for name in ('library.db', 'auth.db'):
        # Header only: library/account contents stay inside the owning guest.
        with os.fdopen(os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stream.read(16) != b'SQLite format 3\x00':
                raise ValueError('Preserve both existing Music Assistant SQLite databases')
    if (root / 'playlists').is_symlink() or not (root / 'playlists').is_dir():
        raise ValueError('Preserve the Music Assistant playlists directory')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    try:
        check_directory(DATA, parser.parse_args(argv).address)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        print('Music Assistant startup held; inspect retained state privately')
        return 1
    print('Music Assistant retained state and listener checks passed; provider/player acceptance remains separate')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
