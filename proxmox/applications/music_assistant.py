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
             'coverartarchive', 'dlna', 'party', 'wikipedia', 'loudness_analysis',
             'playlist_metadata', 'itunes_artwork', 'radio_playlist', 'recommendations',
             'sendspin_source', 'lastfm_recommendations', 'ambient_sounds'}
DATA = Path('/srv/homelab/data/music-assistant/data')


def data_path(value):
    """Validate a selected data path without probing the controller filesystem."""
    value = os.fspath(value)
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or not value.startswith('/') or value.startswith('//') or value == '/'
            or str(Path(value)) != value or '..' in value.split('/')
            or any(value == prefix or value.startswith(prefix + '/') for prefix in
                   ('/proc', '/sys', '/dev', '/etc', '/root', '/run', '/var/run',
                    '/var/lib/homelab'))):
        raise ValueError('Select a normalized bound Music Assistant data directory')
    return Path(value)


def address(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError('Select the assigned Music Assistant player-facing IPv4 address')
    return str(ip)






def configure_service(service, selected, *, data_root=None, stream_address=None):
    """Apply the owned Music mount/probe to one independent service."""
    selected = address(selected)
    stream = selected if stream_address is None else address(stream_address)
    root = DATA if data_root is None else data_path(data_root)
    service['volumes'] = [{'type': 'bind', 'source': str(root).replace('$', '$$'), 'target': '/data',
                           'bind': {'create_host_path': False}}]
    service['healthcheck'] = {
        'test': ['CMD', 'python3', '-c',
                 "import socket,urllib.request;urllib.request.build_opener(urllib.request.ProxyHandler({})).open("
                 + repr('http://' + selected + ':8095/info')
                 + ",timeout=3).close();socket.create_connection((" + repr(stream)
                 + ",8097),timeout=3).close()"],
        'interval': '30s', 'timeout': '8s', 'retries': 5, 'start_period': '60s'}
    return service


def validate_settings(settings, selected, stream_address=None):
    """Check retained identity, providers and separately selected socket roles."""
    selected = address(selected)
    stream = selected if stream_address is None else address(stream_address)
    if (not isinstance(settings, dict) or not isinstance(settings.get('server_id'), str)
            or not settings['server_id'] or settings.get('onboard_done') is not True):
        raise ValueError('Preserve the commissioned Music Assistant identity and onboarding')
    core = settings.get('core', {})
    web = core.get('webserver', {}).get('values', {})
    streams = core.get('streams', {}).get('values', {})
    if (web.get('bind_ip') != selected or web.get('bind_port', 8095) != 8095
            or streams.get('bind_ip') != stream or streams.get('publish_ip') != stream
            or streams.get('bind_port', 8097) != 8097):
        raise ValueError('Review the retained Music Assistant UI and player listeners before startup')
    providers = settings.get('providers')
    if (not isinstance(providers, dict) or not providers or len(providers) > 128
            or any(not isinstance(value, dict) or value.get('enabled', True)
                   and value.get('domain') not in PROVIDERS for value in providers.values())):
        raise ValueError('Retain only the reviewed existing Music Assistant providers')


def read_file(path, limit, *, directory_fd=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory_fd is None:
        descriptor = os.open(path, flags)
    else:
        if not isinstance(path, str) or Path(path).name != path or path in ('', '.', '..'):
            raise ValueError('Read only a fixed file within the bound Music directory')
        descriptor = os.open(path, flags, dir_fd=directory_fd)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('Use bounded regular retained Music Assistant files')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (any(getattr(after, field) != getattr(info, field) for field in fields)
                or len(raw) != info.st_size):
            raise ValueError('Retained Music Assistant state changed during verification')
    return raw


def check_directory(root, selected, stream_address=None):
    """Read retained settings and database headers without changing state."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Use the separately prepared Music Assistant data directory')
    validate_settings(json.loads(read_file(root / 'settings.json', 4 * 1024 * 1024)), selected, stream_address)
    for name in ('library.db', 'auth.db'):
        # Header only: library/account contents stay inside the owning guest.
        with os.fdopen(os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stream.read(16) != b'SQLite format 3\x00':
                raise ValueError('Preserve both existing Music Assistant SQLite databases')
    if (root / 'playlists').is_symlink() or not (root / 'playlists').is_dir():
        raise ValueError('Preserve the Music Assistant playlists directory')


def open_bound_directory(root):
    """Traverse from the root descriptor; no path component follows a link."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open('/', flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def check_bound_directory(value, selected, stream_address=None):
    """Read only the selected directory, anchored before any private-file read."""
    root = data_path(value)
    descriptor = open_bound_directory(root)
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError('Bound Music Assistant directory changed before verification')

        def same(info):
            return stat.S_ISDIR(info.st_mode) and all(
                getattr(info, key) == getattr(before, key) for key in fields)

        validate_settings(json.loads(read_file('settings.json', 4 * 1024 * 1024,
                                               directory_fd=descriptor)), selected, stream_address)
        for name in ('library.db', 'auth.db'):
            with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=descriptor), 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or stream.read(16) != b'SQLite format 3\x00'):
                    raise ValueError('Preserve both existing Music Assistant SQLite databases')
        playlists = os.open('playlists', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            if not stat.S_ISDIR(os.fstat(playlists).st_mode):
                raise ValueError('Preserve the Music Assistant playlists directory')
        finally:
            os.close(playlists)
        if not same(os.fstat(descriptor)):
            raise ValueError('Bound Music Assistant directory changed during verification')
        repeated = open_bound_directory(root)
        try:
            if not same(os.fstat(repeated)):
                raise ValueError('Bound Music Assistant directory changed during verification')
        finally:
            os.close(repeated)
    finally:
        os.close(descriptor)


def main(argv=None):
    """Validate the declared retained Music directory and report its boundary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--data-root')
    parser.add_argument('--stream-address')
    try:
        args = parser.parse_args(argv)
        options = () if args.stream_address is None else (args.stream_address,)
        if args.data_root is None:
            check_directory(DATA, args.address, *options)
        else:
            check_bound_directory(args.data_root, args.address, *options)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        print('Music Assistant startup held; inspect retained state privately')
        return 1
    print('Music Assistant retained state and listener checks passed; provider/player acceptance remains separate')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
