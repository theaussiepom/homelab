"""Order published Authentik calendar releases and bind their official image pins."""
import re

REPOSITORY = 'ghcr.io/goauthentik/server'
TAG = re.compile(r'(20[0-9]{2})\.([1-9]|1[0-2])\.(0|[1-9][0-9]*)')
PIN = re.compile(re.escape(REPOSITORY) + ':' + TAG.pattern + r'@sha256:[0-9a-f]{64}')
# These series predate the recurring release selector and are also used by
# already-sealed deployments. Subsequent series come from upstream releases.
HISTORICAL = ((2025, 4), (2025, 6), (2025, 8), (2025, 10), (2025, 12),
              (2026, 2), (2026, 5), (2026, 8))


def plugin(document):
    """Only this profile owns these upstream coordinates and service roles."""
    if document != {'owner': 'authentik', 'upstream': 'goauthentik/authentik',
                    'image': REPOSITORY, 'roles': ['server', 'worker']}:
        raise ValueError('Invalid Authentik release-series plugin')
    return document


def version(pin):
    match = PIN.fullmatch(pin) if isinstance(pin, str) else None
    if not match:
        raise ValueError('Use a stable official Authentik image pinned by digest')
    return tuple(map(int, match.groups()))


def validate(path):
    if not isinstance(path, list) or len(path) < 2:
        raise ValueError('Include the accepted and target Authentik images')
    versions = [version(pin) for pin in path]
    series = [v[:2] for v in versions]
    for i, (left, right) in enumerate(zip(versions, versions[1:])):
        if right < left or path[i] == path[i+1] or (i and left[:2] == right[:2]):
            raise ValueError('Use increasing Authentik series, with an optional initial patch or digest update')
    if series[0] < HISTORICAL[0] or any(family not in series for family in HISTORICAL
                                        if series[0] <= family <= series[-1]):
        raise ValueError('Include every historical Authentik release series')


def select(source, published, resolve_digest, *, through=None):
    """Select the latest published patch of each series, including the source series."""
    start = version(source)
    ceiling = version(through)[:2] if through else None
    latest = {}
    for tag in published:
        match = TAG.fullmatch(tag)
        if match:
            value = tuple(map(int, match.groups()))
            family = value[:2]
            if family >= start[:2] and (ceiling is None or family <= ceiling):
                latest[family] = max(value, latest.get(family, value))
    if start[:2] not in latest or latest[start[:2]] < start:
        raise ValueError('The upstream release inventory does not cover the accepted source')
    path = [source]
    for _, value in sorted(latest.items()):
        tag = '.'.join(map(str, value))
        pin = f'{REPOSITORY}:{tag}@{resolve_digest(tag)}'
        version(pin)
        if pin != source:
            path.append(pin)
    if len(path) > 1:
        validate(path)
    return path
