"""Stable runtime-file ownership independent of labels, layout and lifecycle."""
from pathlib import PurePosixPath
import copy
import re

from component_sources import require
from component_adapters import (RUNTIME_FILES as FILES, runtime_files,
                                CUSTODY_ROOTS, custody_directory)
from component_adapters import SIDECAR_FILES

ROOT = '/opt/homelab-app/runtime'


def directory(value):
    require(isinstance(value, str) and (value == ROOT or
            re.fullmatch(re.escape(ROOT) + '/[a-z0-9_-]+(?:/[a-z0-9_-]+)*', value)),
            'component.runtime-directory')
    return value


def claims(value):
    """Reject leaf collisions and directory binds exposing a peer's inputs.

    Owners provide paths from their fixed adapter implementation, never a user
    filename override. A retained shared directory is not itself a conflict:
    every private leaf still has one logical application owner, and mounting a
    whole directory cannot grant access to another app's private leaves.
    """
    leaves = []
    for row in value:
        root = PurePosixPath(directory(row['directory']))
        for name in row['files']:
            require(isinstance(name, str) and PurePosixPath(name).name == name
                    and name not in ('.', '..'), 'component.runtime-file')
            path = root / name
            require(all((row['guest'], path) != (old['guest'], oldpath) or row['app'] == old['app']
                        for old, oldpath in leaves), 'component.runtime-file-conflict')
            leaves.append((row, path))
    for row in value:
        for raw in row.get('directory_mounts', []):
            root = PurePosixPath(directory(raw))
            require(all(row['guest'] != old['guest'] or row['app'] == old['app'] or
                        not (path == root or root in path.parents)
                        for old, path in leaves), 'component.runtime-visibility')


def bind(resolver):
    ownership = []
    custody=[]
    sidecars=[]
    for app_id, app in resolver.apps.items():
        identity = app['identity']
        fixed=SIDECAR_FILES.get(app['adapter'],{})
        for row in fixed.values():
            require((app['guest'],row['destination']) not in sidecars,'component.sidecar-file-conflict')
            sidecars.append((app['guest'],row['destination']))
        if fixed:app['sidecar_files']=copy.deepcopy(fixed)
        if app['adapter'] in CUSTODY_ROOTS:
            require(app['lifecycle']!='retained' or 'custody_directory' in identity,
                    'component.custody-directory-required')
            try:
                selected=custody_directory(app['adapter'],identity.get('custody_directory',
                    CUSTODY_ROOTS[app['adapter']]+'/'+app_id))
            except ValueError:
                require(False,'component.custody-directory')
            require((app['guest'],selected) not in custody,'component.custody-directory-conflict')
            custody.append((app['guest'],selected));identity['custody_directory']=selected
        else:
            require('custody_directory' not in identity,'component.custody-directory-unused')
        files = runtime_files(app)
        if not files:
            require('runtime_directory' not in identity, 'component.runtime-directory-unused')
            continue
        if app['lifecycle'] == 'retained':
            require('runtime_directory' in identity, 'component.runtime-directory-required')
        root = directory(identity.get('runtime_directory', ROOT + '/' + app_id))
        identity['runtime_directory'] = root
        row = {'app': app_id, 'guest': app['guest'], 'directory': root, 'files': sorted(files),
               'directory_mounts': []}
        ownership.append(row)
        app['runtime_files'] = row
    claims(ownership)
