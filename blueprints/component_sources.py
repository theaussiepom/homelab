"""Confined component definitions and byte-preserved local source evidence.

This module reads source checkouts only. It never reads a configured secret path,
contacts a target, executes a helper or manufactures an admission receipt.
"""
import copy
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat

import authored_config
from component_errors import ComponentError, at

SCHEMA = 'homelab-components-v1'
POLICIES = ('network', 'transport', 'tls', 'middlewares', 'authentication')
LIBRARY_MAPS = ('guest_templates', 'app_profiles', 'software', 'runtime_profiles',
                'health_profiles', 'authentication_profiles', 'monitoring_profiles',
                'assets', 'bundles')
SITE_MAPS = ('contexts', 'networks', 'storage', 'guests', 'apps', 'domains',
             'external_endpoints', 'identity_providers', 'secret_sources', 'accounts',
             'devices', 'evidence', 'connections', 'exposures', 'images', 'host_aliases', 'address_groups')
SITE_DEFINITIONS = {'guests': 'guest', 'apps': 'app'}
KINDS = {'guest_templates': 'guest-template', 'app_profiles': 'app-profile',
         'software': 'software', 'runtime_profiles': 'runtime-profile',
         'health_profiles': 'health-profile', 'authentication_profiles': 'authentication-profile',
         'monitoring_profiles': 'monitoring-profile', 'bundles': 'bundle'}
ERROR = 'Use confined typed component source definitions'


def require(ok, code='component.invalid'):
    if not ok:
        raise ComponentError(code)


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', value) is not None


def closed(value, required=(), optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional),
            'component.fields')
    return value


def named(value):
    require(isinstance(value, dict) and len(value) <= 1024 and all(identifier(key) for key in value))
    return value


class Sources:
    """One source-root authority with a digest pin for every consumed snapshot."""
    def __init__(self, root):
        self.root = Path(root).absolute()
        require(self.root.is_dir() and not self.root.is_symlink())
        self.pins = {}
        self.root_identity = None
        with self.parent('anchor') as directory:
            info = os.fstat(directory)
            self.root_identity = (info.st_dev, info.st_ino)

    @contextmanager
    def parent(self, relative):
        """Walk from / through directory FDs; no checked pathname is reopened.

        A concurrently renamed ancestor cannot redirect a later open. Each
        component is opened relative to the already anchored directory with
        NOFOLLOW; the final file is opened relative to the yielded parent FD.
        """
        relative = self.relative(relative)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open('/', flags)
        try:
            for part in self.root.parts[1:]:
                child = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            info = os.fstat(directory)
            require(self.root_identity is None or self.root_identity == (info.st_dev, info.st_ino))
            for part in relative.parts[:-1]:
                child = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            yield directory
        except OSError:
            raise ComponentError('component.source') from None
        finally:
            os.close(directory)

    def relative(self, relative):
        require(isinstance(relative, str) and relative and len(relative) <= 4096)
        selected = Path(relative)
        require(not selected.is_absolute() and selected.as_posix() == relative
                and all(part not in ('.', '..') for part in selected.parts))
        return selected

    def path(self, relative):
        relative = self.relative(relative)
        path = self.root
        for part in relative.parts:
            path /= part
            require(not path.is_symlink())
        require(path.is_file() and path.resolve().is_relative_to(self.root.resolve()))
        return path

    def raw(self, relative, digest=None):
        selected = self.relative(relative)
        try:
            with self.parent(relative) as directory:
                fd = os.open(selected.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    require(stat.S_ISREG(before.st_mode) and before.st_size <= authored_config.MAX_BYTES)
                    raw = stream.read(authored_config.MAX_BYTES + 1)
                    require(len(raw) <= authored_config.MAX_BYTES
                            and authored_config._identity(before) == authored_config._identity(os.fstat(stream.fileno()))
                            and authored_config._identity(before) == authored_config._identity(
                                os.stat(selected.name, dir_fd=directory, follow_symlinks=False)))
            actual = hashlib.sha256(raw).hexdigest()
            if digest is not None:
                require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) and digest == actual)
            key = selected.as_posix()
            require(key not in self.pins or self.pins[key] == actual)
            self.pins[key] = actual
            return raw
        except OSError:
            raise ComponentError('component.source') from None

    def document(self, relative):
        try:
            path = authored_config.source_path(self.path(relative))
            return authored_config.parse(self.raw(relative), path.suffix)
        except ValueError:
            raise ComponentError('component.source') from None

    def definition(self, value, kind):
        if isinstance(value, dict) and set(value) == {'source'}:
            value = self.document(value['source'])
            require(isinstance(value, dict) and value.get('schema') == SCHEMA and value.get('kind') == kind)
            value = {k: v for k, v in value.items() if k not in ('schema', 'kind')}
        return copy.deepcopy(value)

    def asset(self, value):
        closed(value, ('type', 'source', 'sha256'))
        require(value['type'] == 'raw-utf8')
        try:
            text = self.raw(value['source'], value['sha256']).decode('utf-8')
        except UnicodeError:
            raise ComponentError('component.source') from None
        return {'type': 'raw-utf8', 'text': text, 'sha256': value['sha256']}

    def evidence(self, value):
        if isinstance(value, dict) and value.get('type') == 'raw-utf8':
            return self.asset(value)
        require(isinstance(value, dict) and value.get('type') in
                ('identity-callbacks',))
        if 'document' in value:
            closed(value, ('type', 'document'))
            document = copy.deepcopy(value['document'])
        else:
            closed(value, ('type', 'source', 'sha256'))
            require(isinstance(value['source'], str))
            require(Path(value['source']).suffix == '.json')
            authored_config.source_path(self.path(value['source']))
            document = authored_config.parse(self.raw(value['source'], value['sha256']), '.json')
        require(isinstance(document, list))
        return {'type': value['type'], 'document': document}


def policies(value, sources):
    closed(value, (), POLICIES)
    result = {}
    for kind in POLICIES:
        result[kind] = {key: sources.definition(row, kind + '-policy')
                        for key, row in named(value.get(kind, {})).items()}
    return result


def library(root):
    sources = Sources(root)
    spec = sources.document('stack.json')
    closed(spec, ('schema', 'kind', 'guest_templates', 'app_profiles'),
           tuple(key for key in LIBRARY_MAPS if key not in ('guest_templates', 'app_profiles')) + ('policies',))
    require(spec['schema'] == SCHEMA and spec['kind'] == 'library')
    result = {'schema': SCHEMA, 'kind': 'library'}
    for kind in LIBRARY_MAPS:
        result[kind] = {key: (sources.asset(row) if kind == 'assets'
                              else sources.definition(row, KINDS[kind]))
                        for key, row in named(spec.get(kind, {})).items()}
    result['policies'] = policies(spec.get('policies', {}), sources)
    return result, sources


def site(path):
    path = authored_config.source_path(path)
    sources = Sources(path.parent)
    spec = sources.document(path.name)
    closed(spec, ('schema', 'kind', 'contexts', 'networks', 'storage', 'guests', 'apps'),
           tuple(key for key in SITE_MAPS if key not in ('contexts', 'networks', 'storage', 'guests', 'apps'))
           + ('policies', 'zabbix'))
    require(spec['schema'] == SCHEMA and spec['kind'] == 'site')
    result = {'schema': SCHEMA, 'kind': 'site'}
    for kind in SITE_MAPS:
        result[kind] = {}
        for key, row in named(spec.get(kind, {})).items():
            with at(kind, key):
                result[kind][key] = (sources.definition(row, SITE_DEFINITIONS[kind])
                                     if kind in SITE_DEFINITIONS else copy.deepcopy(row))
    for key, row in result['evidence'].items():
        with at('evidence', key):
            result['evidence'][key] = sources.evidence(row)
    result['policies'] = policies(spec.get('policies', {}), sources)
    if 'zabbix' in spec:
        if spec['zabbix'] is not None:
            closed(spec['zabbix'], ('server',))
            require(identifier(spec['zabbix']['server']))
        result['zabbix'] = copy.deepcopy(spec['zabbix'])
    return result, sources
