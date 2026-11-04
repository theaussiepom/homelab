"""Read bounded authored JSON/YAML without changing runtime JSON contracts."""
import json
import math
import os
from pathlib import Path
import re
import stat

import yaml

# Current 17 authored files: <= 56,072 bytes, depth 9, 923 values. These
# limits leave room for larger sites while bounding parser work and recursion.
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000
SUFFIXES = ('.yaml', '.yml', '.json')
ERROR = 'Use bounded unambiguous JSON-compatible authored configuration'


def require(ok):
    if not ok:
        raise ValueError(ERROR)


def source_path(path):
    """Use the exact named file; never redirect an absent explicit filename."""
    path = Path(path)
    require(path.suffix in SUFFIXES)
    siblings = [path.with_suffix(suffix) for suffix in SUFFIXES]
    present = [p for p in siblings if p.exists() or p.is_symlink()]
    require(present == [path])
    require(stat.S_ISREG(path.lstat().st_mode))
    return path


def _logical(root, stem):
    paths = [Path(root) / (stem + suffix) for suffix in SUFFIXES]
    present = [p for p in paths if p.exists() or p.is_symlink()]
    require(len(present) == 1)
    return source_path(present[0])


def site_path(root):
    return _logical(root, 'site')




class Loader(yaml.SafeLoader):
    """JSON scalar resolution, with no tags, references or merge semantics."""
    yaml_implicit_resolvers = {}

    def __init__(self, stream):
        super().__init__(stream)
        self.nodes = self.depth = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        require(not isinstance(event, yaml.AliasEvent)
                and getattr(event, 'anchor', None) is None
                and getattr(event, 'tag', None) is None)
        self.nodes += 1
        self.depth += 1
        require(self.nodes <= MAX_NODES and self.depth <= MAX_DEPTH)
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            require(key.tag == 'tag:yaml.org,2002:str')
            name = self.construct_object(key, deep=deep)
            require(not (name == '<<' and key.style is None) and name not in result)
            result[name] = self.construct_object(value, deep=deep)
        return result


Loader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$'), list('tf'))
Loader.add_implicit_resolver('tag:yaml.org,2002:null', re.compile(r'^(?:null)?$'), ['n', ''])
Loader.add_implicit_resolver('tag:yaml.org,2002:int', re.compile(r'^-?(?:0|[1-9][0-9]*)$'), list('-0123456789'))
Loader.add_implicit_resolver('tag:yaml.org,2002:float', re.compile(r'^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)|[+-]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$'), list('-+0123456789.'))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _shape(value, depth=1, count=None):
    count = [0] if count is None else count
    count[0] += 1
    require(depth <= MAX_DEPTH and count[0] <= MAX_NODES)
    require(type(value) in (dict, list, str, int, float, bool, type(None)))
    if isinstance(value, float):
        require(math.isfinite(value))
    if isinstance(value, dict):
        require(all(isinstance(key, str) for key in value))
        children = value.values()
    else:
        children = value if isinstance(value, list) else ()
    for child in children:
        _shape(child, depth + 1, count)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parse(raw, suffix):
    """Parse a previously bounded source snapshot with the same safe reader."""
    try:
        require(isinstance(raw, bytes) and len(raw) <= MAX_BYTES and suffix in SUFFIXES)
        text = raw.decode('utf-8')
        value = (json.loads(text, object_pairs_hook=_unique, parse_constant=lambda _: require(False))
                 if suffix == '.json' else yaml.load(text, Loader=Loader))
        _shape(value)
        return value
    except (ValueError, RecursionError, yaml.YAMLError):
        raise ValueError(ERROR) from None


def read(path):
    """Return JSON-compatible values; never expose parser/source diagnostics."""
    try:
        path = source_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES)
            raw = stream.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES and _identity(os.fstat(stream.fileno())) == _identity(before)
                    and _identity(path.lstat()) == _identity(before))
        return parse(raw, path.suffix)
    except (OSError, ValueError, RecursionError, yaml.YAMLError):
        raise ValueError(ERROR) from None
