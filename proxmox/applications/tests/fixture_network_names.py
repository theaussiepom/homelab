"""Translate only network labels in immutable historical test inputs.

Expected service bytes, identities, storage, credentials and historical files stay
unchanged. This helper is test-only; active source and runtime have no aliases.
"""
import copy


def modernize(value):
    value = copy.deepcopy(value)
    def name(key, suffix):
        return key if key.endswith('_' + suffix) else key + '_' + suffix
    def visit(row, parent=None):
        if isinstance(row, list):
            for item in row: visit(item, parent)
        elif isinstance(row, dict):
            for key in ('role_addresses', 'listeners'):
                if isinstance(row.get(key), dict):
                    kind = 'interface' if key == 'role_addresses' else 'listener'
                    row[key] = {name(k, kind): v for k, v in row[key].items()}
            interfaces = row.get('interfaces')
            if isinstance(interfaces, dict) and interfaces and all(
                    isinstance(v, dict) and ('accepts' in v or set(v) == {'interface'}
                        or 'scope' in v and set(v) <= {'scope', 'network', 'interface'})
                    for v in interfaces.values()):
                row['interfaces'] = {name(k, 'interface'): v for k, v in interfaces.items()}
            endpoints = row.get('endpoints')
            if isinstance(endpoints, dict) and endpoints and all(
                    isinstance(v, dict) and ('listener' in v or 'internal' in v)
                    for v in endpoints.values()):
                row['endpoints'] = {name(k, 'endpoint'): v for k, v in endpoints.items()}
            if 'app' in row and 'endpoint' in row:
                row['endpoint'] = name(row['endpoint'], 'endpoint')
            if 'listener' in row and 'via' in row:
                row['listener'] = name(row['listener'], 'listener')
                row['via'] = name(row['via'], 'interface')
            if 'source_interface' in row:
                row['source_interface'] = name(row['source_interface'], 'interface')
            if 'interface' in row and ('service' in row and 'namespace' in row
                    or row.get('scope') == 'guest-interface' or parent == 'mdns'
                    or 'app' in row):
                row['interface'] = name(row['interface'], 'interface')
            for key, item in row.items(): visit(item, key)
    visit(value)
    return value
