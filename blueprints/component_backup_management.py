"""Closed PBS management declaration; compilation never opens credentials."""
import copy

from component_sources import closed, identifier, require
import component_types as types


def source(value):
    closed(value, ('credential', 'datastore_path'))
    require(identifier(value['credential']), 'component.backup-management-credential')
    types.path(value['datastore_path'])
    require(value['datastore_path'] != '/', 'component.backup-datastore-path')


def bind(resolver, value):
    source(value)
    credential = resolver.site['secret_sources'].get(value['credential'])
    require(isinstance(credential, dict) and credential.get('type') == 'environment'
            and credential.get('name') == 'PBS_API_TOKEN'
            and credential.get('workflow_secret', 'PBS_API_TOKEN') == 'PBS_API_TOKEN',
            'component.backup-management-credential')
    return {'schema': 'homelab-pbs-management-v1',
            'credential': copy.deepcopy(credential), 'datastore_path': value['datastore_path']}
