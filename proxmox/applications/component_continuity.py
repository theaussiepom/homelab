"""Private role continuity from validated immutable input proofs, never a store.

Only a selected app phase calls this module. Public configuration and evolving
provider permission metadata are outside its credential material comparison.
"""
import re
from pathlib import Path

import component_input_secrets
import component_payload
import component_generation
from private_io import read_json, require

SCHEMA = 'homelab-component-private-material-v1'
FILE = 'private-material.json'


def document(app, roles):
    value = {'schema': SCHEMA, 'app': app['id'], 'roles': roles}
    validate(app, value)
    return value


def validate(app, value):
    require(isinstance(value, dict) and set(value) == {'schema', 'app', 'roles'}
            and value['schema'] == SCHEMA and value['app'] == app['id']
            and isinstance(value['roles'], dict)
            and set(value['roles']) == set(app.get('input_sources', {})),
            'Preserve the selected app private role proof')
    component_input_secrets.slots(app['adapter'], app.get('input_sources', {}))
    for role, row in value['roles'].items():
        require(isinstance(row, dict) and set(row) == {'source', 'material_sha256'}
                and row['source'] == app['input_sources'][role]
                and isinstance(row['material_sha256'], str)
                and re.fullmatch('[0-9a-f]{64}', row['material_sha256']),
                'Preserve each selected private role material proof')
    return value['roles']


def verify(attempt, app, current):
    """Refuse drift before this app publishes inputs or creates credential records."""
    validate(app, current)
    receipt_path = attempt.receipt
    if not receipt_path.exists() and not receipt_path.is_symlink():
        require(not current['roles'] or app['lifecycle'] == 'fresh',
                'Retained private roles require a genuine prior successful input proof')
        return
    receipt = read_json(receipt_path, private=True)
    operation = Path(receipt['operation']) if isinstance(receipt.get('operation'), str) else None
    if operation is not None and component_generation.component_success(receipt, operation):
        proofs = [row for row in receipt['phase_inputs'].values()
                  if row is not None and row['app'] == app['id']]
        require(len(proofs) <= 1, 'Preserve one prior private role owner per app')
        if not proofs:
            return
        selected = component_payload.AppPayload.load(
            Path(receipt['binding']['app_inputs_directory']) / app['id'], proofs[0])
        old_app = read_json(selected.directory / 'application.json', private=True)
        old = validate(old_app, read_json(selected.directory / FILE, private=True))
    else:
        require(False,'Private continuity requires a genuine prior component success')
    require(set(old) <= set(current['roles']),
            'An ordinary update cannot remove a sealed private role or erase its continuity')
    require(all(row['material_sha256'] == current['roles'][role]['material_sha256']
                for role, row in old.items()),
            'Private role material changed; ordinary deployment cannot rotate credentials')
