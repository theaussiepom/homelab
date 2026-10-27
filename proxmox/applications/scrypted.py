#!/usr/bin/env python3
"""Validate a Scrypted preparation packet locally; emit no executable stack.

This is a review helper for the existing application installer, not a deployment
entry point. Decoder and recording-source admission require a later source PR.
"""
import argparse
import copy
import json
from pathlib import Path
import re

from site_config import read

SCHEMA = 'homelab-scrypted-preparation-v1'
PRESERVE = {
    'server_volume_target': '/server/volume',
    'nvr_target': '/nvr',
    'numeric_user': '0:0',
    'configuration': ['plugins', 'cameras', 'nvr', 'credentials', 'recording-paths'],
}
INPUTS = {'image_archive_sha256', 'frozen_capture_sha256', 'nvr_mount_contract',
          'guest_profile', 'trust_reference', 'recovery_reference', 'exclusive_writer_evidence'}
HOLDS = {
    'decoder_gpu': 'No verified decoder path that avoids automatic NVIDIA/Vulkan enumeration.',
    'nvr_source_guard': 'Exact recording source, absent/wrong-source refusal and path/metadata checks required.',
    'capture': 'Frozen configuration, exact image archive and recording preservation receipts required.',
    'native_acceptance': 'Existing synthetic LXC evidence is version-specific; target and service acceptance remain open.',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def number(value, name, maximum):
    require(type(value) is int and 0 < value <= maximum, f'{name} must be a bounded positive integer')
    return value


def review(cfg):
    require(isinstance(cfg, dict) and set(cfg) == {'schema', 'enabled', 'selected_image',
            'decoder_decision', 'preserve', 'limits', 'inputs'}, 'Unknown or missing preparation field')
    require(cfg['schema'] == SCHEMA and cfg['enabled'] is False, 'Scrypted preparation must stay disabled')
    require(cfg['decoder_decision'] == 'unresolved', 'Decoder selection requires a separately reviewed implementation')
    require(isinstance(cfg['selected_image'], str) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', cfg['selected_image']) is not None,
            'Preserve the selected local image ID; a verified archive is still required')
    require(cfg['preserve'] == PRESERVE, 'Preserve existing user, configuration and container path semantics')
    require(isinstance(cfg['inputs'], dict) and set(cfg['inputs']) == INPUTS,
            'List every unresolved admission input')
    require(all(value is None or isinstance(value, str) and 0 < len(value) <= 1024
                and not any(c in value for c in '\r\n\x00') for value in cfg['inputs'].values()),
            'Inputs are null or private receipt references, never embedded configuration')
    limits = cfg['limits']
    require(isinstance(limits, dict) and set(limits) == {'guest', 'container', 'logs'}, 'Supply all resource limits')
    for scope, fields in [('guest', {'cpus', 'memory_mib'}),
                          ('container', {'cpus', 'memory_mib', 'pids'}),
                          ('logs', {'max_size_mib', 'max_files'})]:
        require(isinstance(limits[scope], dict) and set(limits[scope]) == fields, 'Unknown resource limit')
    guest, container, logs = (limits[key] for key in ('guest', 'container', 'logs'))
    number(guest['cpus'], 'guest CPU', 64)
    number(guest['memory_mib'], 'guest memory', 65536)
    number(container['cpus'], 'container CPU', guest['cpus'])
    number(container['memory_mib'], 'container memory', guest['memory_mib'])
    require(container['memory_mib'] + 1024 <= guest['memory_mib'], 'Leave 1024 MiB outside the container')
    number(container['pids'], 'container PIDs', 4096)
    number(logs['max_size_mib'], 'log size', 100)
    number(logs['max_files'], 'log count', 10)
    return {'schema': SCHEMA, 'deployable': False, 'selected_image': cfg['selected_image'],
            'preserve': copy.deepcopy(PRESERVE), 'limits': copy.deepcopy(limits),
            'holds': dict(HOLDS), 'missing_inputs': sorted(key for key, value in cfg['inputs'].items() if value is None),
            'execution': 'No Compose, guest profile, device mapping, probe, start or health check is emitted.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    # Deliberately omit receipt values and any runtime configuration from stdout.
    print(json.dumps(review(read(args.config)), indent=2))


if __name__ == '__main__':
    main()
