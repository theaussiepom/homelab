"""Disposable component deployment processes; only guest executors are synthetic."""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

F = Path(os.environ.get('HOMELAB_FRAMEWORK', Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(F / 'proxmox/applications'), str(Path(__file__).parent),
                str(F / 'proxmox/applications/tests')]
import component_inputs as inputs
import deploy
import private_io as io
import component_process_fixtures as fixtures


def checkpoint(name):
    print(name, flush=True)
    if sys.stdin.readline() != 'continue\n':
        raise RuntimeError('Fixture checkpoint was not released')


def run(root, mode, phase, pause, run_id):
    os.environ.update(GITHUB_RUN_ID=run_id, GITHUB_RUN_ATTEMPT='1', GITHUB_RUN_NUMBER=run_id,
        GITHUB_REPOSITORY='example/private-site',
        HOMELAB_DEPLOYMENT_WORKFLOW='example/private-site/.github/workflows/deploy.yml@refs/heads/main')
    if mode == 'prepare':
        original_mkdir, original_write = inputs.os.mkdir, inputs.write_new
        def mkdir(path, *args, **kwargs):
            if str(path) == 'a' * 64 and pause == 'create': checkpoint('create-ready')
            return original_mkdir(path, *args, **kwargs)
        def write(path, value, **kwargs):
            original_write(path, value, **kwargs)
            if str(path) == 'site.json' and pause == 'partial': checkpoint('input-partial')
        with patch.object(inputs.os, 'mkdir', side_effect=mkdir), \
             patch.object(inputs, 'write_new', side_effect=write):
            inputs.prepare(root / 'packet.json', root / 'inputs', create=True)
    else:
        def operation(*args, **kwargs):
            with io.private_writer(root / 'guest-operations', append=True) as stream:
                stream.write((phase + '\n').encode())
            if pause == 'operation': checkpoint('operation-complete')
            return {'status': 'passed', 'created': False, 'changed': False,
                    'state_sha256': io.sha(root / 'state/808/terraform.tfstate')}
        def prepare_app(cfg, app, environment, *, attempt):
            if app != 'database': raise AssertionError('Unexpected app input owner')
            return fixtures.payload(cfg)
        with patch('deployment_inputs.source_hash', return_value='b' * 64), \
             patch.object(deploy, 'bootstrap_closed'), \
             patch.object(deploy.proxmox_guest, 'infrastructure', side_effect=operation), \
             patch('component_ansible.run_phase', side_effect=operation), \
             patch('component_prepare.prepare', side_effect=prepare_app):
            deploy.run(phase, root / 'packet.json', inputs=root / 'inputs', environment={})
    print(json.dumps({'status': 'passed'}), flush=True)


if __name__ == '__main__':
    try:
        run(Path(sys.argv[1]).resolve(), *sys.argv[2:])
    except Exception as error:
        print(type(error).__name__, flush=True)
        raise SystemExit(2) from None
