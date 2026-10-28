#!/usr/bin/env python3
"""Run clean-install metadata guards in a disposable tools container only."""
import json
import os
from pathlib import Path
import shutil
import secrets
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1]


def main():
    assert os.getuid() == 0 and Path('/.dockerenv').exists()
    assert not Path('/srv/homelab').exists() and not Path('/opt/homelab-app').exists()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(SOURCE / 'ansible', root / 'ansible')
        shutil.copyfile(SOURCE / 'pegaprox_setup.py', root / 'pegaprox_setup.py')
        key = root / 'key'; key.write_text('synthetic-fixture-key'); key.chmod(0o600)
        play = root / 'ansible/fixture.yml'
        play.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False,
            'vars': {'app': {'clean_install_confirmed': True, 'pegaprox': {'key_source': str(key)}}},
            'tasks': [{'ansible.builtin.import_tasks': 'tasks/pegaprox.yml'}]}]))
        Path('/opt/homelab-app').mkdir(mode=0o700)
        command = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(play)]
        env = dict(os.environ, ANSIBLE_LOCAL_TEMP='/tmp/ansible-local')

        def execute(success):
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
            if (result.returncode == 0) != success:
                raise RuntimeError('Unexpected Ansible fixture result')

        execute(True)
        runtime = Path('/opt/homelab-app/runtime/pegaprox-db-key')
        directory = Path('/srv/homelab/data/pegaprox/config')
        assert (runtime.stat().st_uid, runtime.stat().st_gid, runtime.stat().st_mode & 0o777) == (999, 999, 0o600)
        assert (directory.stat().st_uid, directory.stat().st_gid, directory.stat().st_mode & 0o777) == (999, 999, 0o700)
        original, stamp = runtime.read_bytes(), runtime.stat().st_mtime_ns
        execute(True)
        assert runtime.read_bytes() == original and runtime.stat().st_mtime_ns == stamp
        runtime.write_text('synthetic-drift')
        execute(False)
        assert runtime.read_text() == 'synthetic-drift'
        runtime.write_bytes(original)
        existing = directory / 'existing-state'; existing.write_text('synthetic-state')
        execute(False)
        assert existing.read_text() == 'synthetic-state' and runtime.read_bytes() == original
        # Exercise the actual Ansible always block with a local stand-in for the
        # Docker/API helper. The real image/API is covered separately.
        receipt = root / 'temporary-path'
        published = root / 'published'
        docker = root / 'docker'
        docker.write_text('#!/bin/sh\nprintf published > ' + str(published) + '\n')
        docker.chmod(0o700)
        helper = Path('/opt/homelab-app/pegaprox-setup.py')
        helper.write_text("import pathlib,sys,stat; sys.exit(0) if sys.argv[1]=='verify' else None; p=pathlib.Path(sys.argv[sys.argv.index('--password-file')+1]); assert p.stat().st_mode & 0o777 == 0o600; assert p.read_text(); pathlib.Path(" + repr(str(receipt)) + ").write_text(str(p)); sys.exit(1 if sys.argv[-1]=='fail-account' else 0)")
        bootstrap = root / 'ansible/bootstrap-fixture.yml'
        fixture_password = 'Fixture-' + secrets.token_urlsafe(16) + '7'
        for success in (True, False):
            published.unlink(missing_ok=True)
            bootstrap.write_text(json.dumps([{'hosts': 'localhost', 'gather_facts': False,
                'vars': {'app': {'start_services': True, 'pegaprox': {
                    'admin_username': 'practice-admin' if success else 'fail-account'}}},
                'tasks': [{'ansible.builtin.import_tasks': 'tasks/pegaprox-bootstrap.yml'}]}]))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(bootstrap)],
                env=dict(env, PATH=str(root) + os.pathsep + env.get('PATH', ''), PEGAPROX_ADMIN_PASSWORD=fixture_password),
                capture_output=True, text=True, timeout=60)
            assert (result.returncode == 0) == success
            assert not Path(receipt.read_text()).exists()
            assert published.exists() == success
        print('PegaProx bootstrap Ansible: temporary password removed on success/failure; listener published only on success')
        shutil.rmtree('/srv/homelab')
        shutil.rmtree('/opt/homelab-app')
        print('PegaProx Ansible: fresh/repeat metadata, key drift and existing-state refusal passed')


if __name__ == '__main__':
    main()
