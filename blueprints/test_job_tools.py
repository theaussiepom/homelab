"""Execute real setup Bash, venv and pip against one offline fixture wheel.

Only the initial venv launcher adds a test-local wheel source. This proves
setup isolation/hash/failure behaviour, not an actual controller deployment.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

import workflows


class JobToolsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        wheelhouse = self.root / 'wheels'; wheelhouse.mkdir()
        wheel = wheelhouse / 'ansible_core-2.21.6-py3-none-any.whl'
        metadata = 'ansible_core-2.21.6.dist-info/'
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('fixture_ansible.py',
                'import json, os, sys\n'
                'def main():\n'
                '    if os.environ.get("FAIL_VERSION"): raise SystemExit(23)\n'
                '    assert sys.argv[1:] == ["--version"]\n'
                '    print(json.dumps({"prefix": sys.prefix, "executable": sys.executable}))\n')
            archive.writestr(metadata + 'METADATA',
                'Metadata-Version: 2.1\nName: ansible-core\nVersion: 2.21.6\nRequires-Dist: must-not-resolve-test\n')
            archive.writestr(metadata + 'WHEEL',
                'Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            archive.writestr(metadata + 'entry_points.txt',
                '[console_scripts]\nansible-playbook = fixture_ansible:main\n')
            archive.writestr(metadata + 'RECORD', '')
        self.lock = 'ansible-core==2.21.6 --hash=sha256:' + hashlib.sha256(wheel.read_bytes()).hexdigest() + '\n'
        self.launcher = self.root / 'launcher'; self.launcher.mkdir()
        shim = self.launcher / 'python3'
        shim.write_text('#!' + sys.executable + '\n'
            'import os, pathlib, subprocess, sys\n'
            'assert sys.argv[1:3] == ["-m", "venv"]\n'
            'if os.environ.get("FAIL_CREATE"): raise SystemExit(17)\n'
            'subprocess.run([sys.executable, *sys.argv[1:]], check=True)\n'
            'root = pathlib.Path(sys.argv[3])\n'
            '(root / "pip.conf").write_text(' + repr('[global]\nno-index = true\nfind-links = ' + wheelhouse.as_uri() + '\n') + ')\n')
        shim.chmod(0o700)
        self.shared = self.root / 'shared'; self.shared.mkdir()
        ambient = self.shared / 'ansible-playbook'
        ambient.write_text('#!/bin/sh\necho "Shared controller tool must not run" >&2\nexit 97\n')
        ambient.chmod(0o700)
        self.shared_before = ambient.read_bytes()
        self.runner = self.root / 'runner temp'; self.runner.mkdir()
        recipe, _ = workflows.phase_recipe()
        self.script = next(step['run'] for step in recipe['steps'] if step.get('name') == 'Prepare tools')

    def run_setup(self, name, *, bad_hash=False, missing_hash=False, failure=None):
        work = self.root / name; work.mkdir()
        source = work / 'framework-source'; source.mkdir()
        lock = self.lock if not bad_hash else self.lock.split('--hash=')[0] + '--hash=sha256:' + '0' * 64 + '\n'
        if missing_hash: lock = self.lock.split('--hash=')[0] + '\n'
        (source / 'requirements.lock.txt').write_text(lock)
        environment_file = work / 'env'; environment_file.touch()
        path_file = work / 'path'; path_file.touch()
        env = {'HOME': str(work), 'PATH': os.pathsep.join((str(self.launcher), str(self.shared), os.defpath)),
               'RUNNER_TEMP': str(self.runner), 'GITHUB_ENV': str(environment_file), 'GITHUB_PATH': str(path_file),
               'PIP_TARGET': str(self.shared)}
        if failure: env[failure] = 'true'
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', self.script],
            cwd=work, env=env, capture_output=True, text=True, timeout=60)
        return result, environment_file.read_text(), path_file.read_text(), env

    def test_parallel_jobs_install_into_distinct_private_envs_and_later_steps_use_them(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            rows = list(pool.map(self.run_setup, ('first', 'second')))
        roots = []
        for result, environment, path, env in rows:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            selected = Path(path.strip()).parent; roots.append(selected)
            self.assertEqual(selected.parent, self.runner)
            self.assertEqual(selected.stat().st_mode & 0o777, 0o700)
            self.assertEqual(environment, 'HOMELAB_CONFIG_PYTHON=' + str(selected / 'bin/python') + '\n')
            self.assertEqual(json.loads(result.stdout.splitlines()[-1])['prefix'], str(selected))
            later = dict(env, PATH=path.strip() + os.pathsep + env['PATH'])
            command = subprocess.run(['ansible-playbook', '--version'], env=later, capture_output=True, text=True, timeout=10)
            self.assertEqual(command.returncode, 0, command.stderr)
            self.assertEqual(json.loads(command.stdout)['prefix'], str(selected))
            python = subprocess.check_output(['python3', '-c', 'import sys; print(sys.prefix)'], env=later, text=True)
            self.assertEqual(python.strip(), str(selected))
        self.assertNotEqual(*roots)
        self.assertEqual((self.shared / 'ansible-playbook').read_bytes(), self.shared_before)
        self.assertEqual(sorted(p.name for p in self.shared.iterdir()), ['ansible-playbook'])

    def test_creation_hash_and_executable_failure_do_not_publish_tools(self):
        for name, options, diagnostic in (
            ('create-failure', {'failure': 'FAIL_CREATE'}, ''),
            ('hash-failure', {'bad_hash': True}, 'DO NOT MATCH THE HASHES'),
            ('missing-hash', {'missing_hash': True}, 'Hashes are required'),
            ('version-failure', {'failure': 'FAIL_VERSION'}, ''),
        ):
            with self.subTest(name=name):
                result, environment, path, _ = self.run_setup(name, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stdout + result.stderr)
                self.assertEqual(environment, '')
                self.assertEqual(path, '')


if __name__ == '__main__': unittest.main()
