"""Run the documented read-only guards against owned command/typed-D-Bus fakes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs/backup/remote-storage.md'


def blocks():
    return re.findall(r'^```(\w+)\n(.*?)^```$', GUIDE.read_text(), re.M | re.S)


class RemoteStorageGuideTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pbs-guide-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_documented_shell_blocks_parse_without_running_setup_commands(self):
        for language, source in blocks():
            if language in ('sh', 'bash'):
                with self.subTest(source=source.splitlines()[0]):
                    result = subprocess.run(['bash', '-n'], input=source, text=True,
                                            capture_output=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_readiness_helper_requires_exact_mount_route_version_and_transport(self):
        source = next(source for language, source in blocks() if source.startswith('#!/bin/sh'))
        helper = self.root / 'ready.sh'
        helper.write_text(source)
        commands = self.root / 'bin'
        commands.mkdir()
        for name in ('ip', 'findmnt'):
            target = commands / name
            target.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
if sys.argv[0].endswith('/ip'):
    print(os.environ['TEST_ROUTE'])
else:
    print(json.loads(os.environ['TEST_MOUNT'])[sys.argv[-1]])
''')
            target.chmod(0o700)
        route = [{'dev': 'nic1', 'prefsrc': '192.0.2.21'}]
        mount = {'SOURCE': '192.0.2.20:/exports/pbs', 'FSTYPE': 'nfs4',
                 'OPTIONS': 'rw,relatime,vers=4.1,hard,proto=tcp,sec=sys'}

        def run(selected_mount, selected_route):
            env = {'PATH': os.pathsep.join((str(commands), str(Path(sys.executable).parent),
                                           '/usr/bin', '/bin')),
                   'TEST_ROUTE': json.dumps(selected_route), 'TEST_MOUNT': json.dumps(selected_mount)}
            return subprocess.run(['sh', str(helper)], env=env, capture_output=True, check=False)

        self.assertEqual(run(mount, route).returncode, 0)
        variants = [
            ('SOURCE', '192.0.2.20:/exports/other'), ('FSTYPE', 'nfs'),
            *[('OPTIONS', mount['OPTIONS'].replace('vers=4.1', version))
              for version in ('vers=3', 'vers=4', 'vers=4.0', 'vers=4.2', 'vers=4.10', '')],
            ('OPTIONS', mount['OPTIONS'].replace('proto=tcp', 'proto=udp')),
            ('OPTIONS', mount['OPTIONS'].replace('proto=tcp', '')),
            ('OPTIONS', mount['OPTIONS'].replace('rw,', 'ro,')),
            ('OPTIONS', mount['OPTIONS'].replace('hard,', 'soft,')),
            ('OPTIONS', mount['OPTIONS'] + ',noatime'),
        ]
        for field, value in variants:
            changed = {**mount, field: value}
            with self.subTest(field=field, value=value):
                self.assertNotEqual(run(changed, route).returncode, 0)
        for changed in ([], [{'dev': 'nic2', 'prefsrc': '192.0.2.21'}],
                        [{'dev': 'nic1', 'prefsrc': '192.0.2.22'}], route + route):
            with self.subTest(route=changed):
                self.assertNotEqual(run(mount, changed).returncode, 0)

    def condition(self, changed=None):
        source = next(source for language, source in blocks() if "<<'PY_CONDITION'" in source)
        python = source.split("<<'PY_CONDITION'\n", 1)[1].rsplit('\nPY_CONDITION', 1)[0]
        marker = str(self.root / 'allow')
        dropin = str(self.root / 'test.conf')
        obj = '/org/freedesktop/systemd1/unit/mnt_2dbackup_2emount'
        data = {
            'GetUnit': {'type': 'o', 'data': [obj]},
            'DropInPaths': {'type': 'as', 'data': [dropin]},
            'Conditions': {'type': 'a(sbbsi)', 'data': [
                ['ConditionPathExists', False, False, marker, 0],
                ['ConditionPathExists', False, False, '/other/prerequisite', 1]]},
        }
        if changed is not None:
            changed(data)
        calls = []

        def read(argv, *, text):
            calls.append(argv)
            self.assertEqual(argv[:3], ['busctl', '--system', '--json=short'])
            key = 'GetUnit' if argv[3] == 'call' else argv[-1]
            if key != 'GetUnit':
                self.assertEqual(argv[5], obj)
            return json.dumps(data[key])

        env = {'PBS_MOUNT_TEST': str(self.root), 'PBS_MOUNT_DROPIN': dropin}
        with patch.dict(os.environ, env), patch.object(subprocess, 'check_output', side_effect=read), \
                contextlib.redirect_stdout(io.StringIO()):
            exec(compile(python, str(GUIDE) + ':PY_CONDITION', 'exec'), {})
        return calls

    def test_actual_typed_condition_check_accepts_mandatory_untested_or_evaluated_gate(self):
        self.assertEqual(len(self.condition()), 3)
        for result in (-1, 1):
            with self.subTest(result=result):
                self.assertEqual(len(self.condition(
                    lambda data: data['Conditions']['data'][0].__setitem__(4, result))), 3)

    def test_actual_typed_condition_check_refuses_missing_optional_or_malformed_gate(self):
        cases = [
            lambda d: d['GetUnit'].update(type='s'),
            lambda d: d['GetUnit'].update(data=[]),
            lambda d: d['GetUnit'].update(data=['/wrong/object']),
            lambda d: d['DropInPaths'].update(data=[]),
            lambda d: d['DropInPaths']['data'].append(d['DropInPaths']['data'][0]),
            lambda d: d['DropInPaths'].update(type='s'),
            lambda d: d['Conditions'].update(data=[]),
            lambda d: d['Conditions'].update(type='s', data='[unprintable]'),
            lambda d: d['Conditions']['data'][0].__setitem__(0, 'ConditionPathIsMountPoint'),
            lambda d: d['Conditions']['data'][0].__setitem__(1, True),
            lambda d: d['Conditions']['data'][0].__setitem__(2, True),
            lambda d: d['Conditions']['data'][0].__setitem__(3, '/wrong/allow'),
            lambda d: d['Conditions']['data'][0].__setitem__(4, False),
            lambda d: d['Conditions']['data'].append(copy.deepcopy(d['Conditions']['data'][0])),
            lambda d: d['Conditions']['data'][0].pop(),
        ]
        for index, change in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(SystemExit):
                self.condition(change)
        (self.root / 'allow').touch()
        with self.assertRaises(SystemExit):
            self.condition()

    def test_documented_owner_change_is_empty_root_only_and_checks_identity_and_readback(self):
        source = next(source for language, source in blocks() if "<<'PY_OWNER'" in source)
        python = source.split("<<'PY_OWNER'\n", 1)[1].rsplit('\nPY_OWNER', 1)[0]
        path = self.root / 'export'
        path.mkdir(mode=0o700)
        # Substitute only the guide's explicitly installation-specific mount path.
        python = python.replace("path = '/mnt/backup'", 'path = ' + repr(str(path)))
        code = compile(python, str(GUIDE) + ':PY_OWNER', 'exec')
        owner = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        env = {'PBS_OWNER_UID': str(owner.pw_uid), 'PBS_OWNER_GID': str(owner.pw_gid)}

        def run(selected=owner, chmod=None):
            import pwd
            with patch.dict(os.environ, env), patch.object(pwd, 'getpwnam', return_value=selected), \
                    patch.object(os, 'fchown') as change, contextlib.redirect_stdout(io.StringIO()):
                if chmod is None:
                    exec(code, {})
                else:
                    with patch.object(os, 'fchmod', side_effect=chmod):
                        exec(code, {})
                self.assertEqual(change.call_count, 1)
                self.assertEqual(change.call_args.args[1:], (owner.pw_uid, owner.pw_gid))

        run()
        with self.assertRaises(SystemExit):
            run(SimpleNamespace(pw_uid=owner.pw_uid + 1, pw_gid=owner.pw_gid))
        (path / '.hidden').write_text('existing')
        with self.assertRaises(SystemExit), patch.object(os, 'fchown') as change:
            run()
        change.assert_not_called()
        (path / '.hidden').unlink()
        path.chmod(0o750)
        with self.assertRaises(SystemExit):
            run(chmod=lambda *_: None)
        path.rmdir()
        path.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError), patch.object(os, 'fchown') as change:
            run()
        change.assert_not_called()


if __name__ == '__main__':
    unittest.main()
