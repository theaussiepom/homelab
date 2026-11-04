"""CLI stdin/dispatch units; runtime identity and Docker logic are mocked peers."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

F = Path(os.environ.get('HOMELAB_FRAMEWORK', Path(__file__).resolve().parents[3]))
spec = importlib.util.spec_from_file_location('component_preflight_cli_unit', F/'proxmox/applications/component-preflight.py')
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)


class PreflightCliUnits(unittest.TestCase):
    def test_real_script_entry_converts_parser_failure_to_a_value_free_hold(self):
        output = io.StringIO(); stdin = SimpleNamespace(buffer=io.BytesIO(b'not-json'))
        with patch.object(runtime.sys, 'argv', ['component-preflight', 'before']), \
             patch.object(runtime.sys, 'stdin', stdin), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(SystemExit, '^Component ownership check held; preserve the existing runtime\\.$'):
                runpy.run_path(str(F/'proxmox/applications/component-preflight.py'), run_name='__main__')
        self.assertEqual(output.getvalue(), '')

    def test_before_and_after_forward_only_the_parsed_contract_once(self):
        selection = {'project': 'example-project', 'services': ['selected'], 'peers': ['peer'],
                     'lifecycle': 'retained', 'previously_owned': True}
        result = {'peers': {'peer': {'id': 'a'*64, 'started': 'fixture-start', 'restarts': 0}}}
        for mode in ('before', 'after'):
            value = selection if mode == 'before' else {'selection': selection, 'before': result}
            output = io.StringIO(); stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(value).encode()))
            with self.subTest(mode=mode), patch.object(runtime.sys, 'argv', ['component-preflight', mode]), \
                 patch.object(runtime.sys, 'stdin', stdin), contextlib.redirect_stdout(output), \
                 patch.object(runtime, 'inspect', return_value=result) as inspect, \
                 patch.object(runtime, 'verify', return_value=result) as verify:
                runtime.main()
            self.assertEqual(json.loads(output.getvalue()), result)
            if mode == 'before': inspect.assert_called_once_with(selection); verify.assert_not_called()
            else: verify.assert_called_once_with(value); inspect.assert_not_called()

    def test_invalid_or_oversized_stdin_never_reaches_runtime_or_emits_values(self):
        limit = 1024*1024
        for raw in (b'not-json', b'{"private":"unfinished', b'x'*(limit+2)):
            output = io.StringIO(); stdin = SimpleNamespace(buffer=io.BytesIO(raw))
            with self.subTest(size=len(raw)), patch.object(runtime.sys, 'argv', ['component-preflight', 'before']), \
                 patch.object(runtime.sys, 'stdin', stdin), contextlib.redirect_stdout(output), \
                 patch.object(runtime, 'inspect') as inspect, patch.object(runtime, 'verify') as verify:
                with self.assertRaises(ValueError): runtime.main()
            inspect.assert_not_called(); verify.assert_not_called()
            self.assertEqual(output.getvalue(), '')
            if len(raw)>limit: self.assertEqual(stdin.buffer.tell(), limit+1)


if __name__ == '__main__':
    unittest.main()
