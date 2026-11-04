"""Typed CLI boundaries redact private failures and preserve stdin/argv separation."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

APP = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('mqtt_cli_'+name.replace('-', '_'), APP/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class ExplorerCLITests(unittest.TestCase):
    def test_workspace_and_health_forward_typed_inputs_and_print_only_safe_result(self):
        m=load('mqtt-explorer-runtime')
        for arguments in (['workspace','--owner','{"vmid":12017}'],['health','--config','/fixture/config.json']):
            with patch.object(sys,'argv',['runtime',*arguments]), \
                    patch.object(m,'workspace',return_value={'workspace':'owned'}) as workspace, \
                    patch.object(m,'read',return_value=b'{"images":{}}') as reader, \
                    patch.object(m,'health',return_value={'mqtt_explorer':'passed'}) as health, \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                m.main()
            if arguments[0]=='workspace':
                workspace.assert_called_once_with({'vmid':12017},None,None);reader.assert_not_called();health.assert_not_called()
                self.assertEqual(json.loads(out.getvalue()),{'workspace':'owned'})
            else:
                reader.assert_called_once_with(Path('/fixture/config.json'));health.assert_called_once_with({'images':{}})
                self.assertEqual(json.loads(out.getvalue()),{'mqtt_explorer':'passed'})
        with patch.object(sys,'argv',['runtime','workspace','--owner','private-invalid-value']), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(SystemExit,'deployment held') as error:m.main()
        self.assertNotIn('private-invalid-value',str(error.exception));self.assertEqual(out.getvalue(),'')

    def test_account_cli_sequences_account_before_profile_and_redacts_input_failure(self):
        m=load('mqtt-explorer-account')
        events=[]
        with patch.object(sys,'argv',['account','--config','/fixture/account.json']), \
                patch.object(m,'read',return_value=(b'{"private":"only-in-file"}',None)) as reader, \
                patch.object(m,'account',side_effect=lambda v:events.append(('account',v)) or {'account':'verified'}), \
                patch.object(m,'profile',side_effect=lambda v:events.append(('profile',v)) or {'saved_connection':'verified'}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            m.main()
        reader.assert_called_once_with(Path('/fixture/account.json'),True)
        self.assertEqual([row[0]for row in events],['account','profile'])
        self.assertEqual(events[0][1],events[1][1]);self.assertNotIn('only-in-file',out.getvalue())
        with patch.object(sys,'argv',['account','--config','/fixture/account.json']), \
                patch.object(m,'read',side_effect=ValueError('private-password')), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(SystemExit,'account held') as error:m.main()
        self.assertNotIn('private-password',str(error.exception));self.assertEqual(out.getvalue(),'')

    def test_direct_entrypoints_refuse_before_any_native_action(self):
        for name,args in [('mqtt-explorer-runtime',['workspace','--owner','[]']),
                          ('mqtt-explorer-account',['--config','/definitely-absent-fixture/account.json'])]:
            with patch.object(sys,'argv',[name,*args]),self.assertRaises(SystemExit):
                runpy.run_path(str(APP/(name+'.py')),run_name='__main__')

    def test_docker_wrappers_capture_output_and_keep_secret_only_on_stdin(self):
        for name in ('mqtt-explorer-runtime','mqtt-explorer-account'):
            m=load(name)
            with patch.object(m.subprocess,'run',return_value=SimpleNamespace(stdout='safe')) as run:
                result=m.docker(['inspect','fixture']) if name.endswith('runtime') else m.docker(['exec','fixture'],input='synthetic-private-password')
            self.assertEqual(result,'safe');self.assertTrue(run.call_args.kwargs['capture_output'])
            self.assertNotIn('synthetic-private-password',repr(run.call_args.args))

    def test_authentication_waits_for_new_account_and_requires_anonymous_refusal(self):
        m=load('mqtt-explorer-account')
        for replies,success,sleeps in [([0,5],True,0),([1,1,0,4],True,2),([1]*6,False,5),([0,0],False,0)]:
            native=SimpleNamespace(connect=Mock(side_effect=replies))
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
            with patch.object(m.importlib.util,'spec_from_file_location',return_value=spec), \
                    patch.object(m.importlib.util,'module_from_spec',return_value=native),patch.object(m.time,'sleep') as sleep:
                if success:m.authenticate('fixture_user','synthetic-password')
                else:
                    with self.assertRaises(ValueError):m.authenticate('fixture_user','synthetic-password')
            self.assertEqual(sleep.call_count,sleeps)


if __name__=='__main__':
    unittest.main()
