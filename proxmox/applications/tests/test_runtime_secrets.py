"""Direct retained-record parser and current selected-input security boundaries."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_input_secrets as inputs
import runtime_secrets

IDENTITY='fixture@pve!discovery'


def record():
    return {'schema':'homelab-service-discovery-v1','identity':IDENTITY,'token':IDENTITY+'=synthetic-only-17'}


class RetainedProviderTokenTests(unittest.TestCase):
    def test_exact_record_returns_only_the_retained_token_value_without_io(self):
        raw=json.dumps(record()).encode()
        with patch('builtins.open',side_effect=AssertionError('Parser never opens inputs')):
            self.assertEqual(runtime_secrets.retained_provider_token(raw,IDENTITY),'synthetic-only-17')

    def test_closed_record_schema_identity_full_prefix_and_token_character_failures(self):
        for mutation in ('schema','identity','missing','extra','not-string','prefix','empty','space','newline','second-equals'):
            value=record()
            if mutation=='schema':value['schema']='foreign'
            elif mutation=='identity':value['identity']='foreign@pve!discovery'
            elif mutation=='missing':value.pop('token')
            elif mutation=='extra':value['foreign']='not-selected'
            else:value['token']={'not-string':None,'prefix':'foreign=value','empty':IDENTITY+'=',
                'space':IDENTITY+'=unsafe value','newline':IDENTITY+'=unsafe\nvalue','second-equals':IDENTITY+'=unsafe=value'}[mutation]
            with self.subTest(case=mutation),self.assertRaises(ValueError)as error:
                runtime_secrets.retained_provider_token(json.dumps(value).encode(),IDENTITY)
            self.assertNotIn('unsafe',str(error.exception))

    def test_nonobject_or_malformed_json_never_returns_a_token(self):
        for raw in (b'',b'{bad-json',b'[]',b'null',b'1',b'"private-malformed-text"'):
            with self.subTest(length=len(raw)),self.assertRaises(ValueError)as error:
                runtime_secrets.retained_provider_token(raw,IDENTITY)
            self.assertNotIn('private-malformed-text',str(error.exception))

    def test_identity_is_regex_escaped_and_cannot_match_a_different_record_prefix(self):
        identity='fixture.user@pve!discovery';value=record()
        value.update(identity=identity,token=identity+'=synthetic-only')
        self.assertEqual(runtime_secrets.retained_provider_token(json.dumps(value).encode(),identity),'synthetic-only')
        value['token']='fixtureXuser@pve!discovery=synthetic-only'
        with self.assertRaises(ValueError):runtime_secrets.retained_provider_token(json.dumps(value).encode(),identity)


class CurrentSelectedInputSecurityTests(unittest.TestCase):
    def test_file_source_preserves_bytes_and_mode0600_but_refuses_other_modes_and_symlinks(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            file=root/'existing';file.write_bytes(b'synthetic-existing-bytes\n')
            sources={'options':{'type':'file','path':str(file)}}
            file.chmod(0o600)
            self.assertEqual(inputs.selected('winet',sources,{}),{'options':file.read_bytes()})
            self.assertEqual(file.stat().st_mode&0o777,0o600)
            # Current selected-file input uses regular()'s 0600-only contract.
            # The removed fixed wrapper's optional 0400 reader is not called.
            for mode in (0o400,0o644):
                file.chmod(mode)
                with self.assertRaises(ValueError):inputs.selected('winet',sources,{})
                self.assertEqual(file.stat().st_mode&0o777,mode)
            file.chmod(0o600);link=root/'link';link.symlink_to(file)
            with self.assertRaises((OSError,ValueError)):inputs.selected('winet',{'options':{'type':'file','path':str(link)}},{})
            file.write_bytes(b'')
            with self.assertRaises(ValueError):inputs.selected('winet',sources,{})

    def test_environment_source_rejects_missing_empty_control_oversize_and_unselected_slots(self):
        sources={'secret_key':{'type':'environment','name':'AUTHENTIK_SECRET_KEY'},
                 'postgresql_password':{'type':'environment','name':'AUTHENTIK_POSTGRESQL_PASSWORD'}}
        slots=inputs.slots('authentik',sources)
        valid={slot:'synthetic-preserved-$value'for slot in slots.values()}
        self.assertEqual(inputs.selected('authentik',sources,valid),{role:b'synthetic-preserved-$value'for role in sources})
        for raw in ('','\n','two\nlines','nul\0value','x'*65537):
            env=copy.deepcopy(valid);env[slots['secret_key']]=raw
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):inputs.selected('authentik',sources,env)
        for mutate in ('missing','foreign'):
            env=copy.deepcopy(valid)
            if mutate=='missing':env.pop(slots['secret_key'])
            else:env['HOMELAB_APP_SECRET_NODE_RED_API_TOKEN']='foreign'
            with self.assertRaises(ValueError):inputs.selected('authentik',sources,env)


if __name__=='__main__':unittest.main()
