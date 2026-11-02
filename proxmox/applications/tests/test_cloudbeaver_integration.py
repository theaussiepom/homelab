"""Community variant and optional read-only preflight stay in ordinary guest stages."""
import copy
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ansible_guest
import deployment_inputs
import discovery_scope
import foundation
import guest_contract
import identity_callbacks
from fixtures import guest
from test_cloudbeaver import fixture
from test_identity_callbacks_contract import fixture as callback_fixture


class IntegrationTests(unittest.TestCase):
    def test_variant_keeps_guest_identity_and_new_workspace_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);cfg=guest(root);stack=fixture()
            cfg['deployment']['capabilities']=['linux','docker']
            cfg['guest']['memory_mib']=2048
            cfg['app'].update(kind='db-tools',variant='cloudbeaver',memory_mib=2048,
              stack_config=str(root/'stack'),exclusive_writer_confirmed=True,
              service_health_checks={'cloudbeaver':[{'argv':['true'],'name':'service','expect':''}]})
            cfg['app'].pop('database');cfg['app']['required_paths']=guest_contract.required_paths(cfg)
            stack['cloudbeaver']['bind_address']=cfg['app']['address']
            self.assertEqual(guest_contract.validate(cfg,stack),808)
            self.assertEqual(guest_contract.applications(cfg),['cloudbeaver'])
            self.assertEqual(guest_contract.blueprint(cfg)['name'],'CloudBeaver')
            before=copy.deepcopy(cfg);cfg['app']['variant']='pgadmin'
            with self.assertRaises(ValueError):guest_contract.validate(cfg,stack)
            self.assertEqual(before['guest'],cfg['guest'])
            private=root/'oauth';private.write_text('synthetic-high-entropy-test-secret'*3);private.chmod(0o600)
            stack['foundation']['secret_files']['oauth_client_secret']=str(private)
            self.assertEqual(len(foundation.files(stack)),8)
            cfg['app']['variant']='cloudbeaver'
            file=Path(cfg['app']['stack_config']);file.write_text(json.dumps(stack));file.chmod(0o600)
            def quiet(command,environment,log):log.write_text('changed=0')
            with patch.object(deployment_inputs,'binding',return_value={}),patch.object(ansible_guest.proxmox_guest,'dhcp_admission'),patch.object(ansible_guest.proxmox_guest,'guest_trust'),patch.object(ansible_guest,'quiet',side_effect=quiet):
                for phase in ('preparation','cloudbeaver'):
                    ansible_guest.run_phase(cfg,root/'site.json',root,root,{},phase)
                    variables=json.loads((root/phase/'variables.json').read_text())
                    self.assertEqual(variables['cloudbeaver_owner'],{'node':cfg['site']['node'],
                        'vmid':808,'hostname':cfg['guest']['hostname']})

    def test_ingress_preflight_uses_existing_traefik_phase_before_ansible(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);cfg=guest(root)
            cfg['deployment']['capabilities']=['linux','docker']
            stack={'kind':'ingress','services':{},'foundation':{}}
            file=root/'stack.json';file.write_text(json.dumps(stack));file.chmod(0o600)
            cfg['app'].update(kind='ingress',stack_config=str(file),
               service_health_checks={'traefik':[{'argv':['true'],'name':'service','expect':''}]})
            events=[]
            def quiet(command,environment,log):events.append('ansible');log.write_text('changed=0')
            with patch.object(deployment_inputs,'binding',return_value={}),patch.object(discovery_scope,'verify',side_effect=lambda *args:events.append('scope')) as verify,patch.object(ansible_guest.proxmox_guest,'dhcp_admission'),patch.object(ansible_guest.proxmox_guest,'guest_trust'),patch.object(ansible_guest,'quiet',side_effect=quiet):
                result=ansible_guest.run_phase(cfg,root/'site.json',root,root,{},'traefik')
            self.assertEqual(events,['scope','ansible']);verify.assert_called_once_with(cfg,stack)
            self.assertEqual(result,{'status':'passed','changed':False})

    def test_identity_callback_configuration_and_cli_are_closed(self):
        record,*_=callback_fixture()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);path=root/'callback.json';path.write_text(json.dumps([record]))
            for uri in ('https://db.example.invalid:bad/oauth2/callback','https://db.example.invalid:0/oauth2/callback'):
                with self.assertRaises(ValueError):identity_callbacks.uri(uri,True)
            args=['identity_callbacks.py','--config',str(path),'--compose',str(root/'compose')]
            with patch.object(sys,'argv',args),patch.object(identity_callbacks,'run',return_value={'callbacks':'verified'}) as run,patch('sys.stdout',new_callable=io.StringIO) as output:identity_callbacks.main()
            run.assert_called_once_with([record],root/'compose');self.assertEqual(json.loads(output.getvalue()),{'callbacks':'verified'})
            with patch.object(sys,'argv',['identity_callbacks.py']),patch('sys.stderr',new_callable=io.StringIO),self.assertRaises(SystemExit):runpy.run_path(str(Path(identity_callbacks.__file__)),run_name='__main__')


if __name__=='__main__':unittest.main()
