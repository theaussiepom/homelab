"""Agent caller integration reuses the real packet/attempt fixture, not native targets."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_ansible
import component_prepare
import deploy
import monitoring_inputs
from private_io import encoded,read_json,write_bytes,write_new
import test_component_deployment as fixture_module


class AgentCallerTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture_module.DeploymentIntegrationTests('test_real_source_and_receiver_repeat_owned_fresh_guest_without_lifecycle_flip')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.cfg=self.fixture.cfg
        directory=Path(self.cfg['deployment']['input_directory'])
        self.cfg['app']['monitoring']={'hostname':'example-node-610','psk_identity':'example-node-610',
            'server_active':'198.18.20.36:10051','server_vmid':816,'server_hostname':'zabbix',
            'profiles':['linux','docker'],'credential_file':str(directory/'applications/agent/monitoring-agent.json')}
        self.cfg['deployment']['phases'].append('zabbix-agent')
        self.cfg['deployment']['payload_phases']['zabbix-agent']='agent'
        packet=read_json(self.fixture.packet,private=True)
        packet['files']['site.json']=encoded(self.cfg).decode();write_bytes(self.fixture.packet,encoded(packet))
        provider=self.root/'provider';provider.mkdir(mode=0o700)
        for name,value in [('owner.json',{'schema':'homelab-zabbix-access-v1',
                'endpoint':self.cfg['site']['api_endpoint'],'node':'example-node',
                'address':'198.18.20.36','backup_source':'example:/backup'}),
                ('READY.json',{'identity':monitoring_inputs.TOKEN_ID,'read_only':True}),
                ('token.json',{'identity':monitoring_inputs.TOKEN_ID,
                    'token':monitoring_inputs.TOKEN_ID+'=synthetic-token'})]:
            write_new(provider/name,encoded(value))
        context=patch.object(monitoring_inputs,'PROVIDER',provider/'token.json')
        context.start();self.addCleanup(context.stop)
        self.agent_calls=[]

    def ansible(self,argv,environment,log):
        if log.parent.name!='zabbix-agent':
            return self.fixture.ansible(argv,environment,log)
        variables=read_json(Path(argv[-1][1:]),private=True)
        started=read_json(log.parent.parent/'zabbix-agent-started.json',private=True)
        self.assertEqual(started['phase_inputs']['app'],'agent')
        self.assertTrue(any(value.endswith('/component-agent.yml') for value in argv))
        self.assertFalse(variables['app']['start_services'])
        self.assertNotIn('component_application',variables)
        self.assertNotIn('zabbix_agent',variables) # No unselected database session.
        self.assertIn('ServerActive=198.18.20.36:10051',variables['monitoring_agent_configuration'])
        self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_') for key in environment))
        self.agent_calls.append(started['phase_inputs'])
        write_new(log,b'example : ok=1 changed=0 failed=0\n')

    def test_selected_agent_payload_is_phase_bound_and_repeats_without_rotation(self):
        with patch.object(component_ansible,'quiet',side_effect=self.ansible):
            self.fixture.all_phases()
            receipt=read_json(self.fixture.state/'610/ordinary-complete.json',private=True)
            parent=Path(receipt['binding']['app_inputs_directory'])
            agent=parent/'agent';app=parent/'recursive_a'
            self.assertEqual(set(p.name for p in agent.iterdir()),{
                'selected-app.json','application.json','monitoring-agent.json'})
            self.assertNotIn('monitoring-agent.json',{p.name for p in app.iterdir()})
            record=self.fixture.state/'monitoring-credentials/guest-610.json'
            before=(record.stat().st_ino,record.read_bytes(),(agent/'monitoring-agent.json').read_bytes())
            self.assertTrue(all(str(path) in receipt['binding']['input_hashes'] for path in
                (monitoring_inputs.PROVIDER,monitoring_inputs.PROVIDER.parent/'owner.json',
                 monitoring_inputs.PROVIDER.parent/'READY.json')))
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):
                self.fixture.all_phases()
            self.assertEqual(before,(record.stat().st_ino,record.read_bytes(),(agent/'monitoring-agent.json').read_bytes()))
            self.assertEqual(len(self.agent_calls),2)
            self.assertEqual(self.agent_calls[0],self.agent_calls[1])

    def test_wrong_payload_slot_or_provider_hold_refuses_without_key_creation(self):
        with patch.object(component_ansible,'quiet',side_effect=self.ansible):
            for phase in ('infrastructure','preparation','recursive_a'):
                deploy.run(phase,self.fixture.packet,inputs=self.fixture.inputs,environment={})
        selected=copy.deepcopy(self.cfg)
        selected['app']['monitoring']['credential_file']=str(self.root/'foreign/monitoring-agent.json')
        with self.assertRaises(ValueError):component_prepare.prepare_agent(selected,{})
        self.assertFalse((self.fixture.state/'monitoring-credentials').exists())
        write_new(monitoring_inputs.PROVIDER.parent/'HOLD.json',b'preserved hold')
        with self.assertRaises(ValueError):component_prepare.prepare_agent(self.cfg,{})
        self.assertFalse((self.fixture.state/'monitoring-credentials').exists())
        self.assertFalse((Path(self.cfg['deployment']['input_directory'])/'applications/agent').exists())
        self.assertEqual(self.agent_calls,[])


if __name__=='__main__':unittest.main()
