"""The root feature flows through ordinary immutable inputs and guest phases."""
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import yaml
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ansible_guest
import deployment_inputs as inputs
import guest_contract
import monitoring_inputs
import test_monitoring_agent as agent_cases
import test_monitoring as server_cases
from fixtures import guest


class IntegrationTests(unittest.TestCase):
    def test_owned_monitoring_files_are_bound_and_native_database_packets_repeat_exactly(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);c=guest(root)
            Path(c['paths']['state_root']).mkdir(mode=0o700)
            (root/'ca').write_text('public CA')
            selected=agent_cases.cfg('mariadb')['app']['monitoring']
            selected.update(hostname='fixture-pve-808',psk_identity='fixture-pve-808')
            destination=root/'inputs'/'mariadb'/('a'*64)
            selected['credential_file']=str(destination/'monitoring-agent.json')
            selected['database_password_file']=str(destination/'monitoring-database-password')
            c['app']['monitoring']=selected
            provider=root/'token.json'
            records={'token.json':{'identity':monitoring_inputs.TOKEN_ID,'token':monitoring_inputs.TOKEN_ID+'=synthetic'},
                     'READY.json':{'identity':monitoring_inputs.TOKEN_ID,'read_only':True},
                     'owner.json':{'schema':'homelab-zabbix-access-v1','endpoint':c['site']['api_endpoint'],'node':'fixture-pve','address':'198.18.25.36','backup_source':'nas:/fixture'}}
            for name,value in records.items():p=root/name;p.write_text(json.dumps(value));p.chmod(0o600)
            packet=root/'packet.json';packet.write_text(json.dumps({'schema':guest_contract.SCHEMA,'enabled':True,'kind':'mariadb','identity':'a'*64,'files':{'site.json':json.dumps(c)}}))
            with patch.object(monitoring_inputs,'PROVIDER',provider):
                cfg,site=inputs.prepare(packet,root/'inputs')
                before={p.name:p.read_bytes() for p in site.parent.iterdir()}
                self.assertEqual(inputs.prepare(packet,root/'inputs')[0],cfg)
                self.assertEqual(before,{p.name:p.read_bytes() for p in site.parent.iterdir()})
                hashes=inputs.input_hashes(cfg)
                self.assertTrue({str(provider),selected['credential_file'],selected['database_password_file']} <= set(hashes))
                for phase in ('preparation','mariadb'):
                    def quiet(command,env,log):log.write_text('ok=1 changed=0 failed=0')
                    with patch.object(inputs,'binding',return_value=hashes),patch.object(ansible_guest.proxmox_guest,'guest_trust'),patch.object(ansible_guest,'quiet',side_effect=quiet):
                        ansible_guest.run_phase(cfg,site,root,root,hashes,phase)
                    variables=json.loads((root/phase/'variables.json').read_text())
                    self.assertEqual('monitoring_agent_configuration' in variables,phase!='preparation')
                    if phase!='preparation':self.assertIn('User=zbx_monitor',variables['monitoring_agent_configuration'])
                packet_value=json.loads(packet.read_text());packet_value['files']['monitoring-agent.json']='foreign';packet.write_text(json.dumps(packet_value))
                with self.assertRaisesRegex(ValueError,'cannot replace'):inputs.prepare(packet,root/'inputs')

    def test_server_phase_uses_retained_private_inputs_pinned_templates_and_existing_trust(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700)
            c=agent_cases.cfg('monitoring',True)
            stack=server_cases.fixture(root);path=root/'stack';path.write_text(json.dumps(stack));path.chmod(0o600)
            c['app'].update(stack_config=str(path),hostname='zabbix',address='198.18.25.36',service_health_checks={'zabbix':[]})
            c['paths']['ca_file']=str(root/'ca')
            c['app']['monitoring']['proxmox']['ca_file']=str(root/'ca')
            c['paths'].update(private_key=str(root/'ssh-key'),known_hosts=str(root/'known-hosts'))
            private=root/'server.json';private.write_text(json.dumps({'admin_password':'synthetic','members':[], 'proxmox':{}}));private.chmod(0o600)
            c['app']['monitoring']['server_file']=str(private)
            c['app']['monitoring']['credential_file']=str(root/'agent.json')
            for filename in ('agent.json','storage-password'):(root/filename).write_text('retained')
            with patch.object(monitoring_inputs,'source_files',return_value=[]):
                hashes=inputs.input_hashes(c)
                self.assertIn(str(root/'ca'),hashes)
                self.assertIn(str(root/'password'),hashes)
            def quiet(command,env,log):log.write_text('changed=0')
            with patch.object(inputs,'binding',return_value={}),patch.object(ansible_guest.proxmox_guest,'guest_trust'),patch.object(ansible_guest.proxmox_guest,'dhcp_admission'),patch.object(ansible_guest,'required_network_interfaces',return_value=[]),patch.object(ansible_guest,'quiet',side_effect=quiet):
                ansible_guest.run_phase(c,root/'site',root,root,{},'zabbix')
            variables=json.loads((root/'zabbix/variables.json').read_text())
            self.assertNotIn('monitoring_server_configuration',variables)
            payload=Path(variables['monitoring_server_configuration_file'])
            self.assertEqual(payload,root/'zabbix/monitoring-server.json')
            self.assertEqual(stat.S_IMODE(payload.stat().st_mode),0o600)
            configuration=json.loads(payload.read_text())
            self.assertEqual(configuration['owner'],{'node':'fixture','vmid':208,'hostname':'monitoring'})
            self.assertEqual(len(configuration['templates']),6)
            self.assertNotIn('Password=',variables['monitoring_agent_configuration'])
            # Execute the actual copy action, not just a single Templar pass:
            # its task-argument finalization rejects raw Zabbix macro content.
            tasks=yaml.safe_load((ansible_guest.SOURCE/'ansible/tasks/monitoring-server.yml').read_text())
            task=next(t for t in tasks if t['name']=='Install private server inputs and pinned templates')
            self.assertTrue(task['no_log'])
            self.assertEqual(task['ansible.builtin.copy']['mode'],'0600')
            self.assertEqual(task['ansible.builtin.copy']['owner'],'root')
            received=root/'literal-server.json'
            task=copy.deepcopy(task);task['no_log']=False
            task['ansible.builtin.copy'].update(dest=str(received),owner=str(os.getuid()),group=str(os.getgid()))
            play=root/'copy.yml';play.write_text(yaml.safe_dump([{'hosts':'all','connection':'local','gather_facts':False,'become':False,'tasks':[task]}]))
            local=Path(sys.executable).with_name('ansible-playbook')
            executable=str(local) if local.is_file() else shutil.which('ansible-playbook')
            self.assertIsNotNone(executable)
            result=subprocess.run([executable,'-i','localhost,',str(play),'--extra-vars','@'+str(root/'zabbix/variables.json')],
                env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(root/'ansible-local'),ANSIBLE_REMOTE_TEMP=str(root/'ansible-remote')),
                capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout[-1200:]+result.stderr[-600:])
            self.assertEqual(received.read_bytes(),payload.read_bytes())
            self.assertEqual(stat.S_IMODE(received.stat().st_mode),0o600)
            self.assertIn(b'{#',received.read_bytes())
