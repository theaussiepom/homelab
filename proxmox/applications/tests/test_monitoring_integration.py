"""Actual selected server payload transfers template macros as literal bytes."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_ansible
import component_prepare
import monitoring_templates
import test_component_monitoring_server_caller as cases
from private_io import read_json


class IntegrationTests(unittest.TestCase):
    def test_server_phase_uses_retained_private_inputs_pinned_templates_and_existing_trust(self):
        case=cases.MonitoringServerCallerTests();case.setUp();self.addCleanup(case.doCleanups)
        with patch.object(component_prepare.component_monitoring_inputs,'prepare',return_value=copy.deepcopy(case.monitoring)):
            selected=component_prepare.prepare(case.cfg,case.app_id,{},attempt=object())
        variables=component_ansible.variables(case.cfg,case.phase,payload=selected)
        payload=selected.directory/'monitoring-server.json'
        configuration=read_json(payload,private=True)
        self.assertEqual(configuration['owner'],{'node':case.cfg['site']['node'],
            'vmid':case.cfg['guest']['vmid'],'hostname':case.cfg['guest']['hostname']})
        self.assertEqual(configuration['templates'],[monitoring_templates.prepared(name)
            for name in monitoring_templates.monitoring.VERSIONS['templates']])
        self.assertEqual(variables['monitoring_server_owner'],configuration['owner'])
        self.assertNotIn('monitoring_agent_configuration',variables)
        self.assertEqual(variables['monitoring_server_configuration_file'],str(payload))
        self.assertEqual(payload.stat().st_mode&0o777,0o600)
        task=next(task for task in yaml.safe_load((component_ansible.SOURCE/'ansible/tasks/monitoring-server.yml').read_text())
                  if task['name']=='Install private server inputs and pinned templates')
        self.assertTrue(task['no_log']);self.assertEqual(task['ansible.builtin.copy']['mode'],'0600')
        self.assertEqual(task['ansible.builtin.copy']['owner'],'root')
        self.assertEqual(task['ansible.builtin.copy']['src'],'{{ monitoring_server_configuration_file }}')
        received=case.root/'literal-server.json';task=copy.deepcopy(task);task['no_log']=False
        task['ansible.builtin.copy'].update(dest=str(received),owner=str(os.getuid()),group=str(os.getgid()))
        play=case.root/'copy.yml';play.write_text(yaml.safe_dump([{'hosts':'all','connection':'local',
            'gather_facts':False,'become':False,'tasks':[task]}]))
        values=case.root/'variables.json';case.save(values,variables)
        env=dict(os.environ,ANSIBLE_HOME=str(case.root/'ansible'),ANSIBLE_LOCAL_TEMP=str(case.root/'local'),
                 ANSIBLE_REMOTE_TEMP=str(case.root/'remote'))
        result=subprocess.run([sys.executable,'-m','ansible.cli.playbook','-i','localhost,',str(play),
            '--extra-vars','@'+str(values)],env=env,capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stdout[-1200:]+result.stderr[-600:])
        self.assertEqual(received.read_bytes(),payload.read_bytes())
        self.assertEqual(received.stat().st_mode&0o777,0o600)
        selected.check()


if __name__=='__main__':unittest.main()
