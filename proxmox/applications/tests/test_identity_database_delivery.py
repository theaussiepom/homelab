"""Pinned in-memory source delivery must compile and install no guest helper."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from jinja2 import Environment, select_autoescape
import yaml

ROOT = Path(__file__).resolve().parents[1]


class DeliveryTests(unittest.TestCase):
    def test_source_bundle_compiles_from_only_the_two_pinned_local_files(self):
        play = yaml.safe_load((ROOT/'ansible/identity-database-network.yml').read_text())[0]
        reads = []
        def lookup(plugin, path):
            self.assertEqual(plugin,'ansible.builtin.file')
            path = Path(path).resolve();self.assertIn(path,[ROOT/'identity_database.py',ROOT/'identity_database_runtime.py'])
            reads.append(path);return path.read_text()
        # This fixture renders Python source; HTML/XML templates still autoescape.
        env=Environment(autoescape=select_autoescape(default_for_string=False));env.filters['to_json']=json.dumps;env.globals['lookup']=lookup
        program=env.from_string(play['vars']['identity_runtime_program']).render(playbook_dir=str(ROOT/'ansible'))
        compile(program,'<source-delivery>','exec')
        self.assertEqual(set(reads),{ROOT/'identity_database.py',ROOT/'identity_database_runtime.py'})
        commands=[task['ansible.builtin.command'] for task in play['tasks'] if 'ansible.builtin.command' in task]
        self.assertEqual(commands[-1]['argv'][:2],['/usr/bin/python3','-c'])
        self.assertIn('stdin',commands[-1])

    @unittest.skipUnless(shutil.which('ansible-playbook'), 'Pinned Linux tools contain Ansible')
    def test_real_ansible_renders_the_bundle_without_double_templating_source(self):
        play=yaml.safe_load((ROOT/'ansible/identity-database-network.yml').read_text())[0]
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'compile.yml'
            program=play['vars']['identity_runtime_program'].replace('playbook_dir','identity_adapter_dir')
            target.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local','gather_facts':False,
                'vars':{'identity_adapter_dir':str(ROOT/'ansible'),'identity_runtime_program':program},
                'tasks':[{'name':'Compile only, do not execute runtime operations',
                    'ansible.builtin.command':{'argv':['/usr/bin/python3','-c',
                        'import sys; compile(sys.argv[1], "<delivered-runtime>", "exec"); print("source_bundle_compiled")',
                        '{{ identity_runtime_program }}']},'register':'compiled','changed_when':False},
                    {'ansible.builtin.assert':{'that':'compiled.stdout == "source_bundle_compiled"'}}]}]))
            with patch.dict(os.environ,{'ANSIBLE_CONFIG':str(Path(directory)/'inherited-invalid.cfg'),
                                        'ANSIBLE_STDOUT_CALLBACK':'must-not-load-inherited-callback'}):
                config=Path(directory)/'ansible.cfg'
                config.write_text('[defaults]\nretry_files_enabled = False\n')
                environment={k:v for k,v in os.environ.items() if not k.startswith('ANSIBLE_')}
                environment.update(ANSIBLE_CONFIG=str(config),
                    ANSIBLE_LOCAL_TEMP=str(Path(directory)/'ansible-local'))
                result=subprocess.run(['ansible-playbook','-i','localhost,',str(target)],capture_output=True,text=True,
                    timeout=45,env=environment)
            self.assertEqual(result.returncode,0,result.stdout[-2500:]+result.stderr[-1000:])

    def test_inspect_and_verify_install_no_guest_files_or_service_state(self):
        play=yaml.safe_load((ROOT/'ansible/identity-database-network.yml').read_text())[0]
        for task in play['tasks']:
            self.assertNotIn('ansible.builtin.systemd_service',task)
            self.assertNotIn('ansible.builtin.script',task)
            self.assertNotIn('ansible.builtin.shell',task)
            if 'ansible.builtin.copy' in task:
                self.assertEqual(task.get('delegate_to'),'localhost')
                self.assertEqual(task['ansible.builtin.copy']['mode'],'0600')
                self.assertFalse(task['ansible.builtin.copy']['force'])


if __name__ == '__main__':unittest.main()
