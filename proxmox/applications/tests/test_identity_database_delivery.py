"""Pinned in-memory source delivery must compile and install no guest helper."""
import ast
import inspect
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


def compile_bundle(program):
    """Compile the rendered wrapper and its exact literal payloads without execution."""
    compile(program,'<source-delivery>','exec')
    payloads=[]
    for node in ast.walk(ast.parse(program)):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='compile':
            assert len(node.args)==3 and not node.keywords, 'Use the pinned literal payload compilation'
            payload,filename,mode=(ast.literal_eval(arg) for arg in node.args)
            assert isinstance(payload,str) and mode=='exec', 'Compile only embedded source text'
            compile(payload,filename,mode)
            payloads.append(filename)
    assert sorted(payloads)==['<pinned-identity-database>','<pinned-identity-runtime>'], \
        'Compile exactly both pinned Python payloads'


class DeliveryTests(unittest.TestCase):
    def rendered_bundle(self, overrides=None):
        play = yaml.safe_load((ROOT/'ansible/identity-database-network.yml').read_text())[0]
        reads = []
        def lookup(plugin, path):
            self.assertEqual(plugin,'ansible.builtin.file')
            path = Path(path).resolve();self.assertIn(path,[ROOT/'identity_database.py',ROOT/'identity_database_runtime.py'])
            reads.append(path)
            return overrides[path.name] if overrides and path.name in overrides else path.read_text()
        # This fixture renders Python source; HTML/XML templates still autoescape.
        env=Environment(autoescape=select_autoescape(default_for_string=False));env.filters['to_json']=json.dumps;env.globals['lookup']=lookup
        program=env.from_string(play['vars']['identity_runtime_program']).render(playbook_dir=str(ROOT/'ansible'))
        return program,reads,play

    def test_source_bundle_compiles_from_only_the_two_pinned_local_files(self):
        program,reads,play=self.rendered_bundle()
        compile_bundle(program)
        self.assertEqual(set(reads),{ROOT/'identity_database.py',ROOT/'identity_database_runtime.py'})
        commands=[task['ansible.builtin.command'] for task in play['tasks'] if 'ansible.builtin.command' in task]
        self.assertEqual(commands[-1]['argv'][:2],['/usr/bin/python3','-c'])
        self.assertIn('stdin',commands[-1])

    def test_invalid_embedded_payload_is_rejected_after_rendering(self):
        for name in ('identity_database.py','identity_database_runtime.py'):
            with self.subTest(payload=name):
                program,_,_=self.rendered_bundle({name:'def synthetic_invalid_payload(:\n'})
                with self.assertRaises(SyntaxError):
                    compile_bundle(program)

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
                        'import ast, sys\n'+inspect.getsource(compile_bundle)+
                        '\ncompile_bundle(sys.argv[1]); print("source_bundle_compiled")',
                        '{{ identity_runtime_program }}']},'register':'compiled','changed_when':False},
                    {'ansible.builtin.assert':{'that':'compiled.stdout == "source_bundle_compiled"'}}]}]))
            inherited_home=Path(directory)/'inherited-home'
            callback=inherited_home/'.ansible/plugins/callback/synthetic_inherited.py'
            callback.parent.mkdir(parents=True)
            marker=Path(directory)/'inherited-callback-loaded'
            callback.write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n'
                'from ansible.plugins.callback import CallbackBase\n'
                'class CallbackModule(CallbackBase):\n'
                ' CALLBACK_VERSION=2.0\n CALLBACK_TYPE="aggregate"\n'
                ' CALLBACK_NAME="synthetic_inherited"\n CALLBACK_NEEDS_ENABLED=False\n')
            with patch.dict(os.environ,{'HOME':str(inherited_home),
                                        'ANSIBLE_CONFIG':str(Path(directory)/'inherited-invalid.cfg'),
                                        'ANSIBLE_STDOUT_CALLBACK':'must-not-load-inherited-callback'}):
                config=Path(directory)/'ansible.cfg'
                config.write_text('[defaults]\nretry_files_enabled = False\n')
                environment={k:v for k,v in os.environ.items() if not k.startswith('ANSIBLE_')}
                home=Path(directory)/'home';home.mkdir(mode=0o700)
                ansible_home=Path(directory)/'ansible-home';ansible_home.mkdir(mode=0o700)
                environment.update(HOME=str(home),ANSIBLE_HOME=str(ansible_home),ANSIBLE_CONFIG=str(config),
                    ANSIBLE_LOCAL_TEMP=str(Path(directory)/'ansible-local'))
                result=subprocess.run(['ansible-playbook','-i','localhost,',str(target)],capture_output=True,text=True,
                    timeout=45,env=environment)
            self.assertEqual(result.returncode,0,result.stdout[-2500:]+result.stderr[-1000:])
            self.assertFalse(marker.exists(),'An inherited-home callback was loaded')

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
