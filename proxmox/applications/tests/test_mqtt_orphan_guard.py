"""Exercise the real broker-retirement guard with a synthetic local Docker CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

TASKS = Path(__file__).resolve().parents[1] / 'ansible/tasks/compose.yml'


class BrokerOrphanGuardTests(unittest.TestCase):
    def test_retained_broker_refuses_before_render_and_never_deletes_data(self):
        tasks = yaml.safe_load(TASKS.read_text())
        guard = [next(t for t in tasks if t['name'] == name)
                 for name in ('Check retained broker', 'Preserve retained broker')]
        self.assertLess(tasks.index(guard[-1]), next(i for i, t in enumerate(tasks)
                        if t['name'] == 'Render private stack files on the controller'))
        for retained, selected, kind, phase, check in (
                (False, False, 'automation', 'homeassistant', False),
                (True, False, 'automation', 'homeassistant', False),
                (True, True, 'automation', 'homeassistant', False),
                (True, False, 'mqtt', 'mqtt', False),
                (True, False, 'automation', 'node_red', False),
                (True, False, 'automation', 'homeassistant', True)):
            with self.subTest(retained=retained, selected=selected, kind=kind, phase=phase, check=check), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); binary = root/'docker'; trace = root/'trace.json'
                binary.write_text('#!'+sys.executable+'\nimport json,os,sys\nfrom pathlib import Path\n'
                    'Path(os.environ["SYNTHETIC_TRACE"]).write_text(json.dumps(sys.argv[1:]))\n'
                    'print("retained-broker" if os.environ["SYNTHETIC_RETAINED"]=="1" else "")\n')
                binary.chmod(0o700)
                play = root/'play.yml'
                play.write_text(yaml.safe_dump([{'hosts':'all', 'connection':'local', 'gather_facts':False,
                    'vars':{'app':{'kind':kind}, 'stack':{'services':{'mqtt':{}} if selected else {}},
                            'application_service':phase, 'ansible_python_interpreter':sys.executable},
                    'tasks':guard}]))
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                    SYNTHETIC_TRACE=str(trace), SYNTHETIC_RETAINED='1' if retained else '0',
                    ANSIBLE_HOME=str(root/'ansible-home'), ANSIBLE_LOCAL_TEMP=str(root/'ansible-local'),
                    ANSIBLE_REMOTE_TEMP=str(root/'ansible-remote'))
                args = [str(Path(sys.executable).with_name('ansible-playbook')), '-i', 'localhost,', str(play)]
                result = subprocess.run(args+(['--check'] if check else []), env=env,
                                        capture_output=True, text=True, timeout=45)
                active = kind == 'automation' and not selected and phase == 'homeassistant' and not check
                self.assertEqual(result.returncode == 0, not (active and retained), result.stdout+result.stderr)
                if active:
                    self.assertEqual(json.loads(trace.read_text()), ['ps','--all','--quiet','--filter',
                        'label=com.docker.compose.project=homelab-automation','--filter',
                        'label=com.docker.compose.service=mqtt'])
                    if retained: self.assertIn('separately reviewed broker cutover', result.stdout)
                else:
                    self.assertFalse(trace.exists())


if __name__ == '__main__':
    unittest.main()
