"""Run the actual Ansible guard locally with an isolated synthetic Docker CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

TASKS = Path(__file__).resolve().parents[1] / 'ansible/tasks/compose.yml'


class WinetOrphanGuardTests(unittest.TestCase):
    def test_real_guard_refuses_unselected_retained_winet_before_render_or_start(self):
        tasks = yaml.safe_load(TASKS.read_text())
        guard = [next(t for t in tasks if t['name'] == n) for n in ('Check WiNet', 'Preserve WiNet')]
        self.assertLess(tasks.index(guard[-1]), next(i for i,t in enumerate(tasks)
                        if t['name'] == 'Render private stack files on the controller'))
        start = next(t for t in tasks if t['name'] == 'Start exactly this guest stack')
        self.assertIn('--remove-orphans=false', start['ansible.builtin.command']['argv'])
        for retained, selected, kind, check in ((False, False, 'zigbee2mqtt', False),
                (True, False, 'zigbee2mqtt', False), (True, True, 'zigbee2mqtt', False),
                (True, False, 'ingress', False), (True, False, 'zigbee2mqtt', True)):
            with self.subTest(retained=retained, selected=selected, kind=kind, check=check), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); binary = root / 'docker'; trace = root / 'trace.json'
                binary.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                    'from pathlib import Path\n'
                    'Path(os.environ["SYNTHETIC_TRACE"]).write_text(json.dumps(sys.argv[1:]))\n'
                    'print("synthetic-retained-container" if os.environ["SYNTHETIC_RETAINED"]=="1" else "")\n')
                binary.chmod(0o700)
                play = root / 'play.yml'
                play.write_text(yaml.safe_dump([{'hosts': 'all', 'connection': 'local', 'gather_facts': False,
                    'vars': {'app': {'kind': kind}, 'stack': {'winet': {}} if selected else {},
                             'application_service': 'zigbee2mqtt', 'ansible_python_interpreter': sys.executable},
                    'tasks': guard}]))
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                    SYNTHETIC_TRACE=str(trace), SYNTHETIC_RETAINED='1' if retained else '0',
                    ANSIBLE_HOME=str(root / 'ansible-home'), ANSIBLE_LOCAL_TEMP=str(root / 'ansible-local'),
                    ANSIBLE_REMOTE_TEMP=str(root / 'ansible-remote'))
                args = [str(Path(sys.executable).with_name('ansible-playbook')), '-i', 'localhost,', str(play)]
                run = subprocess.run(args + (['--check'] if check else []), env=env,
                                     capture_output=True, text=True, timeout=45)
                active = kind == 'zigbee2mqtt' and not selected and not check
                self.assertEqual(run.returncode == 0, not (active and retained), run.stdout + run.stderr)
                if active:
                    self.assertEqual(json.loads(trace.read_text()), ['ps', '--all', '--quiet', '--filter',
                        'label=com.docker.compose.project=homelab-zigbee2mqtt', '--filter',
                        'label=com.docker.compose.service=winet'])
                    if retained: self.assertIn('Preserve it and review retirement', run.stdout)
                else:
                    self.assertFalse(trace.exists())


if __name__ == '__main__':
    unittest.main()
