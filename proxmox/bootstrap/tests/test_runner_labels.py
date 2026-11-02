"""Execute actual label guard/registration tasks locally; no GitHub or runner listener."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

BASE = Path(__file__).resolve().parents[1]


class RunnerLabelTests(unittest.TestCase):
    def test_default_and_pool_labels_reach_argv_while_invalid_input_never_registers(self):
        tasks = yaml.safe_load((BASE/'ansible/runner-common.yml').read_text())
        selected = [next(t for t in tasks if t['name']==name) for name in
                    ('Check runner installation inputs', 'Register with a short-lived token supplied through the environment')]
        token = 'synthetic-registration-token-never-print'
        for labels, accepted in [(None,True),('homelab-private-deploy,homelab-deploy-beast,homelab-deploy-test',True),
                ('homelab-private-deploy,bad label,homelab-deploy-test',False),
                ('homelab-private-deploy,other',False),('homelab-deploy-test',False),
                (['homelab-private-deploy','homelab-deploy-test'],False)]:
            with self.subTest(labels=labels), tempfile.TemporaryDirectory()as directory:
                root=Path(directory); trace=root/'argv.json'; executable=root/'config.sh'
                executable.write_text('#!'+sys.executable+'\nimport json,os,sys\nfrom pathlib import Path\n'
                    +'Path('+repr(str(trace))+').write_text(json.dumps(sys.argv[1:]))\n'
                    +"print(os.environ['ACTIONS_RUNNER_INPUT_TOKEN'])\n")
                executable.chmod(0o700)
                variables={'runner_directory':str(root),'runner_name':'homelab-deploy-test',
                           'runner_repository':'example/private-site','runner_archive_sha256':'a'*64}
                if labels is not None:variables['runner_labels']=labels
                play=root/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'all','connection':'local','gather_facts':False,
                    'vars':variables,'tasks':copy.deepcopy(selected)}]))
                result=subprocess.run([str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)],
                    env=dict(os.environ,HOMELAB_RUNNER_REGISTRATION_TOKEN=token,ANSIBLE_LOCAL_TEMP=str(root/'ansible')),
                    capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode==0,accepted,result.stdout+result.stderr)
                self.assertNotIn(token,result.stdout+result.stderr)
                self.assertEqual(trace.exists(),accepted)
                if accepted:
                    args=json.loads(trace.read_text());expected=labels or 'homelab-private-deploy,homelab-deploy-test'
                    self.assertEqual(args[args.index('--labels')+1],expected)
                    self.assertNotIn('--token',args)


if __name__=='__main__':unittest.main()
