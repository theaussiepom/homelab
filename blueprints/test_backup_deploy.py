"""Backup job orchestration mocks compiler/activation contracts; the docs fixture integrates them separately."""
import copy
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import backup_deploy as subject

class BackupDeployTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.plan=SimpleNamespace(check=Mock(),resolved={'backup':{'mode':'scheduled-recovery',
            'group':{'group':'synthetic schedule'},'management':{'datastore_path':'/mnt/recovery'}}})
        def packet(enabled,backup):return {'enabled':enabled,'files':{'site.json':json.dumps({'app':{'backup':backup}})}}
        self.packets={'one':packet(True,{'job':{'group':{'member':'one'}}}),
                      'two':packet(False,{'job':{'group':{'member':'two'}}}),'plain':packet(True,{})}
        self.env={'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','RUNNER_TEMP':str(self.root),'PBS_API_TOKEN':'private-sentinel'}
    def test_descriptor_keeps_disabled_members_but_no_secret_values(self):
        with patch.object(subject.component_packet,'lower_plan',return_value=self.packets):
            value,packets=subject.descriptor(self.plan)
        self.assertEqual(value['enabled'],['one']);self.assertEqual(set(value['coverage']),{'one','two'})
        self.assertEqual(packets,self.packets);self.assertNotIn('private-sentinel',json.dumps(value))
        self.plan.resolved={}
        with self.assertRaisesRegex(ValueError,'operational'):subject.descriptor(self.plan)
    def test_protected_job_only_binds_enabled_members_before_activation(self):
        (self.root/'site.yaml').write_text('kind: site\n')
        with patch.object(subject.compiler,'resolve_plan',return_value=self.plan), \
             patch.object(subject.component_packet,'lower_plan',return_value=self.packets), \
             patch.object(subject.credentials,'bind') as bind, \
             patch.object(subject.backup_activation,'activate',return_value={'status':'activated'}) as activate:
            self.assertEqual(subject.run(self.root,self.root,'[]',environment=self.env),{'status':'activated'})
            bind.assert_called_once();self.assertEqual(bind.call_args.args[0].name,'one.json')
            self.assertEqual(activate.call_args.args[1],'private-sentinel')
            self.assertFalse(list(self.root.glob('homelab-backup-inputs-*')))
            self.packets['one']['enabled']=False
            self.assertEqual(subject.run(self.root,self.root,'["one","two"]',environment=self.env)['status'],'not_selected')
            activate.assert_called_once()
        for field,value in [('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/heads/other')]:
            with self.assertRaisesRegex(ValueError,'protected main'):
                subject.run(self.root,self.root,'[]',environment={**self.env,field:value})
    def test_cli_reports_allowlisted_result_or_redacted_failure(self):
        args=['backup_deploy','--stack',str(self.root),'--site-root',str(self.root)]
        with patch.object(sys,'argv',args),patch.object(subject,'run',return_value={'status':'activated'}) as run,patch('builtins.print') as output:
            subject.main();self.assertEqual(json.loads(output.call_args.args[0]),{'status':'activated'})
        with patch.object(sys,'argv',args),patch.object(subject,'run',side_effect=ValueError('private-sentinel')):
            with self.assertRaises(SystemExit) as caught:subject.main()
            self.assertNotIn('private-sentinel',str(caught.exception))
        with patch.object(sys,'argv',args),patch.dict(os.environ,{'GITHUB_EVENT_NAME':'pull_request'}),self.assertRaises(SystemExit):
            runpy.run_path(subject.__file__,run_name='__main__')

if __name__=='__main__':unittest.main()
