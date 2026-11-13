"""Early Backup setup compiles the full desired membership without visiting guests."""
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
from private_io import digest, encoded


class BackupDeployTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        self.destination={'server':'192.0.2.50','port':8007,'datastore':'recovery','namespace':'guests','fingerprint':'ab:'*31+'ab'}
        def inventory(name):return {'job':{'group':{'member':name},'destination':{**self.destination,'auth_id':name+'@pbs!backup','backup_id':name}}}
        self.coverage={name:inventory(name) for name in ('one','two')}
        self.group={'coverage':{name:digest(encoded(row)) for name,row in self.coverage.items()}}
        self.plan=SimpleNamespace(check=Mock(),resolved={'backup':{'mode':'scheduled-recovery',
            'group':self.group,'management':{'datastore_path':'/mnt/recovery'}}})
        self.packets={name:{'enabled':name=='one','files':{'site.json':json.dumps({'app':{'backup':row}})}} for name,row in self.coverage.items()}
        self.packets['plain']={'enabled':True,'files':{'site.json':json.dumps({'app':{}})}}
        self.env={'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','PBS_API_TOKEN':'private-sentinel'}

    def test_descriptor_binds_disabled_members_without_secret_values(self):
        with patch.object(subject.component_packet,'lower_plan',return_value=self.packets):
            value=subject.descriptor(self.plan)
            self.assertEqual(value['schedule']['coverage'],self.group['coverage'])
            self.assertEqual(value['destination']['server'],'192.0.2.50')
            self.assertNotIn('private-sentinel',json.dumps(value))
            self.plan.resolved={}
            with self.assertRaisesRegex(ValueError,'operational'):subject.descriptor(self.plan)
        self.plan.resolved={'backup':{'mode':'scheduled-recovery','group':{'coverage':{}}}}
        with patch.object(subject.component_packet,'lower_plan',return_value=self.packets),self.assertRaisesRegex(ValueError,'including disabled'):
            subject.descriptor(self.plan)

    def test_early_job_maintains_one_schedule_even_when_all_guests_are_disabled(self):
        (self.root/'site.yaml').write_text('kind: site\n')
        with patch.object(subject.compiler,'resolve_plan',return_value=self.plan), \
             patch.object(subject.component_packet,'lower_plan',return_value=self.packets), \
             patch.object(subject.backup_setup,'install',return_value={'status':'configured'}) as install:
            self.assertEqual(subject.run(self.root,self.root,'[]',environment=self.env),{'status':'configured'})
            self.assertEqual(install.call_args.args,(self.group,))
            self.assertEqual(install.call_args.kwargs['datastore_path'],'/mnt/recovery')
            self.assertEqual(install.call_args.kwargs['token'],'private-sentinel')
            for packet in self.packets.values():packet['enabled']=False
            subject.run(self.root,self.root,'["one","two"]',environment=self.env)
            self.assertEqual(install.call_count,2)
            self.packets['two']['files']['site.json']=json.dumps({'app':{'backup':{
                'job':{'group':{'member':'two'},'destination':{**self.destination,'server':'192.0.2.99'}}}}})
            row=json.loads(self.packets['two']['files']['site.json'])['app']['backup']
            self.group['coverage']['two']=digest(encoded(row))
            with self.assertRaisesRegex(ValueError,'one declared PBS'):subject.run(self.root,self.root,'[]',environment=self.env)
        for key,value in [('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/heads/other')]:
            with self.assertRaisesRegex(ValueError,'protected main'):subject.run(self.root,self.root,'[]',environment={**self.env,key:value})

    def test_cli_result_and_failures_remain_redacted(self):
        args=['backup_deploy','--stack',str(self.root),'--site-root',str(self.root)]
        with patch.object(sys,'argv',args),patch.object(subject,'run',return_value={'status':'configured'}),patch('builtins.print') as output:
            subject.main();self.assertEqual(json.loads(output.call_args.args[0]),{'status':'configured'})
        with patch.object(sys,'argv',args),patch.object(subject,'run',side_effect=ValueError('private-sentinel')):
            with self.assertRaises(SystemExit) as caught:subject.main()
            self.assertNotIn('private-sentinel',str(caught.exception))
        with patch.object(sys,'argv',args),patch.dict(os.environ,{'GITHUB_EVENT_NAME':'pull_request'}),self.assertRaises(SystemExit):
            runpy.run_path(subject.__file__,run_name='__main__')


if __name__=='__main__':unittest.main()
