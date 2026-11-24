"""Only the previous tagged project service and its unchanged bind may be retired."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import authentik_redis_retirement as retirement


class RedisRetirementTests(unittest.TestCase):
    def setUp(self):
        self.cid = '1' * 64
        self.digest = '9' * 64
        self.image = 'redis@sha256:' + '2' * 64
        self.selection = dict(project='identity',services=['web','jobs'],peers=['peer'],
                              previously_owned=True,lifecycle='retained')
        self.file = Path('/opt/homelab-app/compose-identity.yml')
        self.services = {name:{'command':role,'environment':{'AUTHENTIK_REDIS__HOST':'cache'},
                               'depends_on':{'cache':{'condition':'service_healthy'}}}
                         for name,role in [('web','server'),('jobs','worker')]}
        self.services.update(peer={},cache={'image':self.image,'command':['--save','60','1','--loglevel','warning'],
                                             'volumes':['/srv/data/cache:/data']})
        self.mount = {'Type':'bind','Source':'/srv/data/cache','Destination':'/data','RW':True}
        self.labels = {'com.docker.compose.project':'identity','com.docker.compose.service':'cache',
                       'com.docker.compose.config-hash':self.digest}
        self.listing = '\n'.join(str(i)*64+' '+name for i,name in enumerate(['cache','web','jobs'],1))
        self.calls = []

    def docker(self, *args):
        self.calls.append(args)
        return {'ps':self.listing,'compose':'cache '+self.digest,
                'inspect':json.dumps([self.image,self.labels,[self.mount]])}.get(args[0], '')

    def run_retirement(self):
        with patch.object(retirement,'docker',side_effect=self.docker), \
             patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=0o100600,st_uid=0,st_size=1024)), \
             patch.object(Path,'read_bytes',return_value=json.dumps({'name':'identity','services':self.services}).encode()):
            return retirement.retire(self.selection,self.file)

    def test_retires_only_proved_id_and_keeps_data_after_repeat(self):
        self.assertTrue(self.run_retirement())
        self.assertEqual(self.calls[-2:], [('stop','--time','60',self.cid),('rm',self.cid)])
        self.listing=self.listing.split('\n',1)[1]
        self.assertFalse(self.run_retirement())
        self.assertEqual(self.calls[-1][0], 'ps')

    def test_unowned_mismatched_or_shared_predecessor_is_refused(self):
        for change in ('new-owner','extra','changed-hash','foreign-mount','dependent-peer','other-image','old-attachment'):
            with self.subTest(change=change):
                self.setUp()
                if change=='new-owner': self.selection['previously_owned']=False
                if change=='extra': self.listing+='\n'+'8'*64+' foreign'
                if change=='changed-hash': self.labels['com.docker.compose.config-hash']='wrong'
                if change=='foreign-mount': self.mount['Source']='/srv/other'
                if change=='dependent-peer': self.services['peer']['depends_on']={'cache':{}}
                if change=='other-image': self.services['cache']['image']='foreign'
                if change=='old-attachment': self.services['jobs']['environment']['AUTHENTIK_REDIS__HOST']='elsewhere'
                with self.assertRaises(ValueError): self.run_retirement()
                self.assertFalse(any(args[0] in ('stop','rm') for args in self.calls))

    def test_script_reports_only_result_or_fixed_error(self):
        script=retirement.__file__
        for argv,good in [([script,str(self.file)],True),([script,'/tmp/unowned'],False)]:
            with patch.object(sys,'argv',argv),patch.object(sys,'stdin',io.StringIO(json.dumps(self.selection))), \
                 patch('subprocess.run',return_value=SimpleNamespace(stdout='')), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                if good:
                    runpy.run_path(script,run_name='__main__')
                    self.assertEqual(json.loads(out.getvalue()), {'changed':False})
                else:
                    with self.assertRaisesRegex(SystemExit,'Retained Redis retirement refused'):
                        runpy.run_path(script,run_name='__main__')
