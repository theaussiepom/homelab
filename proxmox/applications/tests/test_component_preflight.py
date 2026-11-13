"""Read-only runtime admission units mock only the Docker process boundary."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('component_preflight',Path(__file__).resolve().parents[1]/'component-preflight.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.selection={'project':'example-project','services':['selected'],'peers':['peer'],
                        'lifecycle':'fresh','previously_owned':False}
        self.containers={'peer':{'id':'a'*64,'started':'synthetic-time','restarts':0}}
        self.calls=[]

    def docker(self,argv,**kwargs):
        self.calls.append(argv)
        if argv[:2]==['docker','ps']:
            if '--format' in argv:
                return SimpleNamespace(returncode=0,stdout='\n'.join(
                    row['id']+' '+service for service,row in self.containers.items()),stderr='')
            service=argv[-1].rsplit('=',1)[1]
            row=self.containers.get(service)
            return SimpleNamespace(returncode=0,stdout=row['id']+'\n' if row else '',stderr='')
        service=next(key for key,row in self.containers.items() if row['id']==argv[-1])
        row=self.containers[service]
        labels={'com.docker.compose.project':'example-project','com.docker.compose.service':service}
        return SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,[labels,row['started'],row['restarts']]))+'\n',stderr='')

    def test_fresh_namespace_and_then_owned_repeat_preserve_peer_metadata(self):
        with patch.object(runtime.subprocess,'run',side_effect=self.docker):
            before=runtime.inspect(self.selection)
            self.assertEqual(before['peers']['peer']['id'],'a'*64)
            self.containers['selected']={'id':'b'*64,'started':'new-time','restarts':0}
            runtime.verify({'selection':self.selection,'before':before})
            with self.assertRaises(ValueError):runtime.inspect(self.selection)
            self.selection['previously_owned']=True
            runtime.inspect(self.selection)
        self.assertTrue(all(argv[0]=='docker' for argv in self.calls))
        self.assertTrue(all('.Config.Env' not in ' '.join(argv) for argv in self.calls))

    def test_changed_peer_id_start_or_restart_and_missing_selected_refuse(self):
        for field,value in (('id','c'*64),('started','changed'),('restarts',1)):
            with self.subTest(field=field):
                self.setUp()
                with patch.object(runtime.subprocess,'run',side_effect=self.docker):
                    before=runtime.inspect(self.selection)
                    self.containers['selected']={'id':'b'*64,'started':'new-time','restarts':0}
                    self.containers['peer'][field]=value
                    with self.assertRaises(ValueError):runtime.verify({'selection':self.selection,'before':before})
        self.containers.pop('selected')
        with patch.object(runtime.subprocess,'run',side_effect=self.docker),self.assertRaises(ValueError):
            runtime.verify({'selection':self.selection,'before':{'peers':{}}})

    def test_closed_selection_and_ambiguous_or_failed_docker_reads_refuse(self):
        for field,value in (('project','../foreign'),('services',['selected','selected']),
                ('peers',['selected']),('previously_owned',1),('lifecycle','adopt')):
            selected=dict(self.selection,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):runtime.inspect(selected)
        for result in (SimpleNamespace(returncode=1,stdout='',stderr='private-error'),
                SimpleNamespace(returncode=0,stdout='a'*64+'\n'+'b'*64,stderr=''),
                SimpleNamespace(returncode=0,stdout='',stderr='warning')):
            with self.subTest(result=result.returncode),patch.object(runtime.subprocess,'run',return_value=result),self.assertRaises(ValueError):
                runtime.inspect(self.selection)

    def test_unselected_same_project_service_refuses_before_any_per_service_or_mutating_command(self):
        for service in ('mqtt','winet','foreign'):
            self.setUp();self.containers[service]={'id':'c'*64,'started':'retained-time','restarts':0}
            with self.subTest(service=service),patch.object(runtime.subprocess,'run',side_effect=self.docker),self.assertRaises(ValueError):
                runtime.inspect(dict(self.selection,lifecycle='retained'))
            self.assertEqual(len(self.calls),1)
            self.assertEqual(self.calls[0][:2],['docker','ps'])
            self.assertNotIn('up',self.calls[0]);self.assertNotIn('rm',self.calls[0])

    def test_project_inventory_rejects_missing_labels_duplicate_owners_and_unsafe_projection(self):
        valid='a'*64+' selected'
        for raw in ('a'*64,valid+'\n'+'b'*64+' selected',valid+'\n'+'a'*64+' peer',
                    'not-a-container selected','a'*64+' ../foreign','a'*64+' service extra',
                    '\n'.join([valid]*129)):
            with self.subTest(raw_shape=len(raw)),patch.object(runtime,'command',return_value=raw),self.assertRaises(ValueError):
                runtime.project_services('example-project')
        with patch.object(runtime,'command',return_value=''):
            self.assertEqual(runtime.project_services('example-project'),set())


if __name__=='__main__':unittest.main()
