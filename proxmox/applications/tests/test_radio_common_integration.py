"""Cross the real shared/radio boundary with synthetic inputs and no target access."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
import ordinary_cd as common
import render
import zigbee_ordinary as radio
from test_zigbee_ordinary import fixture


class CommonRadioIntegrationTests(unittest.TestCase):
    def test_real_adapter_preparation_repeat_and_central_alias_preserve_original_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);cfg,stack=fixture(root);inputs=root/'ordinary';identity='a'*64
            destination=inputs/'zigbee2mqtt'/identity
            cfg['app']['stack_config']=str(destination/'stack.json')
            stack['mqtt_host_alias']={'hostname':'broker.example.invalid','address':'198.18.30.21'}
            original=copy.deepcopy(stack['zigbee'])
            packet={'schema':'homelab-ordinary-deployment-v1','enabled':True,'kind':'zigbee2mqtt',
                    'identity':identity,'files':{'site.json':json.dumps(cfg),'stack.json':json.dumps(stack)}}
            path=root/'packet.json';path.write_text(json.dumps(packet))
            with patch.object(common.files,'secret_inputs',side_effect=AssertionError('Radio cannot bind another guest secret mechanism')):
                returned,site=common.prepare(path,inputs,{},adapter=radio)
                before={p.name:p.read_bytes() for p in site.parent.iterdir()}
                common.prepare(path,inputs,{},adapter=radio)
            self.assertEqual(before,{p.name:p.read_bytes() for p in site.parent.iterdir()})
            self.assertEqual(returned,cfg)
            retained=json.loads((site.parent/'stack.json').read_text())
            self.assertEqual(retained['zigbee'],original)
            self.assertEqual(render.compose(retained)['services']['zigbee2mqtt']['extra_hosts'],
                             {'broker.example.invalid':'198.18.30.21'})
            self.assertFalse((destination/'application-secret').exists())
            self.assertEqual(site.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ValueError):common.prepare(path,root/'unapproved',{})
            self.assertFalse((root/'unapproved').exists())

    def test_production_import_is_single_after_writer_guard_and_before_start(self):
        import yaml
        tasks=yaml.safe_load((SOURCE/'ansible/tasks/compose.yml').read_text())
        imports=[i for i,t in enumerate(tasks) if t.get('ansible.builtin.import_tasks')=='zigbee-admission.yml']
        self.assertEqual(len(imports),1)
        writer=next(i for i,t in enumerate(tasks) if t.get('name')=='Require the explicit start step and retired old writers')
        start=next(i for i,t in enumerate(tasks) if t.get('name')=='Start exactly this guest stack')
        self.assertLess(writer,imports[0]);self.assertLess(imports[0],start)
        self.assertFalse(any('/opt/homelab-app/zigbee2mqtt.py' in json.dumps(t) for t in tasks))
        self.assertIn('--no-deps',json.dumps(tasks[start]))
        self.assertIn('ordinary_service',json.dumps(tasks[start]))


if __name__=='__main__':unittest.main()
