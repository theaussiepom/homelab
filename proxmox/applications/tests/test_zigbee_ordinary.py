"""Radio adapter policy tests; use invented inputs and no target or device access."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock,patch

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
import zigbee_ordinary as radio
import zigbee_usb
from test_deploy import fixture as site_fixture
from test_zigbee2mqtt import fixture as stack_fixture,DEVICE


def fixture(root):
    cfg=site_fixture(root);stack=stack_fixture()
    cfg['app'].update(kind='zigbee2mqtt',usb_stage='attached')
    cfg['app'].pop('capture',None)
    cfg['guest']['serial_device']={'path':DEVICE}
    cfg['guest']['interfaces'][0]['role']='backend'
    stack['zigbee']['bind_address']=cfg['guest']['interfaces'][0]['ipv4'].split('/')[0]
    cfg['app']['zigbee_admission']={k:'1'*64 for k in radio.ADMISSION_FIELDS}
    cfg['app']['zigbee_admission'].update(selection_sha256=radio.zigbee2mqtt.fingerprint(stack['zigbee']),
        checker_sha256=radio.deploy.sha(SOURCE/'zigbee2mqtt.py'))
    return cfg,stack


class RadioOrdinaryTests(unittest.TestCase):
    def test_restore_first_start_device_listener_and_unbound_receipts_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,stack=fixture(Path(tmp));radio.validate(cfg,stack)
            bad=[]
            for field,value in [('capture',{}),('zigbee_first_start_approval',{'approved':True}),('usb_stage','prepare')]:
                item=copy.deepcopy(cfg);item['app'][field]=value;bad.append(item)
            for field,value in [('capture_sha256','wrong'),('selection_sha256','2'*64),('checker_sha256','2'*64)]:
                item=copy.deepcopy(cfg);item['app']['zigbee_admission'][field]=value;bad.append(item)
            item=copy.deepcopy(cfg);item['guest']['serial_device']['path']=DEVICE+'-other';bad.append(item)
            item=copy.deepcopy(cfg);item['guest']['interfaces'][0].pop('role');bad.append(item)
            for item in bad:
                with self.subTest(config=item),self.assertRaises(ValueError):radio.validate(item,stack)

    def test_central_broker_alias_preserves_configuration_and_rejects_other_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,stack=fixture(Path(tmp));before=copy.deepcopy(stack['zigbee'])
            stack['mqtt_host_alias']={'hostname':'broker.example.invalid','address':'198.18.30.21'}
            self.assertEqual(radio.zigbee2mqtt.mqtt_alias(stack),{'broker.example.invalid':'198.18.30.21'})
            self.assertEqual(stack['zigbee'],before)
            for alias in ({'hostname':'other.invalid','address':'198.18.30.21'},
                    {'hostname':'broker.example.invalid','address':'0.0.0.0'},
                    {'hostname':'broker.example.invalid','address':'127.0.0.1'},
                    {'hostname':'broker.example.invalid','address':'8.8.8.8'},
                    {'hostname':'broker.example.invalid','address':'198.18.30.21','rewrite':True}):
                stack['mqtt_host_alias']=alias
                with self.subTest(alias=alias),self.assertRaises(ValueError):radio.zigbee2mqtt.mqtt_alias(stack)

    def test_shared_controller_is_the_only_operation_and_hold_owner(self):
        engine=types.SimpleNamespace(GUEST_ADAPTER_API=1,run=Mock(return_value={'changed':False}))
        self.assertEqual(radio.run('infrastructure',Path('/synthetic/packet'),engine=engine),{'changed':False})
        engine.run.assert_called_once_with('infrastructure',Path('/synthetic/packet'),adapter=radio)
        with self.assertRaises(ValueError):radio.run('application',Path('/synthetic/packet'),engine=types.SimpleNamespace())

    def test_plan_rejects_creation_unknown_or_changed_usb_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,_=fixture(Path(tmp));device=[zigbee_usb.desired(cfg)]
            change={'actions':['no-op'],'before':{'device_passthrough':device},'after':{'device_passthrough':device}}
            value={'resource_changes':[{'address':zigbee_usb.RESOURCE,'change':change}]}
            radio.check_plan(value,cfg,existing=True)
            with self.assertRaises(ValueError):radio.check_plan(value,cfg,existing=False)
            for key,value in [('after',{'device_passthrough':[]}),('after_unknown',{'device_passthrough':True})]:
                bad=copy.deepcopy(change);bad[key]=value
                with self.assertRaises(ValueError):radio.check_plan({'resource_changes':[{'address':zigbee_usb.RESOURCE,'change':bad}]},cfg,existing=True)

    def test_missing_state_or_failed_usb_firewall_preflight_precedes_common_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,_=fixture(root);engine=types.SimpleNamespace(application=Mock())
            with self.assertRaises(FileNotFoundError):radio.before_infrastructure(cfg,root/'site',root,root/'op',{},engine=engine)
            engine.application.assert_not_called()
            (root/'terraform.tfstate').write_text('{}');(root/'usb-prepared.json').write_text('{}');(root/'usb-prepared.json').chmod(0o600)
            with patch.object(radio.zigbee_usb,'require_prepared'),patch.object(radio.zigbee_usb,'verify_firewall',side_effect=ValueError('disabled')):
                with self.assertRaises(ValueError):radio.before_infrastructure(cfg,root/'site',root,root/'op',{},engine=engine)
            engine.application.assert_not_called()
            with patch.object(radio.zigbee_usb,'require_prepared'),patch.object(radio.zigbee_usb,'verify_firewall'),patch.object(radio.zigbee_usb,'verify_live'):
                radio.before_infrastructure(cfg,root/'site',root,root/'op',{},engine=engine)
                self.assertEqual(engine.application.call_args.kwargs['playbook'],'zigbee-preflight.yml')
                radio.application(cfg,root/'site',root,root/'op',{},engine=engine)
                self.assertEqual(engine.application.call_args.kwargs['playbook'],'zigbee-reconcile.yml')
