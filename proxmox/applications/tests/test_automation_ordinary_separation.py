"""Ordinary installation keeps historical cross-guest configuration separate."""
import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import automation_cd as cd
import ordinary_cd
class SeparationTests(unittest.TestCase):
    def test_prepare_and_normal_run_never_read_obsolete_cross_guest_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);config=root/'config.json'
            value={'schema':'homelab-automation-deployment-v1','enabled':True,'site':{
                'app':{'kind':'automation','exclusive_writer_confirmed':True,'stack_config':'/old/stack.json',
                       'prerequisite_packet_sha256':'a'*64,'capture':{'path':'/historical/capture'}},
                'guest':{'vmid':200}},'stack':{'kind':'automation'},'discovery_previous_guests':[202,211,212,215]}
            config.write_text(json.dumps(value));original=config.read_bytes()
            with patch('automation_configuration.site_config.read',return_value={}),patch('automation_configuration.validate_inputs'), \
                 patch.object(cd,'prerequisites',side_effect=AssertionError('Historical cross-guest gate must not run')), \
                 patch.object(ordinary_cd,'run',return_value={'status':'passed'}) as engine:
                cd.ordinary('guest',config,root/'missing-legacy.json',root/'foundation.json',True)
                self.assertTrue(engine.call_args.kwargs['infrastructure_only'])
                cd.ordinary('guest',config,root/'missing-legacy.json',root/'foundation.json')
                self.assertNotIn('infrastructure_only',engine.call_args.kwargs)
                cd.ordinary('mqtt',config,root/'missing-legacy.json',root/'foundation.json')
                self.assertEqual(engine.call_args.args[0],'mqtt')
                before=engine.call_count
                with self.assertRaises(ValueError):cd.ordinary('mqtt',config,None,root/'foundation.json',True)
                self.assertEqual(engine.call_count,before)
            self.assertEqual(config.read_bytes(),original)
