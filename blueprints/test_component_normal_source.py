"""Closed normal source/receiver contract; old migration intent cannot opt in."""
import copy
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import component_sources as sources
import component_types as types
import component_guest
import test_component_bitwarden_normal as real_source
from test_component_plan import site

class NormalSourceTests(unittest.TestCase):
 def test_guest_and_app_refuse_every_former_admission_even_empty_or_well_shaped(self):
  source=site()
  rows=[('guest',source['guests']['resolver'],types.guest),('app',source['apps']['recursive_a'],types.app)]
  for kind,base,validator in rows:
   validator(base)
   for value in({},None,{'source_assertions':{'evidence':'old'}},{'initial_ordinary':{'evidence':'old'}},
                 {'coordinated_custody':{'evidence':'old','member':'postgresql'}},
                 {'reviewed_ordinary_failures':{'evidence':'old'}},{'assets':{'catalogue':'old'}}):
    changed=copy.deepcopy(base);changed['admission']=value
    with self.subTest(kind=kind,admission=value),self.assertRaises(ValueError):validator(changed)
 def test_former_migration_evidence_types_refuse_while_ongoing_callback_remains(self):
  with tempfile.TemporaryDirectory()as directory:
   reader=sources.Sources(Path(directory).resolve())
   callbacks=[{'schema':'ongoing callback owner validates contents separately'}]
   self.assertEqual(reader.evidence({'type':'identity-callbacks','document':callbacks}),{'type':'identity-callbacks','document':callbacks})
   for kind in('initial-ordinary','coordinated-custody','reviewed-ordinary-failures','source-assertions'):
    for value in({},[],None):
     with self.subTest(kind=kind,value=value),self.assertRaises(ValueError):reader.evidence({'type':kind,'document':value})
 def test_actual_compiler_packet_has_only_normal_fields_and_old_receiver_fields_cannot_hide(self):
  fixture=real_source.NormalBitwardenCompilerTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
  cfg,packet,app=fixture.packet()
  self.assertFalse(set(cfg)&{'coordinated_custody','initial_ordinary','reviewed_ordinary_failures'})
  self.assertNotIn('kind',cfg['app']);self.assertNotIn('exclusive_writer_confirmed',cfg['app']);self.assertNotIn('prerequisites',cfg['deployment'])
  self.assertFalse(any('custody' in name or 'catalogue' in name or 'acceptance' in name for name in packet['files']))
  cases=[lambda c:c.update(initial_ordinary={}),lambda c:c.update(coordinated_custody={}),lambda c:c.update(reviewed_ordinary_failures=[]),
   lambda c:c['app'].update(exclusive_writer_confirmed=True),lambda c:c['app'].update(exclusive_writer_confirmed=False),
   lambda c:c['paths'].update(coordinated_custody_inputs='/old/inputs'),lambda c:c['deployment'].update(prerequisites=[])]
  for mutate in cases:
   changed=copy.deepcopy(cfg);mutate(changed)
   with self.subTest(case=cases.index(mutate)),patch.object(Path,'open',side_effect=AssertionError('Pure receiver only')),self.assertRaises(ValueError):component_guest.validate(changed)

if __name__=='__main__':unittest.main()
