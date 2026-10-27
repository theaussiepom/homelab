"""Retain all provider credentials/policy and support Authentik typed callback rows."""
from dataclasses import dataclass
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import automation_oidc as oidc


class OidcTests(unittest.TestCase):
    def setUp(self):
        self.cfg={'vmid':211,'hostname':'security','provider_id':21,'client_id':'retained-client','slug':'nodered',
            'before':[{'matching_mode':'strict','url':'https://old.example.org/auth/strategy/callback/'}],
            'callback':'https://new.example.org/auth/strategy/callback/'}

    def test_dictionary_and_typed_callbacks_preserve_old_values_and_verify_without_change(self):
        @dataclass(frozen=True)
        class Redirect:
            matching_mode: str
            url: str
        for rows in [copy.deepcopy(self.cfg['before']),[Redirect(**self.cfg['before'][0])]]:
            original=copy.deepcopy(rows)
            result=oidc.candidate(rows,self.cfg)
            self.assertEqual(rows,original)
            self.assertEqual(oidc.normalized(result),[*self.cfg['before'],{'matching_mode':'strict','url':self.cfg['callback']}])
            self.assertIs(oidc.candidate(result,self.cfg,True),result)
            with self.assertRaises(ValueError):oidc.candidate(result,self.cfg)

    def test_drift_or_non_https_callbacks_never_produce_an_update(self):
        with self.assertRaises(ValueError):oidc.candidate([],self.cfg)
        for callback in ['http://new.example.org/auth/strategy/callback/','https://user:secret@new.example.org/auth/strategy/callback/',
                         'https://new.example.org/elsewhere']:
            bad=copy.deepcopy(self.cfg);bad['callback']=callback
            with self.assertRaises(ValueError):oidc.candidate(self.cfg['before'],bad)
