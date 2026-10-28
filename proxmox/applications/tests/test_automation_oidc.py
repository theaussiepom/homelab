"""Retain all provider credentials/policy and support Authentik typed callback rows."""
from dataclasses import dataclass
import copy
from pathlib import Path
import sys
import unittest
import contextlib
import types
from unittest.mock import patch
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

    def test_inside_persists_the_pinned_models_concrete_field_and_verifies_typed_rows(self):
        # Authentik version/2025.2.1 models.py stores redirect_uris in the
        # concrete _redirect_uris JSON field through a dataclass property.
        @dataclass(frozen=True)
        class Redirect:
            matching_mode: str
            url: str
        class Provider:
            client_id=self.cfg['client_id']
            def __init__(provider):
                provider._redirect_uris=copy.deepcopy(self.cfg['before'])
                provider.persisted=copy.deepcopy(provider._redirect_uris)
                provider.client_secret='retained-private-client-secret'
                provider.saved=[];provider.refreshed=[]
            @property
            def redirect_uris(provider):return [Redirect(**row) for row in provider._redirect_uris]
            @redirect_uris.setter
            def redirect_uris(provider,rows):provider._redirect_uris=[oidc.dataclasses.asdict(row) for row in rows]
            def save(provider,*,update_fields):
                if update_fields!=['_redirect_uris']:raise ValueError('Non-concrete field in update_fields')
                provider.persisted=copy.deepcopy(provider._redirect_uris);provider.saved.append(update_fields)
            def refresh_from_db(provider,*,fields):
                if fields!=['_redirect_uris']:raise ValueError('Non-concrete field in refresh fields')
                provider._redirect_uris=copy.deepcopy(provider.persisted);provider.refreshed.append(fields)
        provider=Provider()
        manager=types.SimpleNamespace(select_for_update=lambda:types.SimpleNamespace(get=lambda **kw:provider))
        applications=types.SimpleNamespace(filter=lambda **kw:types.SimpleNamespace(count=lambda:1))
        modules={'django':types.SimpleNamespace(setup=lambda:None),
            'django.db':types.SimpleNamespace(transaction=types.SimpleNamespace(atomic=contextlib.nullcontext)),
            'authentik.providers.oauth2.models':types.SimpleNamespace(OAuth2Provider=types.SimpleNamespace(objects=manager)),
            'authentik.core.models':types.SimpleNamespace(Application=types.SimpleNamespace(objects=applications))}
        with patch.dict(sys.modules,modules):
            self.assertTrue(oidc.inside(self.cfg)['changed'])
            self.assertEqual(provider.persisted,[*self.cfg['before'],{'matching_mode':'strict','url':self.cfg['callback']}])
            self.assertFalse(oidc.inside(self.cfg,True)['changed'])
        self.assertEqual(provider.saved,[['_redirect_uris']]);self.assertEqual(provider.refreshed,[['_redirect_uris']])
        self.assertEqual(provider.client_secret,'retained-private-client-secret')
