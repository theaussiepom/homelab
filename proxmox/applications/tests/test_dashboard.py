"""Dashboard exposure is explicit, internal-only and authenticated."""
import copy
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import discovery as d
import foundation
from test_foundation import fixture


def selected():
    return {'host':'proxy.example.invalid','service':'api@internal',
            'middlewares':['security-headers','login'],'authentik_forward_auth':'login'}


def settings():
    return {'routes':{'proxy':selected()},'middlewares':{'login':{'forwardAuth':{
        'address':'http://198.18.30.21:9000/outpost.goauthentik.io/auth/traefik',
        'trustForwardHeader':True}}}}


class DashboardTests(unittest.TestCase):
    def test_normal_tls_auth_then_root_redirect_with_callback_and_no_backend_listener(self):
        cfg=settings();before=copy.deepcopy(cfg)
        shared=d.shared(cfg);http=shared['http'];router=http['routers']['proxy']
        self.assertEqual(router['service'],'api@internal')
        self.assertEqual(router['entryPoints'],['websecure'])
        self.assertEqual(router['tls'],{'certResolver':'letsencrypt'})
        self.assertEqual(router['middlewares'],['security-headers@file','login@file','proxy-dashboard-root@file'])
        self.assertNotIn('proxy',http['services'])
        redirect=http['middlewares']['proxy-dashboard-root']['redirectRegex']
        self.assertRegex('https://proxy.example.invalid/',redirect['regex'])
        for path in ('/api/overview','/dashboard/','/outpost.goauthentik.io/start'):
            self.assertIsNone(re.fullmatch(redirect['regex'],'https://proxy.example.invalid'+path))
        self.assertEqual(redirect['replacement'],'https://${1}/dashboard/')
        self.assertFalse(redirect['permanent'])
        callback=http['routers']['proxy-authentik-callback']
        self.assertEqual(callback['service'],'proxy-authentik-callback')
        self.assertNotIn('login@file',callback['middlewares'])
        self.assertNotIn('proxy-dashboard-root@file',callback['middlewares'])
        self.assertIn('PathPrefix(`/outpost.goauthentik.io/`)',callback['rule'])
        self.assertEqual(cfg,before)

    def test_invalid_internal_services_missing_auth_and_middleware_collision_refuse(self):
        for changes in ({'service':'other@internal'},{'service':'api@internal','transport':'private'},
                        {'service':None},{'url':'http://198.18.30.20'}):
            value=dict(selected(),**changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):d.validate_routes({'proxy':value})
        value=selected();value.pop('authentik_forward_auth')
        with self.assertRaises(ValueError):d.validate_routes({'proxy':value})
        with self.assertRaises(ValueError):d.validate_routes({'proxy':selected()},{'198.18.30.20'})
        value=settings();value['middlewares']['proxy-dashboard-root']={'headers':{}}
        with self.assertRaisesRegex(ValueError,'unique dashboard'):d.shared(value)
        value=settings();value['middlewares']['login']={'headers':{}}
        with self.assertRaisesRegex(ValueError,'forwardAuth'):d.shared(value)

    def test_default_static_unchanged_exact_bool_optin_only_and_no_insecure_api(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg=fixture(directory,'ingress')
            before=foundation.files(cfg)
            cfg['foundation']['dashboard']=False
            self.assertEqual(foundation.files(cfg),before)
            cfg['foundation']['dashboard']=True;cfg['routing']=settings()
            static=json.loads(next(a['content'] for a in foundation.files(cfg) if a['path']=='traefik.yml'))
            self.assertEqual(static['api'],{'dashboard':True})
            self.assertEqual(set(static['entryPoints']),{'web','websecure','health'})
            self.assertNotIn('insecure',json.dumps(static['api']))
            for invalid in ('true',1,None,[]):
                cfg['foundation']['dashboard']=invalid
                with self.subTest(invalid=invalid),self.assertRaises(ValueError):foundation.validate(cfg)
            cfg['foundation']['dashboard']=False
            with self.assertRaisesRegex(ValueError,'Enable the dashboard'):foundation.validate(cfg)
