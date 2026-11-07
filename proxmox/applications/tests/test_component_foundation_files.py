"""Conforming component fakes plus one retained public renderer comparison."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3]))
sys.path.insert(0,str(F/'proxmox/applications'))
import foundation
import runtime_secrets
import component_input_secrets
import discovery


def auth():
    sources={key:{'type':'environment','name':key.upper()} for key in ('secret_key','postgresql_password','smtp_password')}
    return {'adapter':'authentik','input_sources':sources}, {key:('synthetic-'+key+'-$literal').encode() for key in sources}


def ingress():
    app={'id':'edge','adapter':'traefik','properties':{'dashboard':True},
         'input_sources':{'cloudflare_dns_token':{'type':'environment','name':'CLOUDFLARE_DNS_TOKEN'},
                          'proxmox_token':{'type':'file','path':'/var/lib/example/service-discovery/token.json'}},
         'role_addresses':{'frontend':'198.18.40.33'},
         'settings':{'provider':{'url':'https://198.18.25.10:8006','token_id':'fixture@pve!discovery','ca_file':'/public/context.pem'},
                     'acme':{'email':'operator@example.invalid','resolvers':['198.18.40.2:53']},
                     'route_ca_files':{'verified':{'source':'/public/context.pem','filename':'route-verified.pem'}}}}
    token={'schema':'homelab-service-discovery-v1','identity':'fixture@pve!discovery','token':'fixture@pve!discovery=synthetic-value-17'}
    secrets={'cloudflare_dns_token':b'synthetic-cloudflare-$literal','proxmox_token':json.dumps(token).encode()}
    ca=b'-----BEGIN CERTIFICATE-----\nsynthetic-public-fixture\n-----END CERTIFICATE-----\n'
    target={'app':'identity','protocol':'http','address':'198.18.30.20','port':9000}
    middleware={'security-headers':{'type':'default-headers'},'admins':{'type':'ip-allow-list','ranges':['198.18.25.0/24']},
                'login':{'type':'forward-auth','endpoint':{'app':'identity','endpoint':'web'},'target':target},
                'canonical':{'type':'canonical-home-redirect','app':'db'}}
    def route(host,target,**extra):
        return {'type':'http','endpoint':{'app':target['app'],'endpoint':'web'} if 'app'in target else {'external':'external'},
                'domain':'fixture-domain','ingress':{'app':'edge','endpoint':'https'},'tls':'fixture-tls',
                'hosts':[host],'target':target,'ingress_target':{'app':'edge','protocol':'https','address':'198.18.40.33','port':443},
                'middlewares':['security-headers'],**extra}
    routes={'external':route('host.example.invalid',{'external':'host','protocol':'https','address':'198.18.25.1','port':443},middlewares=['security-headers','admins'],transport='verified'),
            'managed':route('db.example.invalid',{'app':'db','protocol':'http','address':'198.18.30.32','port':80},middlewares=['security-headers','login']),
            'alias':route('old-db.example.invalid',{'app':'db','protocol':'http','address':'198.18.30.32','port':80},middlewares=['security-headers','canonical']),
            'dashboard':route('proxy.example.invalid',{'app':'edge','internal':'dashboard'},middlewares=['security-headers','login'])}
    plan={'routes':routes,'middlewares':middleware,'transports':{'verified':{'ca_file':'/public/context.pem'}},
          'canonical_middlewares':{'canonical':{'redirectRegex':{'regex':'^https://[^/]+/(.*)','replacement':'https://db.example.invalid/','permanent':False}}}}
    return app,secrets,ca,{'verified':ca},plan


class FoundationFilesTests(unittest.TestCase):
    def test_cloudflare_owned_plugin_and_origin_token_are_only_in_private_payload(self):
        app, secrets, ca, cas, plan = ingress()
        app['settings']['cloudflare'] = True
        from application_contract import runtime_files
        self.assertTrue({'cloudflare.go', 'cloudflare-go.mod', 'cloudflare-LICENSE', 'cloudflare-manifest.yml'} <= runtime_files(app))
        app['input_sources']['cloudflare_origin_token'] = {'type': 'file', 'path': '/protected/origin'}
        secrets['cloudflare_origin_token'] = b'synthetic-retained-origin-token'
        plan['middlewares']['public'] = {'type': 'cloudflare-source', 'ranges': ['10.0.0.0/8'], 'origin_header': 'x-origin-token'}
        plan['routes']['external']['middlewares'].insert(0, 'public')
        rows = {row['path']: row for row in self.build((app, secrets, ca, cas, plan))}
        static = json.loads(rows['traefik.yml']['content'])
        shared = json.loads(rows['shared.yml']['content'])
        self.assertEqual(static['experimental']['localPlugins'], {'cloudflare-source': {'moduleName': 'github.com/theaussiepom/homelab-cloudflare'}})
        self.assertFalse(static['entryPoints']['websecure'].get('forwardedHeaders', {}).get('insecure', False))
        self.assertEqual(shared['http']['middlewares']['public']['plugin']['cloudflare-source'], {
            'internalCIDRs': ['10.0.0.0/8'], 'originHeader': 'x-origin-token', 'originToken': 'synthetic-retained-origin-token'})
        for name in ('cloudflare.go', 'cloudflare-go.mod', 'cloudflare-LICENSE', 'cloudflare-manifest.yml'):
            self.assertEqual(rows[name]['content'], (F/'proxmox/applications/traefik_cloudflare'/name.replace('cloudflare-go.mod', 'go.mod').replace('cloudflare-LICENSE', 'LICENSE').replace('cloudflare-manifest.yml', '.traefik.yml')).read_bytes())
            self.assertEqual(rows[name]['mode'], '0400')
        for bad in ('short', 'missing-gate'):
            if bad == 'short': secrets['cloudflare_origin_token'] = b'short'
            else:
                secrets['cloudflare_origin_token'] = b'synthetic-retained-origin-token'
                plan['routes']['external']['middlewares'].remove('public')
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.build((app, secrets, ca, cas, plan))

    def setUp(self):
        import component_foundation_files
        self.runtime=runtime_secrets;self.foundation=foundation;self.builder=component_foundation_files
    def build(self,args=None):
        app,secrets,ca,cas,plan=ingress() if args is None else args
        return self.builder.files(app,secrets=secrets,public_ca=ca,route_cas=cas,route_plan=plan)
    def test_auth_app_unit_keeps_exact_role_bytes_and_fixed_leaf_ownership(self):
        app,secrets=auth(); rows=self.builder.files(app,secrets=secrets)
        self.assertEqual([r['path']for r in rows],['authentik-secret-key','postgresql-password','smtp-password'])
        self.assertTrue(all((r['uid'],r['gid'],r['mode'])==(1000,1000,'0400')for r in rows))
        self.assertEqual([r['content']for r in rows],list(secrets.values()))
    def test_auth_optional_smtp_is_not_invented(self):
        app,secrets=auth();app['input_sources'].pop('smtp_password');secrets.pop('smtp_password')
        self.assertEqual(len(self.builder.files(app,secrets=secrets)),2)
    def test_auth_missing_foreign_and_invalid_scalar_inputs_refuse(self):
        for change in ('missing','foreign','notbytes','newline','nul','empty','oversize'):
            app,secrets=auth()
            if change=='missing':secrets.pop('secret_key')
            elif change=='foreign':secrets['other']=b'fixture';app['input_sources']['other']={}
            else:secrets['secret_key']={'notbytes':'value','newline':b'value\n','nul':b'value\0','empty':b'','oversize':b'x'*65537}[change]
            with self.subTest(case=change),self.assertRaises(ValueError):self.builder.files(app,secrets=secrets)
    def test_auth_rejects_peer_public_inputs(self):
        app,secrets=auth()
        for extra in ({'public_ca':b'fixture'},{'route_cas':{}},{'route_plan':{}}):
            with self.subTest(keys=list(extra)),self.assertRaises(ValueError):self.builder.files(app,secrets=secrets,**extra)
    def test_app_units_delegate_existing_pure_renderers_and_exact_token_parser(self):
        app,secrets,ca,cas,plan=ingress()
        with patch.object(self.runtime,'retained_provider_token',return_value='parsed-token')as parser,patch.object(self.foundation,'ingress_static',return_value={'static':'fixture'})as static,patch.object(self.builder,'routing',return_value={'transports':{'verified':{'ca_file':'/public/context.pem'}}})as routing,patch.object(discovery,'shared',return_value={'shared':'fixture'})as shared:
            rows=self.builder.files(app,secrets=secrets,public_ca=ca,route_cas=cas,route_plan=plan)
        parser.assert_called_once_with(secrets['proxmox_token'],app['settings']['provider']['token_id']);routing.assert_called_once_with(app,plan);shared.assert_called_once();self.assertEqual(static.call_args.args[1],'parsed-token')
        self.assertEqual(json.loads(rows[0]['content']),{'static':'fixture'})
    def test_retained_record_parser_keeps_closed_schema_identity_and_full_token(self):
        _,secrets,_,_,_=ingress(); raw=secrets['proxmox_token']
        self.assertEqual(self.runtime.retained_provider_token(raw,'fixture@pve!discovery'),'synthetic-value-17')
        for kind in ('schema','identity','token','extra'):
            value=json.loads(raw)
            if kind=='schema':value[kind]='other'
            elif kind=='identity':value[kind]='foreign@pve!discovery'
            elif kind=='token':value[kind]='fixture@pve!discovery=bad value'
            else:value[kind]='foreign'
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.runtime.retained_provider_token(json.dumps(value).encode(),'fixture@pve!discovery')
    def test_selected_inputs_and_real_token_parser_reach_only_owned_component_files(self):
        app,secrets,ca,cas,plan=ingress()
        slots=component_input_secrets.slots('traefik',app['input_sources'])
        env={slots['cloudflare_dns_token']:secrets['cloudflare_dns_token'].decode()}
        with patch.object(component_input_secrets,'regular',return_value=secrets['proxmox_token'])as reader:
            supplied=component_input_secrets.selected('traefik',app['input_sources'],env)
        reader.assert_called_once()
        self.assertEqual(supplied,secrets)
        rows={row['path']:row for row in self.builder.files(app,secrets=supplied,public_ca=ca,route_cas=cas,route_plan=plan)}
        self.assertEqual(rows['cloudflare-dns-token']['content'],secrets['cloudflare_dns_token'])
        self.assertEqual(json.loads(rows['traefik.yml']['content'])['providers']['plugin'][foundation.PLUGIN]['apiToken'],'synthetic-value-17')
        self.assertNotIn('proxmox-token',rows)
    def test_public_retained_static_and_trust_bytes_match_frozen_semantic_rows(self):
        expected=json.loads(Path(__file__).with_name('foundation-pure-baseline.json').read_text())['rows']
        current={row['path']:row for row in self.build()}
        self.assertEqual(current['traefik.yml'],expected['traefik.yml'])
        for name in ('pve-ca.pem','cloudflare-dns-token'):
            self.assertEqual(current[name],dict(expected[name],content=expected[name]['content'].encode()))
    def test_public_typed_route_projection_matches_old_shared_renderer(self):
        app,_,_,_,plan=ingress();old={'routes':{'external':{'host':'host.example.invalid','url':'https://198.18.25.1:443','middlewares':['security-headers','admins'],'transport':'verified'},'dashboard':{'host':'proxy.example.invalid','service':'api@internal','middlewares':['security-headers','login'],'authentik_forward_auth':'login'}},'middlewares':{'admins':{'ipAllowList':{'sourceRange':['198.18.25.0/24']}},'login':{'forwardAuth':{'address':'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik','trustForwardHeader':True,'authResponseHeaders':list(self.builder.AUTH_HEADERS)}},'canonical':copy.deepcopy(plan['canonical_middlewares']['canonical'])},'transports':copy.deepcopy(plan['transports']),'authentik_callbacks':{'managed':{'host':'db.example.invalid','middlewares':['security-headers','login'],'authentik_forward_auth':'login'},'alias':{'host':'old-db.example.invalid','middlewares':['security-headers','login','canonical'],'authentik_forward_auth':'login'}}}
        # Existing callback security contract intentionally disallows redirects.
        plan['routes']['alias']['middlewares']=['security-headers','canonical']
        old['authentik_callbacks'].pop('alias')
        self.assertEqual(discovery.shared(self.builder.routing(app,plan)),discovery.shared(old))
    def test_managed_routes_stay_in_notes_and_only_owned_callbacks_are_file_routes(self):
        app,_,_,_,plan=ingress();plan['routes']['alias']['middlewares']=['security-headers','canonical'];result=self.builder.routing(app,plan)
        self.assertNotIn('managed',result['routes']);self.assertIn('managed',result['authentik_callbacks']);self.assertNotIn('alias',result['authentik_callbacks'])
        dynamic=discovery.shared(result);self.assertNotIn('managed',dynamic['http']['routers']);self.assertIn('managed-authentik-callback',dynamic['http']['routers'])
        callback=dynamic['http']['routers']['managed-authentik-callback'];self.assertEqual(callback['priority'],15);self.assertNotIn('login@file',callback['middlewares'])
    def test_redirect_cannot_be_combined_with_a_forward_auth_callback(self):
        app,_,_,_,plan=ingress();plan['routes']['alias']['middlewares']=['security-headers','login','canonical']
        with self.assertRaisesRegex(ValueError,'Callbacks retain direct'):self.builder.routing(app,plan)
    def test_unknown_route_plan_or_foreign_ingress_refuses(self):
        for case in ('unknown','foreign','missing'):
            args=list(ingress());plan=args[-1]
            if case=='unknown':plan['foreign']={}
            elif case=='foreign':plan['routes']['external']['ingress_target']['app']='other'
            else:plan.pop('transports')
            with self.subTest(case=case),self.assertRaises(ValueError):self.build(args)
    def test_redirect_permanence_unknown_type_and_unselected_projection_refuse(self):
        for case in ('permanent','type','unused'):
            app,_,_,_,plan=ingress()
            if case=='permanent':plan['canonical_middlewares']['canonical']['redirectRegex']['permanent']=True
            elif case=='type':plan['middlewares']['admins']['type']='arbitrary-config'
            else:plan['canonical_middlewares']['unused']=copy.deepcopy(plan['canonical_middlewares']['canonical'])
            with self.subTest(case=case),self.assertRaises(ValueError):self.builder.routing(app,plan)
    def test_unknown_missing_and_conflicting_route_cas_refuse(self):
        for case in ('extra','missing','name','source'):
            args=list(ingress());app,secrets,ca,cas,plan=args
            if case=='extra':cas['other']=ca
            elif case=='missing':cas.clear()
            elif case=='name':app['settings']['route_ca_files']['verified']['filename']='../escape.pem'
            else:app['settings']['route_ca_files']['verified']['source']='/foreign.pem'
            with self.subTest(case=case),self.assertRaises(ValueError):self.build(args)
    def test_public_certificate_and_scalar_boundaries_reject_private_keys_or_control_bytes(self):
        for raw in (b'',b'PRIVATE KEY',b'-----BEGIN CERTIFICATE-----\nPRIVATE KEY',b'\xff',b'x'*65537):
            args=list(ingress());args[2]=raw
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):self.build(args)
    def test_provider_raw_token_substitution_and_foreign_role_refuse(self):
        for case in ('rawtoken','environment','foreign','oversize'):
            args=list(ingress());app,secrets,_,_,_=args
            if case=='rawtoken':secrets['proxmox_token']=b'synthetic-token'
            elif case=='environment':app['input_sources']['proxmox_token']={'type':'environment','name':'TOKEN'}
            elif case=='foreign':secrets['other']=b'foreign'
            else:secrets['proxmox_token']=b'x'*65537
            with self.subTest(case=case),self.assertRaises(ValueError):self.build(args)
    def test_all_generated_rows_have_finite_leaves_and_private_owner_modes(self):
        args=list(ingress());args[-1]['routes']['alias']['middlewares']=['security-headers','canonical'];rows=self.build(args)
        self.assertEqual([r['path']for r in rows],['traefik.yml','shared.yml','route-verified.pem','pve-ca.pem','cloudflare-dns-token'])
        self.assertTrue(all((r['uid'],r['gid'],r['mode'])==(0,0,'0400')for r in rows));self.assertNotIn('proxmox-token',[r['path']for r in rows])
        static=json.loads(rows[0]['content']);self.assertEqual(static['providers']['plugin'][self.foundation.PLUGIN]['apiToken'],'synthetic-value-17');self.assertNotIn('homelab-service-discovery-v1',rows[0]['content'])
    def test_builder_never_opens_source_paths_or_mutates_supplied_metadata(self):
        args=list(ingress());args[-1]['routes']['alias']['middlewares']=['security-headers','canonical'];before=copy.deepcopy(args)
        with patch('pathlib.Path.open',side_effect=AssertionError('No path open')),patch.object(component_input_secrets,'regular',side_effect=AssertionError('No private read')):
            self.build(args)
        self.assertEqual(args,before)

if __name__=='__main__':unittest.main()
