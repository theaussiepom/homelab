"""Configured route ownership, aliases, policy admission and dependency cycles."""
import copy
from types import SimpleNamespace
import unittest

import component_routed_checks as m
from component_errors import ComponentError


def fixture():
    def endpoint(owner, suffix, port=443, protocol='https', app=None):
        return {'guest':owner,'app':app or owner,'address':'198.18.21.'+str(suffix),'port':port,'protocol':protocol}
    guests = {}
    for name, suffix in [('room',10),('edge',11),('names',12),('login',13)]:
        guests[name] = {'interfaces':{'wire':{'slot':0}},
            'provider_interfaces':[{'ipv4':'198.18.21.'+str(suffix)+'/24','gateway':'198.18.21.1'}],
            'rules':[{'direction':direction,'proto':protocol,'port':str(port),
                'source':'198.18.0.0/15','destination':'198.18.0.0/15'}
                for direction in ('in','out') for protocol,port in [('tcp',443),('udp',53)]]}
    guests['room']['route_checks']={'mode':'inline','source':{'interface':'wire'}}
    web={'type':'http','target':endpoint('room',10,9000,'http'),'domain':'web','hosts':['web.example.invalid','alias.example.invalid'],
         'ingress_target':endpoint('edge',11),'resolver':'filter','check':{'type':'page','contains':'expected'}}
    idp={'type':'http','target':endpoint('login',13,9000,'http'),'domain':'idp','hosts':['idp.example.invalid'],
         'ingress_target':endpoint('edge',11)}
    e=SimpleNamespace(resolved={'web':web,'idp':idp},domains={'web':'web.example.invalid','idp':'idp.example.invalid'},middlewares={})
    r=SimpleNamespace(guests=guests,endpoints={('app','filter','query'):endpoint('names',12,53,'udp','filter')},
                      address_groups={'runner':['198.18.21.99/32']})
    return r,e,{'guest_dependencies':{key:[]for key in guests}}


class RoutedCompilationTests(unittest.TestCase):
    def test_all_aliases_real_dns_distinct_sources_and_exact_dependencies(self):
        r,e,d=fixture();before=copy.deepcopy(r.guests)
        result=m.bind(r,e,d);rows=result['routed_checks']['room']['rows']
        self.assertEqual([row['host']for row in rows],e.resolved['web']['hosts'])
        self.assertTrue(all(row['resolver_address']=='198.18.21.12' and row['source_address']=='198.18.21.10' for row in rows))
        self.assertEqual(d['guest_dependencies']['room'],['edge','names'])
        self.assertEqual(r.guests,before);self.assertEqual(result['deferred_routed_checks'],{})

    def test_forward_auth_derived_provider_and_explicit_page_provider_are_real_waits(self):
        for check in (None,{'type':'page','contains':'local login','provider':{'exposure':'idp'}}):
            r,e,d=fixture();web=e.resolved['web'];web.pop('check')
            if check:web['check']=check
            e.middlewares={'auth':{'type':'forward-auth','target':{'guest':'login','app':'login'}}};web['middlewares']=['auth']
            result=m.bind(r,e,d)
            self.assertEqual(d['guest_dependencies']['room'],['edge','login','names'])
            self.assertEqual(result['routed_checks']['room']['rows'][0]['auth_origins'],['https://idp.example.invalid'])

    def test_domain_provider_resolves_owned_guest_but_external_origin_has_no_fake_job(self):
        for managed in (True,False):
            r,e,d=fixture();e.resolved['web']['check']={'type':'auth-redirect','provider':{'domain':'idp'}}
            if not managed:e.resolved['idp']['target'].pop('guest')
            value=m.bind(r,e,d)
            self.assertEqual('login' in d['guest_dependencies']['room'],managed)
            self.assertEqual(value['routed_checks']['room']['rows'][0]['auth_origins'],['https://idp.example.invalid'])
        r,e,d=fixture();e.resolved['web']['check']={'type':'auth-redirect','provider':{'exposure':'idp'}}
        e.resolved['idp']['target'].pop('guest')
        m.bind(r,e,d)
        self.assertNotIn('login',d['guest_dependencies']['room'])
        r,e,d=fixture();e.resolved['web']['check']={'type':'auth-redirect','provider':{'domain':'idp'}}
        e.resolved['web']['middlewares']=['external']
        e.middlewares['external']={'type':'forward-auth','target':{'address':'192.0.2.50','port':9000}}
        m.bind(r,e,d)
        e.resolved['web'].pop('check')
        with self.assertRaisesRegex(ComponentError,'route-check'):m.bind(r,e,{'guest_dependencies':{key:[]for key in r.guests}})
        r,e,d=fixture();e.resolved['web'].pop('check');e.resolved['web']['middlewares']=['auth']
        e.middlewares['auth']={'type':'forward-auth','target':{'app':'unpublished','guest':'login'}}
        with self.assertRaisesRegex(ComponentError,'provider'):m.bind(r,e,d)
        r,e,d=fixture();r.guests['login']['route_checks']={'mode':'inline','source':{'interface':'wire'}}
        r.guests['room'].pop('route_checks');e.resolved['idp'].update(resolver='filter',check={'type':'page','contains':'Identity'})
        with self.assertRaisesRegex(ComponentError,'route-check-owner'):m.bind(r,e,d)

    def test_deferred_checks_break_foundation_cycle_without_dropping_prerequisites(self):
        r,e,d=fixture();d['guest_dependencies']['login']=['room']
        e.resolved['web']['check']={'type':'auth-redirect','provider':{'exposure':'idp'}}
        with self.assertRaisesRegex(ComponentError,'cycle'):m.bind(r,e,d)
        r.guests['room']['route_checks']={'mode':'deferred','name':'Check room web','source':{'address_group':'runner'}}
        result=m.bind(r,e,{'guest_dependencies':{key:[]for key in r.guests}})
        self.assertEqual(result['deferred_routed_checks']['room'],{'name':'Check room web','needs':['edge','login','names','room']})
        self.assertEqual(result['routed_checks']['room']['rows'][0]['source_address'],'198.18.21.99')

    def test_deferred_web_edges_never_delay_guest_and_real_edges_remain(self):
        r,e,d=fixture()
        r.guests['room']['route_checks']={'mode':'deferred','name':'Check room web','source':{'address_group':'runner'}}
        e.resolved['web']['check']={'type':'auth-redirect','provider':{'exposure':'idp'}}
        d['guest_dependencies']['login']=['room']
        before=copy.deepcopy(d)
        for _ in range(2):
            result=m.bind(r,e,d)
            self.assertEqual(d,before)
            self.assertEqual(result['deferred_routed_checks']['room']['needs'],['edge','login','names','room'])
        # The same producer can be a genuine declared startup prerequisite.
        d['guest_dependencies']['room']=['edge']
        m.bind(r,e,d)
        self.assertEqual(d['guest_dependencies']['room'],['edge'])
        d['guest_dependencies']['edge']=['room']
        with self.assertRaisesRegex(ComponentError,'cycle'):m.bind(r,e,d)

    def test_missing_expectations_resolver_provider_source_or_existing_grants_refuse(self):
        def mutate(r,e,d,case):
            web=e.resolved['web']
            if case=='check':web.pop('check')
            if case=='resolver':web.pop('resolver')
            if case=='dns':r.endpoints={}
            if case=='source':r.guests['room']['route_checks']['source']['interface']='missing'
            if case=='manual':r.guests['room']['provider_interfaces'][0]['ipv4']='manual'
            if case=='egress':r.guests['room']['rules']=[]
            if case=='ingress':r.guests['edge']['rules']=[]
            if case=='provider':web['check']={'type':'auth-redirect','provider':{'exposure':'missing'}}
            if case=='foreign-provider':web['check']={'type':'auth-redirect','provider':{'exposure':'idp'}};e.resolved['idp']['target'].pop('guest')
            if case=='allowlist':web['middlewares']=['acl'];e.middlewares={'acl':{'type':'ip-allow-list','ranges':['192.0.2.0/24']}}
            if case=='owner':r.guests['room'].pop('route_checks')
            if case=='empty':e.resolved.pop('web')
        for case in ('check','resolver','dns','source','manual','egress','ingress','provider','allowlist','owner','empty'):
            r,e,d=fixture();mutate(r,e,d,case)
            with self.subTest(case=case),self.assertRaises(ValueError):m.bind(r,e,d)

    def test_deferred_runner_must_be_one_host_and_permitted_on_both_destinations(self):
        for values,fail in [(['198.18.21.99/32'],False),([],True),(['198.18.21.0/24'],True),(['198.18.21.99/32','198.18.21.98/32'],True)]:
            r,e,d=fixture();r.guests['room']['route_checks']={'mode':'deferred','name':'Read web','source':{'address_group':'runner'}}
            r.address_groups['runner']=values
            if fail:
                with self.assertRaises(ValueError):m.bind(r,e,d)
            else:
                m.bind(r,e,d);r.guests['names']['rules']=[]
                with self.assertRaisesRegex(ComponentError,'traffic-ingress'):m.bind(r,e,d)

    def test_plain_compiler_refuses_disabled_deferred_prerequisite_before_packet_admission(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import component_plan
        from test_component_traffic import composition
        spec,source=composition()
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();(root/'stack.json').write_text(json.dumps(spec))
            (root/'site.json').write_text(json.dumps(source))
            metadata={'deferred_routed_checks':{'resolver':{'name':'Check resolver web','needs':['resolver','other']}}}
            with patch.object(m,'bind',return_value=metadata),self.assertRaisesRegex(ComponentError,'disabled-dependency'):
                component_plan.resolve(root,root/'site.json',['other'])

    def test_legacy_unselected_routes_and_closed_definitions(self):
        r,e,d=fixture();r.guests['room'].pop('route_checks');e.resolved['web'].pop('check')
        self.assertEqual(m.bind(r,e,d),{})
        for value in (None,{}, {'type':'page'}, {'type':'page','contains':'x','unknown':True},
                      {'type':'page','contains':'x','path':'/../'}, {'type':'page','contains':'x\n'},
                      {'type':'auth-redirect','provider':{'wrong':'web'}}, {'type':'auth-redirect','provider':'idp'}):
            with self.subTest(value=value),self.assertRaises(ValueError):m.check_definition(value)
        for value in (None,{}, {'mode':'automatic','source':{}}, {'mode':'inline','source':{'address_group':'runner'}},
                      {'mode':'deferred','source':{'address_group':'runner'},'name':'${{ injected }}'}):
            with self.subTest(value=value),self.assertRaises(ValueError):m.guest_definition(value)
        m.check_definition({'type':'auth-redirect','path':'/login','provider':{'exposure':'idp','domain':'idp'}})


class CompleteRouteExampleTests(unittest.TestCase):
    def test_actual_complete_example_compiles_and_binds_real_guest_packet(self):
        import importlib.util,json
        from pathlib import Path
        from unittest.mock import patch
        root=Path(__file__).resolve().parents[1]
        spec=importlib.util.spec_from_file_location('route_example_compiler',root/'blueprints/compile.py')
        c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
        source=root/'docs/examples/route-checks'
        with patch('socket.create_connection',side_effect=AssertionError('No target traffic')):
            plan=c.resolve_plan(source,source/'site.yaml')
            packet=c.lower_plan(plan)['resolver']
        config=json.loads(packet['files']['site.json'])
        self.assertEqual(config['app']['route_checks']['mode'],'inline')
        self.assertEqual(config['app']['route_checks']['rows'][0]['auth_origins'],['https://idp.example.invalid'])
        self.assertEqual(plan.resolved['guest_dependencies'],{'resolver':[]})
