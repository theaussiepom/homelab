"""Direct traffic matcher negatives and real compiler admission propagation."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import component_plan
import component_traffic as traffic
from component_errors import ComponentError
from test_component_plan import library,site


def rule(direction='out',protocol='tcp',port='5335',**fields):
    return {'direction':direction,'proto':protocol,'port':port,
        'source':'198.18.21.10/32','destination':'198.18.21.11/32','comment':'Synthetic explicit DNS',**fields}


def composition():
    spec=library();source=site();profile=spec['app_profiles']['recursive']
    profile['interfaces']['web']={'required':True,'accepts':['guest-interface']}
    profile['listeners']['udp']['publish']={'scope':'guest-interface','interface':'web','port':5335}
    profile['endpoints']['dns']['via']='web'
    profile['connections']={'upstream':{'type':'dns','required':False,'readiness':[]}}
    source['apps']['recursive_a']['interfaces']['web']={'interface':'backend'}
    guest=copy.deepcopy(source['guests']['resolver']);guest['identity']={'vmid':611,'hostname':'other-dns'}
    for row in guest['interfaces'].values():
        row['mac']=row['mac'][:-2]+'11';row['address']['value']=row['address']['value'][:-2]+'11'
    source['guests']['other']=guest
    source['apps']['other']=copy.deepcopy(source['apps']['recursive_a']);source['apps']['other']['guest']='other'
    source['connections']={'upstream':{'consumer':{'app':'recursive_a','connection':'upstream'},
        'target':{'app':'other','endpoint':'dns'},'source_interface':'web'}}
    source['policies']={'network':{direction:{'rules':[
        rule(direction,protocol,interface='wire')for protocol in ('tcp','udp')]}
        for direction in ('out','in')}}
    for guest_id,direction in [('resolver','out'),('other','in')]:
        source['guests'][guest_id]['network_policy']=[{'policy':direction,'interfaces':{'wire':'backend'}}]
    return spec,source


class TrafficMatcherTests(unittest.TestCase):
    def test_hostname_route_projects_only_the_unique_default_source_and_explicit_egress(self):
        guest={'context':'lab','provider_interfaces':[{'ipv4':'198.18.21.10/24','gateway':'198.18.21.1'}],
               'rules':[rule(port='443',destination='0.0.0.0/0')]}
        resolver=SimpleNamespace(guests={'proxy':guest},apps={'edge':{'guest':'proxy','resolved_connections':{}}},
            site={'guests':{'proxy':{}},'contexts':{'lab':{'dns_servers':[]}}})
        exposure=SimpleNamespace(routes={'edge':{'remote':{'target':{
            'address':'backend.example.invalid','protocol':'https','port':443}}}},middlewares={})
        with patch('socket.getaddrinfo',side_effect=AssertionError('No DNS lookup')):
            traffic.bind(resolver,exposure)
            guest['rules'][0]['destination']='192.0.2.0/24'
            with self.assertRaisesRegex(ComponentError,'traffic-egress'):traffic.bind(resolver,exposure)
            guest['rules'][0]['destination']='0.0.0.0/0'
            guest['provider_interfaces'][0].pop('gateway')
            with self.assertRaisesRegex(ComponentError,'traffic-source'):traffic.bind(resolver,exposure)
            guest['provider_interfaces'][0].update(ipv4='dhcp',ipv4_endpoint='198.18.21.10/24',gateway=None)
            traffic.bind(resolver,exposure)
            guest['provider_interfaces'].append({'ipv4':'198.18.22.10/24','gateway':'198.18.22.1'})
            with self.assertRaisesRegex(ComponentError,'traffic-source'):traffic.bind(resolver,exposure)

    def test_http_and_authenticated_internal_routes_keep_real_egress_without_dashboard_socket(self):
        def guest(address):
            return {'context':'lab','provider_interfaces':[{'ipv4':address+'/24','gateway':'198.18.21.1'}]}
        resolver=SimpleNamespace(guests={'ingress':guest('198.18.21.10'),'backend':guest('198.18.21.11')},
            apps={'proxy':{'guest':'ingress','resolved_connections':{}}},
            site={'guests':{'ingress':{},'backend':{}},'contexts':{'lab':{'dns_servers':[]}}})
        target={'guest':'backend','address':'198.18.21.11','port':9000,'protocol':'http'}
        exposure=SimpleNamespace(routes={'proxy':{
            'web':{'target':target,'middlewares':['login']},
            'dashboard':{'target':{'internal':'dashboard'},'middlewares':['login']}}},
            middlewares={'login':{'type':'forward-auth','target':target}})
        with patch.object(traffic,'check')as check:
            traffic.bind(resolver,exposure)
        self.assertEqual(check.call_count,3) # web + its auth + dashboard auth.
        self.assertTrue(all(call.args[1:]==('ingress','backend','198.18.21.10','198.18.21.11','tcp',9000)
                            for call in check.call_args_list))

    def test_network_port_ranges_lists_null_and_local_interface_are_explicit(self):
        flow=traffic.Flow('198.18.21.10','198.18.21.11','tcp',5335)
        for port in ('5335','53,5335','5300:5400',None):
            self.assertTrue(traffic.permits([rule(port=port,interface='net1')],'out',flow,'net1'))
        for change in ({'direction':'in'},{'proto':'udp'},{'port':'5336'},{'port':'53,5336'},
                       {'port':'1:5334'},{'interface':'net0'},{'source':'198.18.20.0/24'},
                       {'destination':'198.18.22.11/32'}):
            with self.subTest(change=change):
                self.assertFalse(traffic.permits([rule(**change)],'out',flow,'net1'))
        for port in ('0','1:65536','5335,','garbage',1,'5000:4000'):
            with self.subTest(port=port),self.assertRaises(ComponentError):
                traffic.permits([rule(port=port)],'out',flow,'net1')
        self.assertTrue(traffic.permits([rule(source=None,destination=None)],'out',flow,'net1'))

    def test_external_hostname_has_no_resolution_or_inferred_narrow_destination_grant(self):
        flow=traffic.Flow('198.18.21.10','broker.example.invalid','tcp',5335)
        self.assertFalse(traffic.permits([rule()],'out',flow,'net1'))
        self.assertTrue(traffic.permits([rule(destination='0.0.0.0/0')],'out',flow,'net1'))

    def test_physical_interface_resolution_uses_qualified_dhcp_and_rejects_ambiguity(self):
        guest={'provider_interfaces':[{'ipv4':'manual'},{'ipv4':'dhcp','ipv4_endpoint':'198.18.21.10/24'}]}
        self.assertEqual(traffic.nic(guest,'198.18.21.10'),'net1')
        for change in ('missing','duplicate'):
            value=copy.deepcopy(guest)
            if change=='duplicate':value['provider_interfaces'].append(value['provider_interfaces'][1])
            with self.subTest(change=change),self.assertRaisesRegex(ComponentError,'traffic-interface'):
                traffic.nic(value,'198.18.21.12'if change=='missing'else'198.18.21.10')

    def test_intra_guest_connections_do_not_add_grants_or_inspect_guest_firewalls(self):
        with patch.object(traffic,'permits',side_effect=AssertionError('No inferred guest grant')):
            traffic.check({},'same','same','127.0.0.1','127.0.0.1','tcp',5335)


class TrafficCompilerTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.spec,self.source=composition()

    def resolve(self):
        (self.root/'stack.json').write_text(json.dumps(self.spec))
        (self.root/'site.json').write_text(json.dumps(self.source))
        return component_plan.resolve(self.root,self.root/'site.json')

    def test_real_typed_connection_requires_both_guest_firewalls_and_both_dns_transports(self):
        before=copy.deepcopy(self.source)
        with patch('socket.getaddrinfo',side_effect=AssertionError('No DNS calls')):
            plan=self.resolve()
        self.assertEqual(self.source,before)
        self.assertEqual([row['proto']for row in plan.resolved['guests']['resolver']['rules']],['tcp','udp'])
        self.assertEqual(plan.resolved['guest_dependencies'],{'resolver':[],'other':[]})
        for direction in ('out','in'):
            original=self.source['policies']['network'][direction]['rules']
            guest='resolver'if direction=='out'else'other'
            binding=self.source['guests'][guest]['network_policy'][0]
            for selected in ([],original[:1],original[1:]):
                self.source['policies']['network'][direction]['rules']=selected
                binding['interfaces']={'wire':'backend'}if selected else{}
                with self.subTest(direction=direction,count=len(selected)),self.assertRaisesRegex(ComponentError,'traffic-'):
                    self.resolve()
            self.source['policies']['network'][direction]['rules']=original
            binding['interfaces']={'wire':'backend'}

    def test_wrong_source_target_protocol_port_or_interface_refuses_with_safe_component_path(self):
        for field,value in [('source','198.18.22.0/24'),('destination','198.18.23.0/24'),
                            ('proto','tcp'),('port','5336'),('interface','wrong')]:
            self.spec,self.source=composition()
            if field=='interface':
                self.source['guests']['resolver']['network_policy'][0]['interfaces']['wire']='management'
            else:
                self.source['policies']['network']['out']['rules'][1][field]=value
            with self.subTest(field=field),self.assertRaises(ComponentError)as caught:self.resolve()
            self.assertIn('apps.recursive_a.connections.upstream',str(caught.exception))
            self.assertNotIn('198.18.',str(caught.exception))

    def test_preparation_uses_the_explicit_control_interface_and_value_refs_create_no_waits(self):
        self.source['connections']={}
        plan=self.resolve();self.assertEqual(plan.resolved['guest_dependencies'],{'resolver':[],'other':[]})
        self.source['guests']['resolver']['readiness']=[{'stage':'preparation','target':{'app':'other','endpoint':'dns'}}]
        with self.assertRaisesRegex(ComponentError,'traffic-egress at guests.resolver.readiness'):self.resolve()
        for direction in ('out','in'):
            for row in self.source['policies']['network'][direction]['rules']:row['source']='198.18.20.10/32'
        self.source['guests']['resolver']['network_policy'][0]['interfaces']['wire']='management'
        plan=self.resolve();self.assertEqual(plan.resolved['guest_dependencies']['resolver'],['other'])


if __name__=='__main__':unittest.main()
