"""Direct value-graph units, mocked policy wiring and real source/packet parity."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import yaml

import component_addresses as addresses
import component_exposures
import component_packet
import component_plan
import component_sources
import component_types
import component_workflows
from component_errors import ComponentError
import test_component_packet as fixtures


class AddressGroupTests(unittest.TestCase):
    def test_ordered_network_and_group_members_preserve_duplicates_without_io(self):
        groups={'vpn':{'members':['198.18.15.0/24']},'clients':{'members':[
            {'network':'lan'},{'address_group':'vpn'},'198.18.50.1/32',{'address_group':'vpn'}]}}
        original=copy.deepcopy(groups)
        with patch('subprocess.run',side_effect=AssertionError('No process')), \
             patch('socket.create_connection',side_effect=AssertionError('No network')), \
             patch.object(Path,'open',side_effect=AssertionError('No source/private file read')):
            result=addresses.resolve(groups,{'lan':{'cidr':'198.18.20.0/24'}})
        self.assertEqual(result['clients'],['198.18.20.0/24','198.18.15.0/24','198.18.50.1/32','198.18.15.0/24'])
        selected=addresses.selected('clients',result);selected.clear()
        self.assertEqual(len(result['clients']),4);self.assertEqual(groups,original)
        self.assertEqual(addresses.resolve({},{}),{})

    def test_closed_group_member_shapes_types_ids_and_literal_addresses_refuse(self):
        values=[None,[],{}, {'members':None},{'members':[]},{'members':True},
            {'members':['198.18.0.1']*257},{'members':['198.18.0.1'],'extra':True}]
        members=[None,True,3,[],{}, {'network':'lan','address_group':'clients'},
            {'endpoint':'service'},{'interface':'management'},{'source':'arbitrary'},
            {'network':None},{'network':'../PRIVATE_SENTINEL'},{'address_group':'Bad'},
            '', '::g/128','999.0.0.1','198.18.0.1/99','PRIVATE_SENTINEL']
        values += [{'members':[v]}for v in members]
        for value in values:
            with self.subTest(value=value),self.assertRaises(ComponentError)as caught:addresses.group(value)
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
        for groups in ([],{'Bad':{'members':['198.18.0.1']}}, {'g'+str(n):{'members':['198.18.0.1']}for n in range(1025)}):
            with self.subTest(collection=type(groups).__name__),self.assertRaises(ComponentError):addresses.resolve(groups,{})

    def test_unknown_references_cycles_and_invalid_network_collaborators_refuse(self):
        cases=[({'g':{'members':[{'network':'unknown'}]}},{}),
            ({'g':{'members':[{'address_group':'unknown'}]}},{}),
            ({'g':{'members':[{'address_group':'g'}]}},{}),
            ({'a':{'members':[{'address_group':'b'}]},'b':{'members':[{'address_group':'a'}]}},{}),
            ({'unused':{'members':[{'address_group':'unused'}]},'used':{'members':['198.18.0.1']}},{}),
            ({'g':{'members':[{'network':'lan'}]}},{'lan':{}}),
            ({'g':{'members':[{'network':'lan'}]}},{'lan':{'cidr':'::1/128'}})]
        for groups,networks in cases:
            with self.subTest(groups=groups),self.assertRaises(ComponentError):addresses.resolve(groups,networks)
        for name in ('unknown','../PRIVATE_SENTINEL',None):
            with self.subTest(name=name),self.assertRaises(ComponentError):addresses.selected(name,{})

    def test_depth_member_and_total_limits_are_independent_of_map_order(self):
        def chain(count):
            return {'g'+str(n):{'members':[{'address_group':'g'+str(n+1)}]if n<count-1 else ['198.18.0.1']}
                    for n in range(count)}
        self.assertEqual(addresses.resolve(chain(64),{})['g0'],['198.18.0.1'])
        for groups in (chain(65),dict(reversed(list(chain(65).items())))):
            with self.subTest(order=list(groups)[:1]),self.assertRaisesRegex(ComponentError,'size'):addresses.resolve(groups,{})
        groups={'atom':{'members':['198.18.0.1']*256},'maximum':{'members':[{'address_group':'atom'}]*16}}
        self.assertEqual(len(addresses.resolve(groups,{})['maximum']),4096)
        groups['maximum']['members'].append({'address_group':'atom'})
        with self.assertRaisesRegex(ComponentError,'size'):addresses.resolve(groups,{})
        groups={'atom':{'members':['198.18.0.1']*256}}
        groups.update({'g'+str(n):{'members':[{'address_group':'atom'}]*16}for n in range(16)})
        with self.assertRaisesRegex(ComponentError,'size'):addresses.resolve(groups,{})


class PolicyGroupWiringTests(unittest.TestCase):
    def resolver(self,rule=None,binding=None):
        r=component_plan.Resolver.__new__(component_plan.Resolver)
        r.policy={'network':{'admin':{'rules':[rule or {'direction':'in','proto':'tcp','port':'443',
            'source':{'address_group':'clients'},'comment':'exact ordered source permission'}]}}}
        r.site={'networks':{}};r.address_groups={'trusted':['198.18.20.0/24','198.18.15.0/24'],
                                               'servers':['198.18.30.1/32','198.18.30.2/32','198.18.30.3/32']}
        r.endpoint=Mock(side_effect=AssertionError('No endpoint lookup for address values'))
        guest={'network_policy':[binding or {'policy':'admin','address_groups':{'clients':'trusted'}}],
               'interfaces':{},'interface_addresses':{},'context':'lab'}
        return r,guest

    def test_cartesian_rule_order_exact_fields_and_only_selected_group_dispatch(self):
        rule={'direction':'out','proto':'tcp','port':'443','source':{'address_group':'clients'},
              'destination':{'address_group':'backends'},'comment':'preserve literal comment'}
        r,g=self.resolver(rule,{'policy':'admin','address_groups':{'clients':'trusted','backends':'servers'}})
        with patch.object(addresses,'selected',wraps=addresses.selected)as selected:
            rows=r.policy_values(g)
        self.assertEqual(selected.call_count,2)
        self.assertEqual([(v['source'],v['destination'])for v in rows],[(a,b)for a in r.address_groups['trusted']for b in r.address_groups['servers']])
        self.assertTrue(all(v['comment']==rule['comment']and v['port']=='443'and v['proto']=='tcp'for v in rows))
        r.endpoint.assert_not_called()

    def test_missing_unknown_unused_roles_and_inbound_wildcard_refuse(self):
        for binding in ({'policy':'admin'},{'policy':'admin','address_groups':{'wrong':'trusted'}},
            {'policy':'admin','address_groups':{'clients':'missing'}},
            {'policy':'admin','address_groups':{'clients':'trusted','unused':'trusted'}}):
            r,g=self.resolver(binding=binding)
            with self.subTest(binding=binding),self.assertRaises(ComponentError):r.policy_values(g)
        r,g=self.resolver();r.address_groups['trusted']=['0.0.0.0/0']
        with self.assertRaises(ComponentError):r.policy_values(g)
        for row in ({'policy':'admin','address_groups':None},{'policy':'admin','address_groups':{'clients':'bad!'}},
                    {'policy':'admin','address_groups':{'clients':{'network':'lan'}}}):
            with self.subTest(binding=row),self.assertRaises(ComponentError):component_types.policy_binding(row)
        rule={'direction':'out','proto':'tcp','port':{'address_group':'clients'},'comment':'no group ports'}
        with self.assertRaises(ComponentError):component_types.network_policy({'rules':[rule]})

    def test_cartesian_and_cumulative_limits_refuse_before_variant_allocation(self):
        rule={'direction':'out','proto':'tcp','source':{'address_group':'clients'},
              'destination':{'address_group':'backends'},'comment':'bounded'}
        r,g=self.resolver(rule,{'policy':'admin','address_groups':{'clients':'trusted','backends':'servers'}})
        r.address_groups['trusted']=['198.18.20.0/24']*65;r.address_groups['servers']=['198.18.30.0/24']*64
        with patch.object(component_plan.itertools,'product',side_effect=AssertionError('Over-budget product must not start')):
            with self.assertRaisesRegex(ComponentError,'size'):r.policy_values(g)
        r,g=self.resolver();r.policy['network']['admin']['rules']*=3;r.address_groups['trusted']=['198.18.20.0/24']*2048
        with self.assertRaisesRegex(ComponentError,'size'):r.policy_values(g)

    def test_middleware_expands_exact_range_positions_without_endpoint_or_wait_effects(self):
        r=SimpleNamespace(site={'domains':{},'networks':{'lan':{'cidr':'198.18.20.0/24'}}},apps={},
            policy={'tls':{},'middlewares':{'allowed':{'type':'ip-allow-list',
                'ranges':['198.18.1.1/32',{'address_group':'vpn'},{'network':'lan'},{'address_group':'vpn'}]}}},
            address_groups={'vpn':['198.18.15.0/24']},endpoint=Mock(side_effect=AssertionError('No endpoint')))
        e=component_exposures.Exposures(r);e.validate_policies()
        self.assertEqual(e.middlewares['allowed']['ranges'],['198.18.1.1/32','198.18.15.0/24','198.18.20.0/24','198.18.15.0/24'])
        self.assertEqual((e.records,e.routes,e.resolved),({},{},{}));r.endpoint.assert_not_called()
        for ranges in ([{'address_group':'unknown'}],[{'address_group':'vpn','network':'lan'}],['198.18.1.1/32']*4097):
            r.policy['middlewares']['allowed']['ranges']=ranges
            with self.subTest(size=len(ranges)),self.assertRaises(ComponentError):component_exposures.Exposures(r).validate_policies()


class SourceGroupIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.case=fixtures.PacketIntegrationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)

    def split(self):
        for collection,kind in (('guests','guest'),('apps','app')):
            folder=self.case.consumer/collection;folder.mkdir()
            for name,value in list(self.case.site[collection].items()):
                path=folder/(name+'.yaml')
                path.write_text(yaml.safe_dump({'schema':component_sources.SCHEMA,'kind':kind,**value},sort_keys=False))
                self.case.site[collection][name]={'source':str(path.relative_to(self.case.consumer))}

    def test_fresh_and_retained_complete_typed_files_preserve_real_packets_and_workflows(self):
        for lifecycle in ('fresh','retained'):
            with self.subTest(lifecycle=lifecycle):
                if lifecycle=='retained':
                    self.case.doCleanups();self.case=fixtures.PacketIntegrationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
                    self.case.site['guests']['resolver']['lifecycle']='retained'
                    self.case.site['guests']['resolver']['compose_projects']={
                        'owned':{'name':'owned-resolver'}}
                    self.case.site['guests']['resolver']['root_paths']={
                        'config':{'path':'/srv/example/unbound/config'}}
                    self.case.spec['app_profiles']['recursive']['storage']={'config':{
                        'target':'/opt/unbound/etc/unbound','read_only':False,
                        'required':True,'kind':'directory'}}
                    self.case.site['apps']['recursive_a']['lifecycle']='retained'
                    self.case.site['apps']['recursive_a']['identity']={
                        'phase':'recursive_a','runtime_id':'recursive_a','project':'owned',
                        'services':{'unbound':'owned-unbound'},'networks':{'default':'default'}}
                    self.case.site['apps']['recursive_a']['storage']={
                        'config':{'root_path':'config','subpath':''}}
                before=self.case.resolve();packets=component_packet.lower_plan(before);model=component_workflows.model(before)
                self.split();after=self.case.resolve()
                self.assertEqual(component_packet.lower_plan(after),packets)
                self.assertEqual(component_workflows.model(after),model)
                self.assertEqual(set(after.pins['site']),{'site.json','guests/resolver.yaml','apps/recursive_a.yaml'})
                self.assertEqual(after.site['guests'],before.site['guests']);self.assertEqual(after.site['apps'],before.site['apps'])

    def test_wrong_kinds_headers_body_and_recursive_reference_refuse_real_compiler(self):
        self.split();path=self.case.consumer/'guests/resolver.yaml';original=path.read_text();doc=yaml.safe_load(original)
        cases=[dict(doc,kind='app'),dict(doc,schema='foreign'),{k:v for k,v in doc.items()if k!='schema'},
               {'schema':component_sources.SCHEMA,'kind':'guest','source':'guests/never-open.yaml'},dict(doc,unknown='PRIVATE_SENTINEL')]
        for value in cases:
            path.write_text(yaml.safe_dump(value))
            with self.subTest(keys=list(value)),self.assertRaises(ComponentError)as caught:self.case.resolve()
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
        path.write_text(original)
        self.case.site['guests']['resolver']['extra']='overlay'
        with self.assertRaises(ComponentError):self.case.resolve()

    def test_escaping_missing_symlinked_ambiguous_and_duplicate_key_files_refuse(self):
        self.split();path=self.case.consumer/'guests/resolver.yaml';original=path.read_text()
        for source in ('../escape.yaml','/absolute.yaml','guests/missing.yaml','guests/../resolver.yaml','guests//resolver.yaml'):
            self.case.site['guests']['resolver']={'source':source}
            with self.subTest(source=source),self.assertRaises(ComponentError):self.case.resolve()
        self.case.site['guests']['resolver']={'source':'guests/resolver.yaml'}
        path.unlink();path.symlink_to(self.case.stack/'stack.json')
        with self.assertRaises(ComponentError):self.case.resolve()
        path.unlink();path.write_text(original)
        sibling=path.with_suffix('.json');sibling.write_text('{}')
        with self.assertRaises(ComponentError):self.case.resolve()
        sibling.unlink();path.write_text('schema: homelab-components-v1\nkind: guest\nkind: guest\n')
        with self.assertRaises(ComponentError):self.case.resolve()

    def test_composed_facts_preserve_distinct_allowlists_and_literal_firewall_order(self):
        groups={'vpn':{'members':['198.18.15.0/28']}}
        for n in range(6):groups['atom'+str(n)]={'members':['198.18.'+str(30+n)+'.1/32']}
        atoms=[{'address_group':'atom'+str(n)}for n in range(6)]
        groups.update(selected={'members':[{'network':'primary'},{'address_group':'vpn'},{'network':'secondary'},*atoms[:4]]},
            management={'members':[{'network':'primary'},{'address_group':'vpn'},{'network':'secondary'}]},
            music={'members':[{'network':'secondary'},atoms[0],{'address_group':'vpn'},{'network':'primary'},*atoms[1:]]})
        expected=addresses.resolve(groups,self.case.site['networks'])
        self.assertEqual([len(expected[n])for n in ('selected','management','music')],[7,3,9])
        self.assertEqual(json.dumps(groups).count('198.18.15.0/28'),1)
        rule={'direction':'in','proto':'tcp','port':'443','comment':'same declared scope/order'}
        self.case.site['policies']={'network':{'admin':{'rules':[dict(rule,source=r)for r in expected['management']]}},
            'middlewares':{n:{'type':'ip-allow-list','ranges':expected[n]}for n in ('selected','management','music')}}
        self.case.site['guests']['resolver']['network_policy']=['admin']
        before=self.case.resolve();packet=component_packet.lower_plan(before);model=component_workflows.model(before)
        self.case.site['address_groups']=groups
        self.case.site['policies']['network']['admin']['rules']=[dict(rule,source={'address_group':'clients'})]
        self.case.site['guests']['resolver']['network_policy']=[{'policy':'admin','address_groups':{'clients':'management'}}]
        for n in ('selected','management','music'):self.case.site['policies']['middlewares'][n]['ranges']=[{'address_group':n}]
        after=self.case.resolve()
        self.assertEqual(after.resolved['address_groups'],expected)
        self.assertEqual(after.resolved['middlewares'],before.resolved['middlewares'])
        self.assertEqual(after.resolved['guests']['resolver']['rules'],before.resolved['guests']['resolver']['rules'])
        self.assertEqual(component_packet.lower_plan(after),packet);self.assertEqual(component_workflows.model(after),model)
        self.case.site['address_groups']['vpn']['members']=[{'address_group':'unknown'}]
        with self.assertRaises(ComponentError):self.case.resolve()


if __name__=='__main__':unittest.main()
