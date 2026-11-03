"""Typed declared bindings preserve old text and proof contracts."""
import copy
from pathlib import Path
import unittest
import compile as c
import test_packets


class SiteBindingTests(unittest.TestCase):
    def test_whole_scalar_nullable_and_list_keep_types_without_embedded_coercion(self):
        declared={'vmid':'integer','name':'string','vlan':['integer','null'],'keys':'string-list'}
        values={'vmid':207,'name':'service','vlan':None,'keys':['ssh-ed25519 fixture']}
        original=copy.deepcopy(values)
        self.assertEqual(c.substitute({'x':['${vmid}','${name}','${vlan}','${keys}','${inputs}']},values,declared),
                         {'x':[207,'service',None,['ssh-ed25519 fixture'],'${inputs}']})
        self.assertEqual(c.substitute('${name}-${vmid}',values,declared),'service-207')
        self.assertEqual(c.substitute('${vmid}',values),'207')
        for text in ('prefix${keys}','${vlan}/24','${absent}'):
            with self.subTest(text=text),self.assertRaises(ValueError):c.substitute(text,values,declared)
        with self.assertRaises(ValueError):c.substitute('${vmid}',dict(values,vmid=True),declared)
        self.assertEqual(values,original)

    def test_declared_types_are_closed_and_explicit_at_admission(self):
        valid={'a':'integer','b':'string','c':['integer','null'],'d':'string-list'}
        values={'a':216,'b':'service','c':None,'d':['one','two']}
        spec={'values':values,'required_site_bindings':valid}
        self.assertEqual(c.validate_site_bindings(spec,{'values':{}},admit=False),valid)
        self.assertEqual(c.validate_site_bindings(spec,{'values':values},admit=True),valid)
        with self.assertRaisesRegex(ValueError,'explicit consumer'):c.validate_site_bindings(spec,{'values':{}},admit=True)
        for kind,items in [('integer',[True,None,1.0,'2']),('string',['',None,2]),('string-list',[[],[''],['ok',3],{},'a']),(['integer','null'],[True,2.0,'3'])]:
            for value in items:
                with self.subTest(kind=kind,value=value),self.assertRaises(ValueError):
                    c.validate_site_bindings({'values':{},'required_site_bindings':{'x':kind}},{'values':{'x':value}},admit=False)
        with self.assertRaises(ValueError):c.validate_site_bindings({'values':{},'required_site_bindings':{'x':'string'}},{'values':{}},admit=False)
        for declaration in ([],{str(i):'string' for i in range(513)}, {'inputs':'string'}, {'Bad':'string'},{'x':'bool'},{'x':{}},{'x':['null','integer']},{'x':'object'},{'x'*161:'string'}):
            with self.subTest(declaration=declaration),self.assertRaises(ValueError):c.binding_declarations({'required_site_bindings':declaration})
        self.assertEqual(c.binding_declarations({}),{})

    def test_only_declared_semantic_examples_refuse_live_admission(self):
        for key,value in [('addresses.web','192.0.2.5'),('networks.management',['203.0.113.0/24']),
                          ('gateways.x','198.51.100.1'),('interfaces.dns.0.ipv4_endpoint','198.18.2.1/24'),
                          ('interfaces.a.0.ipv4','2001:db8::1/64'),('domains.ui','UI.EXAMPLE.COM.'),
                          ('hostnames.db','db.example.invalid')]:
            kind='string-list' if isinstance(value,list) else 'string'
            spec={'values':{},'required_site_bindings':{key:kind}};overlay={'values':{key:value}}
            self.assertTrue(c.synthetic_binding(key,value))
            c.validate_site_bindings(spec,overlay,admit=False)
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'synthetic'):c.validate_site_bindings(spec,overlay,admit=True)
        for key,value in [('proof.original','example.invalid'),('vmids.db',202),('addresses.db','10.44.3.21'),
                          ('networks.any','0.0.0.0/0'),('interfaces.db.0.ipv4','manual'),('interfaces.dns.0.ipv4','dhcp'),
                          ('networks.bad','not-a-cidr'),('networks.optional',None),('domains.real','ui.service.company'),('hostnames.short','db')]:
            self.assertFalse(c.synthetic_binding(key,value),(key,value))

    def test_two_distinct_synthetic_sites_compile_typed_allocations_and_keep_proof_text(self):
        fixture=test_packets.PacketTests()
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        spec=c.read(fixture.root/'stack.json')
        spec['required_site_bindings']={'vmids.dns':'integer','addresses.dns':'string','prefixes.management':'integer','ssh.keys':'string-list'}
        fixture.save('stack.json',spec)
        profile=c.read(fixture.root/'guests/dns/profile.json')
        profile['config']['guest']['vmid']='${vmids.dns}'
        profile['config']['app']['vmid']='${vmids.dns}'
        profile['config']['guest']['interfaces'][0]['ipv4']='${addresses.dns}/${prefixes.management}'
        profile['config']['app']['address']='${addresses.dns}'
        profile['config']['ssh_public_keys']='${ssh.keys}'
        fixture.save('guests/dns/profile.json',profile)
        outputs=[]
        for vmid,address,prefix in [(1701,'198.18.25.8',24),(2701,'198.19.25.8',27)]:
            overlay=copy.deepcopy(fixture.overlay)
            overlay['values']={'vmids.dns':vmid,'addresses.dns':address,'prefixes.management':prefix,'ssh.keys':['ssh-ed25519 '+ 'A'*68]}
            # Avoid a fixture-only static Compose backend owned by the other example;
            # this test exercises real guest resolution and type/semantic receivers.
            cfg,stack,files=c._resolve_guest(fixture.root,overlay,'dns',spec)
            self.assertIs(type(cfg['guest']['vmid']),int)
            self.assertEqual(cfg['guest']['interfaces'][0]['ipv4'],f'{address}/{prefix}')
            self.assertEqual(files['settings.txt'],'fixture.invalid\n${inputs}/retained')
            outputs.append(cfg)
        self.assertNotEqual(outputs[0]['guest']['vmid'],outputs[1]['guest']['vmid'])
        self.assertNotEqual(outputs[0]['guest']['interfaces'],outputs[1]['guest']['interfaces'])
