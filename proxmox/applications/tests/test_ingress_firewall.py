"""Firewall-only successor planning; no native target in these fixtures."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ingress_firewall as firewall
import database_network_maintenance as m
import test_database_network_maintenance as fixture


def guest():
    value=fixture.cfg()['guest'];value.update(vmid=212,hostname='proxy')
    value['interfaces'] += [dict(bridge='vmbr1',vlan=40,mac='02:88:40:00:02:12',ipv4='10.88.40.33/24',ipv6='manual'),
                           dict(bridge='vmbr33',vlan=None,mac='02:88:33:00:02:12',ipv4='10.88.33.33/24',ipv6='manual')]
    return value


def policy():
    return dict(schema=firewall.POLICY_SCHEMA,vmid=212,rules=[dict(source='10.88.30.23',destination='10.88.30.35',port=8080)],
        baseline={'state_sha256':'1'*64,'state_lineage':'accepted','state_serial':3,
            'network_overlay':{'path':'/var/lib/homelab-applications/212/database-network-apply-'+'a'*64+'/overlay.json','sha256':'2'*64},
            'network_plan_directory':'database-network-plan-accepted',
            'catalogue':{'path':'/var/lib/homelab-applications/212/accepted-catalogue.json','sha256':'3'*64},
            'acme':{'path':'/var/lib/homelab-applications/212/ingress-acme-network-baseline.json','sha256':'4'*64},
            'browser_packet_sha256':'5'*64})


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.guest=guest();self.policy=policy()
        self.candidate=firewall.candidate(self.guest,self.policy)
        before={m.CONTAINER:fixture.raw_container(self.guest),m.OPTIONS:{'container_id':212,'node_name':'pve-test'},
                m.RULES:fixture.raw_rules(self.guest)}
        self.before=before
        self.plan={'resource_changes':[{'address':name,'change':{'actions':['no-op'],'before':value,
            'after':copy.deepcopy(value),'after_unknown':{}}} for name,value in before.items()]}
        row=self.plan['resource_changes'][-1]['change'];row['actions']=['update']
        row['after']['rule'].extend(firewall.provider_rules(before[m.RULES]['rule'],self.policy))

    def test_candidate_appends_one_source_bound_rule_preserving_four_nics_and_every_old_rule(self):
        self.assertEqual(self.candidate['interfaces'],self.guest['interfaces'])
        self.assertEqual(self.candidate['rules'][:-1],self.guest['rules'])
        self.assertEqual(self.candidate['rules'][-1],{'direction':'out','proto':'tcp','port':'8080',
            'source':'10.88.30.23/32','destination':'10.88.30.35/32','comment':'Selected ingress backend'})
        firewall.check_plan(self.plan,'pve-test',self.guest,self.policy,self.before)

    def test_two_reviewed_rules_derive_distinct_existing_sources_in_one_exact_append(self):
        self.policy['rules'].append(dict(source='10.88.25.23',destination='10.88.25.34',port=5000))
        selected=firewall.candidate(self.guest,self.policy)
        self.assertEqual(selected['interfaces'],self.guest['interfaces'])
        self.assertEqual([r['port'] for r in selected['rules'][-2:]],['8080','5000'])
        self.assertEqual([r['source'] for r in selected['rules'][-2:]],['10.88.30.23/32','10.88.25.23/32'])
        value=copy.deepcopy(self.plan)
        value['resource_changes'][-1]['change']['after']['rule']=copy.deepcopy(self.before[m.RULES]['rule'])+firewall.provider_rules(self.before[m.RULES]['rule'],self.policy)
        firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)
        self.policy['rules'].append(dict(source='10.88.25.23',destination='10.88.25.35',port=22))
        with self.assertRaises(ValueError):firewall.candidate(self.guest,self.policy)

    def native_defaults_plan(self):
        self.policy['rules'].append(dict(source='10.88.25.23',destination='10.88.25.34',port=5000))
        value=copy.deepcopy(self.plan)
        before=value['resource_changes'][-1]['change']['before']
        for index,row in enumerate(before['rule']):
            row.update(pos=index,**{name:'' for name in ('sport','iface','macro','log','security_group')})
        self.before[m.RULES]=copy.deepcopy(before)
        fixture=Path(__file__).with_name('fixtures')/'ingress-egress-bpg-added-rules.json'
        added=json.loads(fixture.read_text())
        value['resource_changes'][-1]['change']['after']['rule']=copy.deepcopy(before['rule'])+added
        return value

    def test_native_bpg_null_added_defaults_match_the_ordinary_existing_rule_defaults(self):
        # Captured BPG plan shape, with only deployment addresses substituted.
        value=self.native_defaults_plan()
        firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)

    def test_native_shape_still_rejects_logging_interface_extra_fields_and_old_rule_changes(self):
        original=self.native_defaults_plan()
        for key,bad in [('log','info'),('log','nolog'),('iface','eth1'),('macro','SSH'),('sport','22'),
                        ('security_group','broader'),('enabled',1),('unexpected',None),('pos',999),
                        ('source','0.0.0.0/0'),('dest','0.0.0.0/0'),('dport','8080,5000')]:
            value=copy.deepcopy(original);value['resource_changes'][-1]['change']['after']['rule'][-1][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):
                firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)
        value=copy.deepcopy(original);value['resource_changes'][-1]['change']['after']['rule'][0]['log']=None
        with self.assertRaises(ValueError):firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)

    def test_scope_refuses_other_source_subnet_destination_or_fifth_nic(self):
        for key,bad in [('source','10.88.40.33'),('destination','10.88.31.35'),('destination','0.0.0.0'),('port',True)]:
            # The source must be on the installed backend interface, never the frontend.
            row=copy.deepcopy(self.policy);row['rules'][0][key]=bad
            with self.subTest(key=key,bad=bad),self.assertRaises(ValueError):firewall.candidate(self.guest,row)
        changed=copy.deepcopy(self.guest);changed['interfaces'].append(copy.deepcopy(changed['interfaces'][-1]))
        with self.assertRaises(ValueError):firewall.candidate(changed,self.policy)

    def test_saved_plan_refuses_container_options_old_rule_or_extra_authority(self):
        for edit in [lambda p:p['resource_changes'][0]['change']['after'].update(description='changed'),
                     lambda p:p['resource_changes'][1]['change']['after'].update(enabled=False),
                     lambda p:p['resource_changes'][2]['change']['after']['rule'][0].update(comment='changed'),
                     lambda p:p['resource_changes'][2]['change']['after']['rule'][-1].update(dport='8080,5000'),
                     lambda p:p['resource_changes'][2]['change']['after']['rule'][-1].update(source=''),
                     lambda p:p['resource_changes'][2]['change']['after']['rule'][-1].update(iface='eth1'),
                     lambda p:p['resource_changes'][0]['change'].update(actions=['update'])]:
            value=copy.deepcopy(self.plan);edit(value)
            with self.subTest(edit=edit),self.assertRaises(ValueError):firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)

    def test_unknown_drift_replace_or_missing_resource_refuses(self):
        for edit in [lambda p:p['resource_changes'].pop(),
                     lambda p:p['resource_changes'][2]['change'].update(after_unknown={'rule':True}),
                     lambda p:p['resource_changes'][2]['change'].update(replace_paths=[['rule']]),
                     lambda p:p.update(resource_drift=[{'address':'other'}])]:
            value=copy.deepcopy(self.plan);edit(value)
            with self.assertRaises(ValueError):firewall.check_plan(value,'pve-test',self.guest,self.policy,self.before)


import json
from unittest.mock import patch
import database_network_apply as driver
import ingress_network_baseline as baseline
import ingress_browser as browser
import test_ingress_network_baseline as ancestry
from test_component_browser import update_packet


class SavedPlanTests(unittest.TestCase):
    put=ancestry.BaselineTests.put
    plan_value=ancestry.BaselineTests.plan_value
    fake_tofu=ancestry.BaselineTests.fake_tofu
    prepare=ancestry.BaselineTests.prepare

    def setUp(self):
        ancestry.BaselineTests.setUp(self)
        review=self.prepare();old_plan,new_guest=self.plan_value()
        values={r['address']:r['change']['after'] for r in old_plan['resource_changes']}
        state_raw=ancestry.state(values,3);(self.work/'terraform.tfstate').write_bytes(state_raw)
        request=json.loads((self.evidence/'request.json').read_bytes())
        old_packet={'schema':driver.SCHEMA,'vmid':212,'request_sha256':m.digest((self.evidence/'request.json').read_bytes()),
            'review_packet_sha256':m.digest((self.evidence/'review-packet.json').read_bytes()),
            'apply_helper_sha256':m.digest(Path(driver.__file__).read_bytes()),'allow_guest_restart':True}
        operation=self.work/('database-network-apply-'+old_packet['review_packet_sha256'])
        overlay={'schema':driver.OVERLAY_SCHEMA,'status':'network_overlay_verified','vmid':212,
            'packet_sha256':m.digest(m.encoded(old_packet)),'request_sha256':old_packet['request_sha256'],
            'review_packet_sha256':old_packet['review_packet_sha256'],'candidate_guest_sha256':review['candidate_guest_sha256'],
            'original':request['original'],'state_sha256':m.digest(state_raw),'state_lineage':'original-ingress-lineage','state_serial':3}
        for base in (operation,self.nas/operation.name):
            self.put(base/'overlay.json',overlay);self.put(base/'claim.json',old_packet);self.put(base/'state-after.json',state_raw)
        original=b'{"http":{}}';route=update_packet(original,212)
        route['policy_evidence']['path']=str(self.work/'admission/policy.json')
        route.update(state_sha256=m.digest(state_raw),network_evidence={'path':str(operation/'overlay.json'),'sha256':m.digest(m.encoded(overlay))})
        for path in (self.work/'influx-browser-route/claim.json',self.work/'influx-browser-route/complete.json',
                     self.nas/'influx-browser-claim.json',self.nas/'influx-browser-complete.json'):self.put(path,route)
        self.put(self.nas/'influx-browser-shared-before.json',original)
        self.enterContext(patch.object(browser,'EVIDENCE_ROOT',self.state))
        catalogue=self.put(self.work/'accepted-catalogue.json',self.catalogue_path.read_bytes())
        self.target=policy();self.target['baseline'].update(state_sha256=m.digest(state_raw),state_lineage='original-ingress-lineage',
            network_overlay=route['network_evidence'],network_plan_directory=self.evidence.name,
            catalogue={'path':str(catalogue),'sha256':m.digest(catalogue.read_bytes())},acme=self.reference,
            browser_packet_sha256=m.digest(m.encoded(route)))
        self.policy_path=self.put(self.root/'firewall-policy.json',self.target)
        self.old_plan=self.evidence;self.evidence=self.work/'database-network-plan-firewall'
        self.guest=new_guest;self.accepted_values=values;self.calls=[]
        self.protected={p:p.read_bytes() for p in self.work.rglob('*') if p.is_file()}

    def firewall_plan(self):
        rows=[]
        for address,before in self.accepted_values.items():
            after=copy.deepcopy(before)
            if address==m.RULES:after['rule'].extend(firewall.provider_rules(before['rule'],self.target))
            rows.append({'address':address,'change':{'actions':['update'] if address==m.RULES else ['no-op'],
                'before':copy.deepcopy(before),'after':after,'after_unknown':{},'replace_paths':[]}})
        return {'resource_changes':rows}

    def native(self,command,environment,log,output=None):
        self.calls.append(command);value=self.firewall_plan()
        if 'apply' in command:
            values={r['address']:r['change']['after'] for r in value['resource_changes']}
            (self.work/'terraform.tfstate').write_bytes(ancestry.state(values,4))
        if 'plan' in command:
            path=Path(next(c.split('=',1)[1] for c in command if c.startswith('-out=')))
            m.write_new(path,b'SYNTHETIC_SAVED_FIREWALL_PLAN')
        if output:
            if 'check.tfplan' in command[-1]:
                for row in value['resource_changes']:
                    row['change']['before']=copy.deepcopy(row['change']['after']);row['change']['actions']=['no-op']
            m.write_new(output,m.encoded(value))

    def prepared(self):
        with patch.object(m,'tofu',side_effect=self.native):
            result=firewall.plan(self.deployment,self.site,self.policy_path,self.evidence)
        selected={'schema':firewall.APPLY_SCHEMA,'vmid':212,'request_sha256':m.digest((self.evidence/'request.json').read_bytes()),
            'review_packet_sha256':m.digest((self.evidence/'review-packet.json').read_bytes()),
            'apply_helper_sha256':m.digest(Path(driver.__file__).read_bytes()),'allow_guest_restart':False}
        path=self.put(self.root/'firewall-apply.json',selected)
        return result,(self.deployment,self.site,self.policy_path,self.evidence,path,m.digest(path.read_bytes()))

    def test_readonly_plan_uses_accepted_four_nic_guest_not_original_three_nic_inputs(self):
        result,args=self.prepared()
        self.assertEqual(result['schema'],firewall.PLAN_SCHEMA)
        self.assertFalse(result['apply_supported']);self.assertFalse(any('apply' in c for c in self.calls))
        candidate=json.loads((self.evidence/'candidate-guest.json').read_bytes())
        self.assertEqual(candidate['interfaces'],self.guest['interfaces']);self.assertEqual(len(candidate['interfaces']),4)
        for path,raw in self.protected.items():self.assertEqual(path.read_bytes(),raw)
        driver.admission(self.deployment,driver.load(*args))
        self.deployment.execute.assert_not_called()

    def test_existing_driver_applies_exact_saved_firewall_once_and_keeps_ancestry_and_nas(self):
        _,args=self.prepared();self.calls.clear();self.deployment.quiet.reset_mock()
        with patch.object(m,'tofu',side_effect=self.native):
            result=driver.apply(*args)
            with self.assertRaises(ValueError):driver.apply(*args)
        self.assertEqual(result['status'],'network_overlay_verified');self.assertEqual(result['state_serial'],4)
        self.assertEqual(sum('apply' in c for c in self.calls),1)
        self.assertEqual(sum('plan' in c for c in self.calls),1)
        self.deployment.quiet.assert_not_called();self.deployment.execute.assert_not_called()
        for path,raw in self.protected.items():
            if path.name!='terraform.tfstate':self.assertEqual(path.read_bytes(),raw)
        operation=self.work/('database-network-apply-'+json.loads(args[-2].read_bytes())['review_packet_sha256'])
        for path in operation.iterdir():
            if path.is_file() and path.name not in ('apply.log','admitted-plan.json'):
                self.assertEqual(path.read_bytes(),(self.nas/operation.name/path.name).read_bytes())
        self.assertFalse((self.work/'HOLD.json').exists())

    def test_combined_two_rule_saved_plan_uses_one_existing_driver_apply(self):
        self.target['rules'].append(dict(source='10.88.25.23',destination='10.88.25.34',port=5000))
        self.policy_path.write_bytes(m.encoded(self.target));_,args=self.prepared();self.calls.clear()
        with patch.object(m,'tofu',side_effect=self.native):driver.apply(*args)
        self.assertEqual(sum('apply' in c for c in self.calls),1)
        selected=json.loads((self.evidence/'candidate-guest.json').read_bytes())
        self.assertEqual([r['port'] for r in selected['rules'][-2:]],['8080','5000'])
        self.assertEqual(len(selected['interfaces']),4)

    def test_missing_route_nas_or_changed_network_ancestry_refuses_before_native_commands(self):
        for path in (self.nas/'influx-browser-complete.json',self.old_plan/'candidate-guest.json',
                     Path(self.target['baseline']['network_overlay']['path']),self.work/'terraform.tfstate'):
            raw=path.read_bytes();path.write_bytes(raw+b' ')
            with patch.object(m,'tofu') as native,self.subTest(path=path),self.assertRaises(ValueError):
                firewall.plan(self.deployment,self.site,self.policy_path,self.evidence)
            native.assert_not_called();path.write_bytes(raw)

    def test_apply_refuses_policy_binary_candidate_or_current_state_drift_before_claim(self):
        _,args=self.prepared()
        for path in (self.policy_path,self.evidence/'guest.tfplan',self.evidence/'candidate-guest.json',self.work/'terraform.tfstate'):
            raw=path.read_bytes();path.write_bytes(raw+b' ')
            with patch.object(m,'tofu') as native,self.subTest(path=path),self.assertRaises(ValueError):driver.apply(*args)
            native.assert_not_called();self.assertFalse((self.work/'HOLD.json').exists());path.write_bytes(raw)

    def test_rehashed_unrelated_saved_plan_still_fails_the_exact_scope_checker(self):
        _,args=self.prepared();shown=self.evidence/'guest.tfplan.json';value=json.loads(shown.read_bytes())
        value['resource_changes'][-1]['change']['after']['rule'][-1]['dport']='5000'
        shown.write_bytes(m.encoded(value));path=self.evidence/'review-packet.json';review=json.loads(path.read_bytes())
        review['plan_json_sha256']=m.digest(shown.read_bytes());path.write_bytes(m.encoded(review))
        packet=args[-2];selected=json.loads(packet.read_bytes());selected['review_packet_sha256']=m.digest(path.read_bytes())
        packet.write_bytes(m.encoded(selected));args=(*args[:-1],m.digest(packet.read_bytes()))
        with patch.object(m,'tofu') as native,self.assertRaises(ValueError):driver.apply(*args)
        native.assert_not_called();self.assertFalse((self.work/'HOLD.json').exists())

    def test_firewall_packet_cannot_grant_restart_or_select_a_different_guest(self):
        _,args=self.prepared();path=args[-2];original=json.loads(path.read_bytes())
        for key,bad in [('allow_guest_restart',True),('vmid',213)]:
            path.write_bytes(m.encoded({**original,key:bad}));argv=(*args[:-1],m.digest(path.read_bytes()))
            with patch.object(m,'tofu') as native,self.assertRaises(ValueError):driver.apply(*argv)
            native.assert_not_called();self.assertFalse((self.work/'HOLD.json').exists())

    def test_failure_hold_prevents_new_claim_or_replay_and_preserves_original_receipts(self):
        _,args=self.prepared();self.calls.clear()
        def fail(command,*rest,**kwargs):
            if 'apply' in command:raise RuntimeError('synthetic apply failure')
            return self.native(command,*rest,**kwargs)
        with patch.object(m,'tofu',side_effect=fail),self.assertRaises(RuntimeError):driver.apply(*args)
        self.assertTrue((self.work/'HOLD.json').is_file())
        with patch.object(m,'tofu') as native,self.assertRaises(ValueError):driver.apply(*args)
        native.assert_not_called()


if __name__=='__main__':unittest.main()
