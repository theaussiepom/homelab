"""Only the declared backend rule may be appended to an existing guest plan."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import firewall_append as policy

ADDITION={'direction':'out','proto':'tcp','port':'8123,1880','destination':'10.88.30.21/32','comment':'Selected automation backend'}


def fixture(completed=False):
    rows=[]
    for address,key in policy.RESOURCES.items():
        before={key:212,'node_name':'pve'}
        after=copy.deepcopy(before);actions=['no-op']
        if address==policy.RULES:
            before['rule']=[{'type':'out','action':'ACCEPT','proto':'udp','dport':'53','dest':'10.88.40.2/32'}]
            after['rule']=[*copy.deepcopy(before['rule']),*policy.provider_rules([ADDITION])]
            if completed:before=copy.deepcopy(after)
            else:actions=['update']
        rows.append({'address':address,'change':{'actions':actions,'before':before,'after':after,'after_unknown':{}}})
    return {'resource_changes':rows}


class FirewallAppend(unittest.TestCase):
    def test_append_and_completed_readback_accept_only_the_expected_rule(self):
        policy.check_plan(fixture(),'pve',212,[ADDITION])
        policy.check_plan(fixture(True),'pve',212,[ADDITION],True)

    def test_guest_changes_deletion_unknowns_and_wider_rule_are_refused(self):
        def guest_change(value):value['resource_changes'][0]['change']['after'].update(started=False)
        def delete(value):value['resource_changes'][0]['change'].update(actions=['delete'])
        def unknown(value):value['resource_changes'][0]['change']['after_unknown'].update(vm_id=True)
        def old_change(value):value['resource_changes'][2]['change']['after']['rule'][0]['dest']='0.0.0.0/0'
        def wider(value):value['resource_changes'][2]['change']['after']['rule'][-1]['dest']='10.88.30.0/24'
        def privilege(value):value['resource_changes'][2]['change']['after']['rule'][-1]['sport']='1:65535'
        for change in (guest_change,delete,unknown,old_change,wider,privilege):
            value=fixture();change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):policy.check_plan(value,'pve',212,[ADDITION])
        for destination in ('0.0.0.0/0','10.88.30.0/24','127.0.0.1/32','1.1.1.1/32',
                            '255.255.255.255/32','240.0.0.1/32','192.0.2.1/32','198.18.0.1/32'):
            with self.subTest(destination=destination),self.assertRaises(ValueError):
                policy.provider_rules([dict(ADDITION,destination=destination)])
