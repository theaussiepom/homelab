"""Known-example admission classification only; semantic validators own syntax."""
import copy
import unittest
from site_values import synthetic_binding


class SyntheticBindingTests(unittest.TestCase):
    def test_unrelated_metadata_is_not_mistaken_for_allocation_or_traffic(self):
        for key in ('images.vendor','notes.value','interfaces.control.mac','issuer.metadata'):
            with self.subTest(key=key):self.assertFalse(synthetic_binding(key,'example.invalid'))

    def test_named_address_gateway_network_and_interface_slots_detect_known_examples(self):
        for key in ('addresses.web','gateways.management','networks.clients','interfaces.control.ipv4',
                    'interfaces.control.ipv4_endpoint'):
            for value in ('192.0.2.1','198.51.100.20/24','203.0.113.0/24','198.18.10.1/24','2001:db8::1/64'):
                with self.subTest(key=key,value=value):self.assertTrue(synthetic_binding(key,value))

    def test_production_allocations_and_invalid_values_do_not_invent_semantic_acceptance(self):
        for value in ('10.44.1.2/24','192.168.9.9','172.20.1.1','2001:db9::1','8.8.8.8',
                      'manual','dhcp','not-an-address',None,False,1):
            with self.subTest(kind=type(value).__name__):self.assertFalse(synthetic_binding('addresses.web',value))

    def test_domain_suffix_case_and_trailing_dot_are_classified_without_rewriting_values(self):
        for suffix in ('example.com','example.net','example.org','example','invalid','test','localhost'):
            for value in (suffix,'app.'+suffix,('App.'+suffix).upper()+'.'):
                with self.subTest(value=value):self.assertTrue(synthetic_binding('domains.web',value))
        for value in ('app.company.internal','example.com.evil','notexample.org','localhost.evil'):
            self.assertFalse(synthetic_binding('hostnames.web',value))

    def test_list_scan_preserves_inputs_and_finds_later_examples(self):
        value=[None,'manual','10.44.1.1','203.0.113.8'];before=copy.deepcopy(value)
        self.assertTrue(synthetic_binding('networks.clients',value));self.assertEqual(value,before)
        self.assertFalse(synthetic_binding('networks.clients',[]))
        self.assertFalse(synthetic_binding('domains.web',[None,'app.company.internal']))


if __name__=='__main__':unittest.main()
