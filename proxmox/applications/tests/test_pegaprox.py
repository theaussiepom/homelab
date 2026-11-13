"""Current resolved PegaProx rendering preserves protocol and security floors."""
import copy
from pathlib import Path
import sys
import unittest

sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[3]/'blueprints')]
import component_runtime
import component_types
import component_properties
from container_policy import restart_policy
from component_pegaprox_fixture import descriptor,guest,service


class PegaProxTests(unittest.TestCase):
    def test_restart_defaults_and_explicit_policy_are_validated(self):
        self.assertEqual(service()['restart'],'always')
        # Configurable legacy stack.restart is retired; this live shared policy
        # primitive remains the renderer's authority and is tested directly.
        for policy in ('always','unless-stopped','no'):
            self.assertEqual(restart_policy({'restart':policy}),policy)
        for policy in (None,False,'sometimes',[],{}):
            with self.subTest(policy=policy),self.assertRaises(ValueError):restart_policy({'restart':policy})

    def test_current_stack_retains_key_path_and_does_not_create_empty_data(self):
        value=descriptor();rendered=component_runtime._pegaprox(value,guest())['pegaprox']
        self.assertEqual(rendered['image'],value['software_selection']['images']['pegaprox']['image'])
        self.assertEqual(rendered['ports'],['198.18.25.34:5000:5000/tcp'])
        self.assertTrue(all(row['bind']['create_host_path'] is False for row in rendered['volumes']))
        self.assertEqual(rendered['environment']['PEGAPROX_KEY_FILE'],'/run/secrets/pegaprox-db-key')
        self.assertEqual(rendered['restart'],'always')

    def test_wrong_product_floating_image_and_historical_switches_are_refused(self):
        for image in ('other/product@sha256:'+'1'*64,'ghcr.io/pegaprox/pegaprox:latest'):
            with self.subTest(image=image),self.assertRaises(ValueError):service(image=image)
        for field in ('enabled','deployable'):
            raw={'profile':'pegaprox','guest':'management','lifecycle':'retained','interfaces':{},field:True}
            with self.subTest(field=field),self.assertRaises(ValueError):component_types.app(raw)

    def test_listener_is_explicit_private_and_resource_budget_reserves_the_guest(self):
        for address in ('0.0.0.0','127.0.0.1','8.8.8.8','224.0.0.1','169.254.1.1','240.0.0.1'):
            with self.subTest(address=address),self.assertRaises(ValueError):service(address=address)
        for fields in ({'memory_mib':2000},{'cpu_limit':3},{'pids_limit':513},{'cpu_limit':True}):
            value=descriptor();value['containers']['pegaprox'].update(fields)
            with self.subTest(fields=fields),self.assertRaises(ValueError):component_runtime._pegaprox(value,guest())
        for change in (lambda a:a['listeners']['web_listener'].update(publication_address='198.18.25.35'),
                       lambda a:a['listeners']['web_listener']['publish'].update(scope='guest-loopback'),
                       lambda a:a['listeners']['web_listener']['publish'].update(port=5001)):
            value=descriptor();change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):component_runtime._pegaprox(value,guest())


class ProxyModeTests(unittest.TestCase):
    def test_explicit_http_mode_keeps_outer_bind_and_protected_runtime_policy(self):
        rendered=service()
        self.assertEqual(rendered['environment'],{
            'PEGAPROX_BEHIND_PROXY':'true','PEGAPROX_HOST':'0.0.0.0',
            'PEGAPROX_TRUSTED_PROXIES':'198.18.25.33/32',
            'PEGAPROX_KEY_FILE':'/run/secrets/pegaprox-db-key','PEGAPROX_SUPERVISED':'1',
            'PEGAPROX_SSH_STRICT_HOST_KEYS':'1','PEGAPROX_PW_HASH_CONCURRENCY':'2','TZ':'Etc/UTC'})
        self.assertEqual(rendered['ports'],['198.18.25.34:5000:5000/tcp'])
        self.assertTrue(rendered['read_only']);self.assertEqual(rendered['cap_drop'],['ALL'])
        self.assertEqual(rendered['security_opt'],['no-new-privileges:true'])
        self.assertEqual(rendered['restart'],'always');self.assertEqual(rendered['mem_limit'],'1024m')
        self.assertEqual(rendered['stop_grace_period'],'60s');self.assertTrue(rendered['volumes'][-1]['read_only'])
        self.assertFalse(any(key.startswith('PEGAPROX_ADMIN') for key in rendered['environment']))

    def test_trust_requires_one_explicit_private_host_not_a_list_subnet_or_self(self):
        for proxy in [None,[],True,'','198.18.25.33','198.18.25.33/24','198.18.25.0/24',
            '198.18.25.33/32,198.18.25.35/32',' 198.18.25.33/32','0.0.0.0/32','0.0.0.0/0',
            '127.0.0.1/32','8.8.8.8/32','224.0.0.1/32','192.0.2.1/32','::1/128','198.18.25.34/32']:
            with self.subTest(proxy=proxy),self.assertRaises(ValueError):service(proxy=proxy)
        with self.assertRaises(ValueError):component_properties.validate('pegaprox',{})
        for proxy in ['10.1.2.3/32','172.20.1.2/32','192.168.1.3/32','198.19.1.2/32']:
            self.assertEqual(service(proxy=proxy)['environment']['PEGAPROX_TRUSTED_PROXIES'],proxy)
