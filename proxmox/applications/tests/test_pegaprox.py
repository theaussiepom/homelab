"""The PegaProx component keeps resources, listener and retained key explicit."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox


def stack():
    return {
        "kind": "pegaprox",
        "image": "ghcr.io/pegaprox/pegaprox:fixture@sha256:" + "1" * 64,
        "bind_address": "198.18.25.34",
        "trusted_proxy": "198.18.25.33/32",
        "guest_memory_mib": 2048,
        "container_memory_mib": 1024,
        "cpus": 1,
        "pids_limit": 256,
    }


class PegaProxTests(unittest.TestCase):
    def test_restart_defaults_and_explicit_policy_are_validated(self):
        self.assertEqual(
            pegaprox.compose(stack())["services"]["pegaprox"]["restart"], "always"
        )
        for policy in ("always", "unless-stopped", "no"):
            cfg = dict(stack(), restart=policy)
            self.assertEqual(
                pegaprox.compose(cfg)["services"]["pegaprox"]["restart"], policy
            )
        for policy in (None, False, "sometimes", [], {}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                pegaprox.compose(dict(stack(), restart=policy))

    def test_current_stack_retains_key_path_and_does_not_create_empty_data(self):
        value = stack()
        service = pegaprox.compose(value)["services"]["pegaprox"]
        self.assertEqual(service["image"], value["image"])
        self.assertEqual(service["ports"], ["198.18.25.34:5000:5000/tcp"])
        self.assertTrue(
            all(m["bind"]["create_host_path"] is False for m in service["volumes"])
        )
        self.assertEqual(
            service["environment"]["PEGAPROX_KEY_FILE"], "/run/secrets/pegaprox-db-key"
        )
        self.assertEqual(service["restart"], "always")

    def test_wrong_product_floating_image_and_historical_switches_are_refused(self):
        for change in [
            {"image": "other/product@sha256:" + "1" * 64},
            {"image": "ghcr.io/pegaprox/pegaprox:latest"},
            {"enabled": True},
            {"deployable": True},
        ]:
            value = stack()
            value.update(change)
            with self.assertRaises(ValueError):
                pegaprox.compose(value)

    def test_listener_is_explicit_private_and_resource_budget_reserves_the_guest(self):
        for address in ["0.0.0.0", "127.0.0.1", "8.8.8.8", "224.0.0.1"]:
            value = stack()
            value["bind_address"] = address
            with self.assertRaises(ValueError):
                pegaprox.compose(value)
        for change in [
            {"container_memory_mib": 2000},
            {"cpus": 3},
            {"pids_limit": 513},
            {"cpus": True},
        ]:
            value = stack()
            value.update(change)
            with self.assertRaises(ValueError):
                pegaprox.compose(value)


class ProxyModeTests(unittest.TestCase):
    def test_explicit_http_mode_keeps_outer_bind_and_protected_runtime_policy(self):
        service = pegaprox.compose(stack())['services']['pegaprox']
        self.assertEqual(service['environment'], {
            'PEGAPROX_BEHIND_PROXY':'true', 'PEGAPROX_HOST':'0.0.0.0',
            'PEGAPROX_TRUSTED_PROXIES':'198.18.25.33/32',
            'PEGAPROX_KEY_FILE':'/run/secrets/pegaprox-db-key', 'PEGAPROX_SUPERVISED':'1',
            'PEGAPROX_SSH_STRICT_HOST_KEYS':'1', 'PEGAPROX_PW_HASH_CONCURRENCY':'2', 'TZ':'Etc/UTC'})
        self.assertEqual(service['ports'], ['198.18.25.34:5000:5000/tcp'])
        self.assertTrue(service['read_only'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(service['restart'], 'always')
        self.assertEqual(service['mem_limit'], '1024m')
        self.assertEqual(service['stop_grace_period'], '60s')
        self.assertTrue(service['volumes'][-1]['read_only'])
        self.assertFalse(any(key.startswith('PEGAPROX_ADMIN') for key in service['environment']))

    def test_trust_requires_one_explicit_private_host_not_a_list_subnet_or_self(self):
        for proxy in [None, [], True, '', '198.18.25.33', '198.18.25.33/24', '198.18.25.0/24',
                      '198.18.25.33/32,198.18.25.35/32', ' 198.18.25.33/32',
                      '0.0.0.0/32','0.0.0.0/0','127.0.0.1/32','8.8.8.8/32','224.0.0.1/32',
                      '192.0.2.1/32','::1/128','198.18.25.34/32']:
            with self.subTest(proxy=proxy), self.assertRaises(ValueError):
                pegaprox.compose(dict(stack(), trusted_proxy=proxy))
        missing = stack(); del missing['trusted_proxy']
        with self.assertRaises(ValueError): pegaprox.compose(missing)
        for proxy in ['10.1.2.3/32','172.20.1.2/32','192.168.1.3/32','198.19.1.2/32']:
            self.assertEqual(pegaprox.compose(dict(stack(),trusted_proxy=proxy))['services']['pegaprox']['environment']['PEGAPROX_TRUSTED_PROXIES'],proxy)
