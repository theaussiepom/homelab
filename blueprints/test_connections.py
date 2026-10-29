"""Internal connection policies use declared interfaces and both firewall ends."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import connections as c


def guest(address, rules, routes=(), dns=()):
    return {
        "site": {"api_endpoint": "https://198.18.0.1:8006/", "node": "fixture"},
        "guest": {
            "interfaces": [
                {
                    "ipv4": address + "/24",
                    "gateway": "198.18.1.1",
                    "bridge": "vmbr0",
                    "vlan": 25,
                    "mac": "02:00:"
                    + ":".join(f"{int(part):02x}" for part in address.split(".")),
                }
            ],
            "rules": rules,
            "dns_servers": list(dns),
        },
        "app": {},
        "routes": {str(i): route for i, route in enumerate(routes)},
    }


class ConnectionContractTests(unittest.TestCase):
    def test_network_identity_conflicts_are_scoped_to_the_declared_link(self):
        cfg = self.configurations()
        for field in ("ipv4", "mac"):
            changed = copy.deepcopy(cfg)
            changed["app"]["guest"]["interfaces"][0][field] = changed["ingress"][
                "guest"
            ]["interfaces"][0][field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "network identity"),
            ):
                c.validate_identities(changed)
            for scope in ("node", "bridge", "vlan"):
                isolated = copy.deepcopy(changed)
                if scope == "node":
                    isolated["app"]["site"]["node"] = "another-node"
                else:
                    isolated["app"]["guest"]["interfaces"][0][scope] = (
                        "vmbr1" if scope == "bridge" else 26
                    )
                c.validate_identities(isolated)

    def configurations(self):
        return {
            "ingress": guest(
                "198.18.1.2",
                [
                    {
                        "direction": "out",
                        "proto": "tcp",
                        "destination": "198.18.2.3/32",
                        "port": "8123",
                    }
                ],
            ),
            "app": guest(
                "198.18.2.3",
                [
                    {
                        "direction": "in",
                        "proto": "tcp",
                        "source": "198.18.1.2/32",
                        "port": "8123",
                    }
                ],
                [{"url": "http://198.18.2.3:8123"}],
            ),
        }

    def test_both_ends_are_required_with_protocol_address_and_exact_port(self):
        cfg = self.configurations()
        c.validate(cfg)
        for name in cfg:
            for changes in (
                {"proto": "udp"},
                {"port": "18123"},
                {"source": "198.18.9.1/32"},
                {"destination": "198.18.9.2/32"},
            ):
                with self.subTest(guest=name, changes=changes):
                    changed = copy.deepcopy(cfg)
                    changed[name]["guest"]["rules"][0].update(changes)
                    with self.assertRaisesRegex(
                        ValueError, name + " (out|in) firewall"
                    ):
                        c.validate(changed)

    def test_external_https_uses_ingress_egress_and_never_claims_host_firewall_ownership(
        self,
    ):
        cfg = self.configurations()
        external_routes = {
            "nas": {"url": "https://192.168.1.2"},
            "pi": {"url": "http://192.168.1.3"},
            "matter": {"url": "http://192.168.1.4:5580"},
        }
        cfg["ingress"]["guest"]["rules"].append(
            {
                "direction": "out",
                "proto": "tcp",
                "destination": "192.168.1.0/24",
                "port": "80,443,5580",
            }
        )
        c.validate(cfg, external_routes)
        external = [
            flow for flow in c.connections(cfg, external_routes) if flow.target is None
        ]
        self.assertEqual({flow.port for flow in external}, {80, 443, 5580})
        self.assertEqual({flow.source_address for flow in external}, {"198.18.1.2"})
        cfg["ingress"]["guest"]["rules"].pop()
        with self.assertRaisesRegex(ValueError, "ingress out firewall"):
            c.validate(cfg, external_routes)

    def test_source_uses_longest_connected_prefix_before_the_default(self):
        cfg = self.configurations()
        cfg["ingress"]["guest"]["interfaces"] += [
            {"ipv4": "198.18.2.2/24"},
            {"ipv4": "198.18.2.4/29"},
        ]
        flow = next(c.connections(cfg))
        self.assertEqual(flow.source_address, "198.18.2.4")
        self.assertEqual(
            c.source_address(cfg["ingress"]["guest"], "198.19.2.3"), "198.18.1.2"
        )
        cfg["ingress"]["guest"]["interfaces"].append(
            {"ipv4": "198.18.3.2/24", "gateway": "198.18.3.1"}
        )
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            c.source_address(cfg["ingress"]["guest"], "198.19.2.3")

    def test_dns_requires_tcp_and_udp_and_skips_self_and_external_resolvers(self):
        cfg = self.configurations()
        cfg["app"]["routes"] = {}
        cfg["app"]["guest"]["dns_servers"] = ["198.18.1.2", "198.19.1.1"]
        cfg["ingress"]["guest"]["dns_servers"] = ["198.18.1.2"]
        cfg["app"]["guest"]["rules"] = [
            {
                "direction": "out",
                "proto": protocol,
                "destination": "198.18.1.2/32",
                "port": "53",
            }
            for protocol in ("tcp", "udp")
        ]
        cfg["ingress"]["guest"]["rules"] = [
            {
                "direction": "in",
                "proto": protocol,
                "source": "198.18.2.3/32",
                "port": "53",
            }
            for protocol in ("tcp", "udp")
        ]
        self.assertEqual({flow.protocol for flow in c.connections(cfg)}, {"tcp", "udp"})
        self.assertEqual(len(list(c.connections(cfg))), 2)
        c.validate(cfg)
        cfg["ingress"]["guest"]["rules"].pop()
        with self.assertRaisesRegex(ValueError, "udp/53"):
            c.validate(cfg)

    def test_ambiguous_internal_resolver_identity_is_refused(self):
        cfg = self.configurations()
        cfg["app"]["guest"]["dns_servers"] = ["198.18.1.2"]
        cfg["duplicate"] = guest("198.18.1.2", [])
        with self.assertRaisesRegex(ValueError, "one guest"):
            list(c.connections(cfg))

    def test_explicit_port_lists_and_ranges_do_not_admit_other_ports(self):
        flow = next(c.connections(self.configurations()))
        rules = [{"direction": "out", "proto": "tcp", "port": "80,8120:8123"}]
        self.assertTrue(c.permits(rules, "out", flow))
        for ports in ("80,8120:8122", "1880"):
            rules[0]["port"] = ports
            self.assertFalse(c.permits(rules, "out", flow))
        for ports in ("0", "65536", "8123:8000", "80-90"):
            rules[0]["port"] = ports
            with self.assertRaises(ValueError):
                c.permits(rules, "out", flow)

    def test_dynamic_addresses_keep_mac_identity_and_port_metadata_remains_literal(
        self,
    ):
        dynamic = guest("198.18.1.2", [])
        dynamic["guest"]["interfaces"][0]["ipv4"] = "dhcp"
        c.validate_identities({"dynamic": dynamic})
        link = c.Connection("source", "target", "198.18.1.2", "198.18.2.3", "tcp", 8123)
        with self.assertRaisesRegex(ValueError, "explicit firewall ports"):
            c.permits([{"direction": "out", "proto": "tcp", "port": 8123}], "out", link)

        self.assertTrue(c.permits([{"direction": "out", "proto": "tcp"}], "out", link))
