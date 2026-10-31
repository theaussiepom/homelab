"""A clean monitoring install cannot restore data or weaken agent/API trust."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring
import render


def fixture(root):
    (root / "password").write_text("synthetic-fixture-password")
    (root / "password").chmod(0o600)
    (root / "ca").write_text(
        "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
    )
    return {
        "kind": "monitoring",
        "guest_memory_mib": 2048,
        "services": {
            name: {
                "image": monitoring.VERSIONS[name],
                "memory_mib": memory,
                "cpus": 1,
                "pids_limit": 128,
            }
            for name, memory in [("zabbix_server", 768), ("zabbix_web", 512)]
        },
        "monitoring": {
            "version": monitoring.VERSIONS["version"],
            "bind_address": "198.18.30.50",
            "postgresql_host": "198.18.30.23",
            "postgresql_database": "zabbix",
            "postgresql_user": "zabbix",
            "secret_files": {
                "database_password": str(root / "password"),
                "proxmox_ca": str(root / "ca"),
            },
        },
    }


class MonitoringTests(unittest.TestCase):

    def test_restart_defaults_and_explicit_policy_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            for service in cfg["services"].values():
                service.pop("restart", None)
            self.assertTrue(
                all(
                    s["restart"] == "always"
                    for s in monitoring.compose(cfg)["services"].values()
                )
            )
            selected = cfg["services"]["zabbix_server"]
            for policy in ("always", "unless-stopped", "no"):
                selected["restart"] = policy
                self.assertEqual(
                    monitoring.compose(cfg)["services"]["zabbix_server"]["restart"],
                    policy,
                )
            for policy in (None, False, "sometimes", [], {}):
                selected["restart"] = policy
                with self.subTest(policy=policy), self.assertRaises(ValueError):
                    monitoring.compose(cfg)

    def test_clean_stack_uses_file_password_and_trusted_api_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            document = render.compose(cfg)
            self.assertEqual(set(document["services"]), {"zabbix_server", "zabbix_web"})
            self.assertNotIn("synthetic-fixture-password", json.dumps(document))
            self.assertTrue(all(s['environment']['ZBX_DBTLSCONNECT']=='required' for s in document['services'].values()))
            self.assertEqual(document['services']['zabbix_web']['environment']['ZBX_DB_ENCRYPTION'],'true')
            server = document["services"]["zabbix_server"]
            self.assertEqual(server["ports"], ["198.18.30.50:10051:10051"])
            self.assertTrue(
                any(
                    v["target"] == "/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem"
                    and v["read_only"]
                    for v in server["volumes"]
                )
            )
            self.assertNotIn("network_mode", server)
            files = monitoring.files(cfg)
            self.assertTrue(
                any(
                    f["path"] == "database-password"
                    and f["uid"] == 1997
                    and f["mode"] == "0400"
                    for f in files
                )
            )

    def test_no_extra_services_env_socket_or_unpinned_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            for field, value in [
                ("image", "zabbix/zabbix-server-pgsql:latest"),
                ("environment", {"ZBX_DBTLSCONNECT": "disable"}),
                ("extra_mounts", [{"source": "/run/docker.sock"}]),
            ]:
                bad = copy.deepcopy(cfg)
                bad["services"]["zabbix_server"][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    render.compose(bad)
            for address in ("0.0.0.0", "127.0.0.1", "::", "invalid"):
                bad = copy.deepcopy(cfg)
                bad["monitoring"]["bind_address"] = address
                with self.subTest(address=address), self.assertRaises(ValueError):
                    render.compose(bad)

    def test_agent_is_active_only_and_rejects_injection(self):
        value = {
            "hostname": "practice-pve",
            "server_active": "198.18.30.50:10051",
            "psk_identity": "practice-pve-unique",
            "psk_path": "/etc/zabbix/agent.psk",
        }
        text = monitoring.agent_config(value)
        self.assertNotIn("\nServer=", text)
        self.assertNotIn("Include=", text)
        self.assertIn("TLSConnect=psk\n", text)
        self.assertIn("DenyKey=system.run[*]", text)
        for key in value:
            bad = dict(value)
            bad[key] += "\nServer=0.0.0.0/0"
            with self.subTest(key=key), self.assertRaises(ValueError):
                monitoring.agent_config(bad)

    def test_template_hashes_and_full_tls_are_pinned(self):
        monitoring.check_templates()


if __name__ == "__main__":
    unittest.main()
