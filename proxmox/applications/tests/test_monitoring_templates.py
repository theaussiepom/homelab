import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_templates as templates


class TemplateTrustTests(unittest.TestCase):
    def test_all_http_items_and_prototypes_require_peer_and_hostname_trust(self):
        document = templates.prepared('template_app_proxmox.yaml')
        templates.check_readback(document)
        items = list(templates.http_agents(document))
        self.assertEqual(len(items), 7)
        for field in ('verify_peer', 'verify_host'):
            bad = copy.deepcopy(document)
            next(templates.http_agents(bad))[field] = 'NO'
            with self.subTest(field=field), self.assertRaises(ValueError): templates.check_readback(bad)

    def test_official_bytes_remain_unchanged(self):
        import monitoring
        before = (monitoring.ROOT / 'templates/template_app_proxmox.yaml').read_bytes()
        templates.prepared('template_app_proxmox.yaml')
        self.assertEqual((monitoring.ROOT / 'templates/template_app_proxmox.yaml').read_bytes(), before)
        monitoring.check_templates()
