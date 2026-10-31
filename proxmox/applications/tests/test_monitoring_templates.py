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
        resources = next(row for row in items if row['key'] == 'proxmox.cluster.resources')
        self.assertEqual(resources['history'], '1h')
        bad = copy.deepcopy(document)
        next(row for row in templates.http_agents(bad) if row['key'] == 'proxmox.cluster.resources')['history'] = '0'
        with self.assertRaises(ValueError): templates.check_readback(bad)
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

    def test_docker_active_derivation_is_stable_and_influx_excludes_privileged_discovery(self):
        docker=templates.prepared('template_app_docker.yaml')
        self.assertEqual(docker,templates.prepared('template_app_docker.yaml'))
        template=docker['zabbix_export']['templates'][0]
        self.assertEqual(template['template'],'HomeLab Docker by active agent 2')
        def nodes(value):
            if isinstance(value,dict):
                yield value
                for child in value.values():yield from nodes(child)
            elif isinstance(value,list):
                for child in value:yield from nodes(child)
        for node in nodes(template):
            for key in ('items','item_prototypes','discovery_rules'):
                self.assertTrue(all(item.get('type')!='ZABBIX_PASSIVE' for item in node.get(key,[])))
        influx=templates.prepared('template_db_influxdb_http.yaml')['zabbix_export']['templates'][0]
        self.assertNotIn('discovery_rules',influx)
        self.assertNotIn('{$INFLUXDB.API.TOKEN}',{m['macro'] for m in influx['macros']})
