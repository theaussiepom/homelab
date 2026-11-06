"""Maintained policy example and private-CD safety contract, source only."""
import json
from pathlib import Path
import re
import sys
import unittest

import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import host_firewall as h

HERE=Path(h.__file__).parent


class DocumentationControls(unittest.TestCase):
    def test_complete_yaml_example_and_guide_are_the_same_valid_policy(self):
        example=h.authored_config.read(HERE/'host-firewall.example.yaml')
        h.validate(example)
        text=(HERE/'HOST-FIREWALL.md').read_text()
        examples=re.findall(r'```yaml\n(.*?)\n```',text,re.S)
        self.assertEqual(len(examples),1)
        guide=h.authored_config.parse(examples[0].encode(),'.yaml')
        self.assertEqual(guide,example)
        self.assertEqual([r['dport'] for r in h.rules(guide)],['8006','22'])
        self.assertIn('kernel_verified: false',text)
        self.assertIn('There is no import, recovery, adoption',text)
        self.assertIn('environmental ownership',text)

    def test_workflow_template_validates_before_protected_native_job_without_nested_lock(self):
        workflow=yaml.load((HERE/'templates/private-host-firewall.yml.example').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']),{'pull_request','push'})
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertNotIn('concurrency',workflow)
        jobs=workflow['jobs'];self.assertEqual(set(jobs),{'validate','firewall'})
        self.assertNotIn('concurrency',jobs['validate'])
        self.assertEqual(jobs['firewall']['concurrency']['group'],'homelab-private-deployment')
        self.assertEqual(jobs['firewall']['environment'],'homelab-bootstrap')
        self.assertEqual(jobs['firewall']['needs'],'validate')
        condition=jobs['firewall']['if']
        for required in ("github.event.repository.private == true", "github.event_name == 'push'", "github.ref == 'refs/heads/main'"):
            self.assertIn(required,condition)
        checks=[s['run']for s in jobs['validate']['steps']if 'run'in s]
        self.assertTrue(any('--check --config bootstrap/firewall.yaml'in s for s in checks))
        self.assertNotIn('PROXMOX_BOOTSTRAP_TOKEN',json.dumps(jobs['validate']))
        native=jobs['firewall']['steps'][-1]
        self.assertEqual(set(native['env']),{'PROXMOX_BOOTSTRAP_TOKEN'})
        self.assertIn('/opt/homelab-tools/bin/python3',native['run'])
        self.assertNotIn('docker',native['run'])
        self.assertNotIn('import',native['run'])
        for job in jobs.values():
            for step in job['steps']:
                if step.get('with',{}).get('repository')=='theaussiepom/homelab':
                    self.assertEqual(step['with']['ref'],'0'*40)
                    self.assertEqual(step['with']['persist-credentials'],'false')

    def test_hcl_hook_is_maintained_in_existing_offline_gate(self):
        root=HERE.parents[1]
        script=(root/'proxmox/applications/tests/check.sh').read_text()
        self.assertIn('cp -R /src/proxmox/bootstrap/host-firewall /tmp/host-firewall-tofu',script)
        self.assertIn('cd /tmp/host-firewall-tofu\ntofu fmt -check -recursive\ntofu init -backend=false',script)
        model=(HERE/'host-firewall/main.tf').read_text()
        self.assertEqual(model.count('prevent_destroy = true'),2)
        self.assertIn('depends_on     = [proxmox_virtual_environment_firewall_rules.host]',model)
        self.assertNotIn('ignore_changes',model)
