"""The same reviewed guest supplies its bootstrap grants and application plan."""
import copy
import json
from pathlib import Path
import unittest

from test_deploy import ROOT
import automation_configuration as configuration


def packet():
    foundation = json.loads((ROOT/'examples/foundation.site.example.json').read_text())
    cfg = json.loads((ROOT/'examples/site.example.json').read_text())
    base = configuration.site_config.render(foundation)
    cfg.update(site=base['bindings.json']['site'], paths=dict(configuration.site_config.PATHS,
               backup_source=foundation['runner']['backup_source']), ssh_public_keys=foundation['ssh_public_keys'])
    cfg['guest'].update(vmid=200,hostname='automation')
    cfg['guest']['interfaces'] = [dict(bridge=foundation['networks']['management']['bridge'],
        vlan=foundation['networks']['management']['vlan'],ipv4='10.88.25.21/24',mac='02:88:00:c8:19:01')]
    cfg['app'].update(vmid=200,hostname='automation',address='10.88.25.21',mac='02:88:00:c8:19:01')
    return foundation, dict(schema='homelab-automation-deployment-v1', enabled=False,site=cfg,
        stack=json.loads((ROOT/'examples/automation.stack.example.json').read_text()),
        discovery_previous_guests=base['bootstrap.json']['service_discovery']['guests'])


class AutomationConfigurationTests(unittest.TestCase):
    def test_untagged_backend_remains_a_bridge_only_bootstrap_grant(self):
        foundation, value=packet()
        value['site']['guest']['interfaces'].append(dict(bridge='vmbr30',vlan=None,ipv4='10.88.30.21/24',mac='02:88:00:c8:1e:01'))
        boot=configuration.compile_config(foundation,value)['bootstrap.json']
        self.assertIn({'vmid':200,'bridge':'vmbr30','vlan':None},boot['application_networks'])
        self.assertIn(('/sdn/zones/localnetwork/vmbr30','PVESDNUser',0),configuration.bootstrap_cd.desired(boot))
        self.assertNotIn(('/sdn/zones/localnetwork/vmbr30/None','PVESDNUser',0),configuration.bootstrap_cd.desired(boot))

    def test_broker_record_uses_the_selected_frontend_address_and_preserves_foundation_dns(self):
        foundation, value = packet()
        value['site']['app']['mqtt_hostname'] = 'broker.mqtt'
        original = configuration.site_config.render(foundation)['dns-settings.json']
        dns = configuration.compile_config(foundation, value)['dns-settings.json']
        self.assertEqual({k:v for k,v in dns.items() if k != 'extra_records'}, original)
        self.assertEqual(dns['extra_records'], {'broker.mqtt':'10.88.25.21'})

    def test_disabled_preview_derives_only_the_same_guest_and_vlan_grants(self):
        foundation, value = packet(); original = copy.deepcopy(value)
        boot = configuration.compile_config(foundation,value)['bootstrap.json']
        self.assertEqual(value, original)
        self.assertEqual(boot['applications'][-1],{'vmid':200,'hostname':'automation'})
        self.assertEqual(boot['application_networks'],[{'vmid':200,'bridge':foundation['networks']['management']['bridge'],
            'vlan':foundation['networks']['management']['vlan']}])
        self.assertEqual(boot['service_discovery_extension'],{'previous_guests':value['discovery_previous_guests']})
        self.assertEqual(boot['service_discovery']['guests'],sorted([*value['discovery_previous_guests'],200]))

    def test_foreign_host_paths_keys_budget_or_previous_scope_are_refused(self):
        foundation, value = packet()
        changes=[lambda p:p['site']['site'].update(node='other'),
                 lambda p:p['site']['paths'].update(state_root='/other'),
                 lambda p:p['site'].update(ssh_public_keys=['other']),
                 lambda p:p['stack'].update(guest_memory_mib=8192),
                 lambda p:p.update(discovery_previous_guests=[200]),
                 lambda p:p.update(enabled='yes')]
        for change in changes:
            bad=copy.deepcopy(value); change(bad)
            with self.subTest(change=change), self.assertRaises(ValueError):
                configuration.compile_config(foundation,bad)


if __name__=='__main__':unittest.main()
