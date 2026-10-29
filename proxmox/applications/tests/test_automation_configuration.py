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
    def test_retained_bootstrap_keeps_existing_access_and_extends_its_current_owner(self):
        import provider_access
        foundation, value = packet()
        retained = configuration.site_config.render(foundation)['bootstrap.json']
        original_owner = provider_access.owner_sha256(provider_access.owner(retained))
        retained['applications'].append({'vmid':2501,'hostname':'existing-app'})
        retained['service_discovery']['guests'].append(2501)
        retained['service_discovery_extension'] = {'owner_sha256':original_owner,'guests':[2501]}
        retained['application_networks'] = [{'vmid':2501,'bridge':'vmbr30','vlan':None}]
        before = copy.deepcopy(retained)
        value['discovery_previous_guests'] = list(retained['service_discovery']['guests'])
        result = configuration.compile_config(foundation, value, bootstrap=retained)['bootstrap.json']
        self.assertEqual(retained, before)
        self.assertEqual(result['applications'][:-1], retained['applications'])
        self.assertEqual(result['application_networks'][:-1], retained['application_networks'])
        self.assertEqual(result['service_discovery']['guests'], [*value['discovery_previous_guests'],200])
        self.assertEqual(result['service_discovery_extension'], {
            'owner_sha256':provider_access.owner_sha256(provider_access.owner(retained)), 'guests':[200]})

    def test_retained_bootstrap_cannot_replace_foundation_identity_or_existing_allocations(self):
        foundation, value = packet()
        for change in (lambda b:b.update(endpoint='https://other.example.org:8006/'),
                       lambda b:b['applications'].pop(0),
                       lambda b:b['service_discovery']['guests'].reverse()):
            retained = configuration.site_config.render(foundation)['bootstrap.json']
            change(retained)
            with self.subTest(change=change), self.assertRaises(ValueError):
                configuration.compile_config(foundation, value, bootstrap=retained)

    def test_ordinary_binding_validation_does_not_replay_a_bootstrap_extension(self):
        foundation, value = packet()
        value['discovery_previous_guests'].append(2501)
        # Runtime application validation retains the selected inputs without
        # creating or authorizing the separately prepared bootstrap request.
        configuration.validate_inputs(foundation, value)
        with self.assertRaises(ValueError):
            configuration.compile_config(foundation, value)

    def test_dns_compilation_does_not_replay_the_historical_discovery_owner(self):
        foundation, value = packet()
        value['discovery_previous_guests'].append(2501)
        value['site']['app'].update(mqtt_hostname='broker.mqtt', mqtt_previous_address=None)
        original = copy.deepcopy(value)
        dns = configuration.compile_dns(foundation, value)
        self.assertEqual(dns['extra_records'], {'broker.mqtt':'10.88.25.21'})
        self.assertEqual(value, original)

    def test_frontend_reply_gateway_cannot_drift_from_the_single_site_network(self):
        foundation,value=packet();network=foundation['networks']['frontend']
        nic=dict(bridge=network['bridge'],vlan=network['vlan'],ipv4='10.88.40.21/24',mac='02:88:00:c8:28:01')
        value['site']['guest']['interfaces'].append(nic)
        value['site']['app']['frontend_routing']={'address':nic['ipv4'],'mac':nic['mac'],'gateway':network['gateway']}
        configuration.compile_config(foundation,value)
        value['site']['app']['frontend_routing']['gateway']='10.88.40.254'
        with self.assertRaisesRegex(ValueError,'reviewed foundation frontend'):
            configuration.compile_config(foundation,value)

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
        value['site']['app']['mqtt_previous_address'] = None
        original = configuration.site_config.render(foundation)['dns-settings.json']
        dns = configuration.compile_config(foundation, value)['dns-settings.json']
        self.assertEqual({k:v for k,v in dns.items() if k not in {'extra_records','extra_records_before'}}, original)
        self.assertEqual(dns['extra_records'], {'broker.mqtt':'10.88.25.21'})

    def test_disabled_preview_derives_only_the_same_guest_and_vlan_grants(self):
        import provider_access
        foundation, value = packet(); original = copy.deepcopy(value)
        previous = configuration.site_config.render(foundation)['bootstrap.json']
        previous_owner = provider_access.owner_sha256(provider_access.owner(previous))
        boot = configuration.compile_config(foundation,value)['bootstrap.json']
        self.assertEqual(value, original)
        self.assertEqual(boot['applications'][-1],{'vmid':200,'hostname':'automation'})
        self.assertEqual(boot['application_networks'],[{'vmid':200,'bridge':foundation['networks']['management']['bridge'],
            'vlan':foundation['networks']['management']['vlan']}])
        self.assertEqual(boot['service_discovery_extension']['guests'], [value['site']['guest']['vmid']])
        self.assertEqual(boot['service_discovery_extension']['owner_sha256'], previous_owner)
        self.assertEqual(boot['service_discovery']['guests'][:-1],value['discovery_previous_guests'])
        self.assertEqual(boot['service_discovery']['guests'],[*value['discovery_previous_guests'],200])

    def test_oidc_issuer_and_callback_must_match_the_commissioned_identity_and_route(self):
        foundation,value=packet()
        cfg=value['site']
        cfg['app']['node_red_authentication']='authentik-oidc'
        cfg['app']['discovery_routes']=[{'name':'homeassistant','host':'hass.lab.example.org',
            'url':'http://10.88.25.21:8123','login':'own'},{'name':'node-red','host':'flows.lab.example.org',
            'url':'http://10.88.25.21:1880','login':'oidc'}]
        value['stack']['node_red_oidc']={'identity_url':'https://'+foundation['domains']['identity'],
            'node_red_url':'https://flows.lab.example.org','client_id':'fixture','provider_slug':'node-red'}
        value['stack']['services']['node_red'].update(command=['--settings','/runtime-settings.js'],
            extra_mounts=[{'source':'/srv/homelab/data/node-red/runtime-settings.js','target':'/runtime-settings.js','read_only':True}])
        configuration.compile_config(foundation,value)
        for field in ('identity_url','node_red_url'):
            bad=copy.deepcopy(value);bad['stack']['node_red_oidc'][field]='https://other.lab.example.org'
            with self.subTest(field=field),self.assertRaises(ValueError):configuration.compile_config(foundation,bad)

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
