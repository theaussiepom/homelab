"""Execute named reference examples through the existing parser and contracts."""
import copy
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'proxmox/applications'))
import authored_config
import component_addresses
import component_accounts
import component_auth
import component_backup
import component_backup_job
import component_foundations
import component_monitoring
import component_packet
import component_plan
import component_properties
import component_secrets
import component_sources
import component_types as types
from test_documentation_contract_helpers import assert_typed_equal, expect_component_refusal

# Explicitly maintained test selection, not another configuration grammar.
EXAMPLES = {
    'site.md': ['site-worked'],
    'library.md': ['template-minimal'],
    'sources.md': ['source-app'],
    'contexts.md': ['context-minimal', 'context-capability'],
    'networks.md': ['network-minimal', 'nic-minimal', 'network-groups'],
    'guests.md': ['guest-minimal'],
    'apps.md': ['app-minimal', 'app-overrides'],
    'app-properties.md': ['properties-adapters'],
    'storage.md': ['pool-minimal', 'storage-combination'],
    'connections.md': ['connection-managed', 'account-managed', 'account-source'],
    'exposures.md': ['exposure-http'],
    'policies.md': ['policy-network', 'policy-binding', 'policy-middleware', 'transport-conflicting-trust'],
    'identity-and-secrets.md': ['secret-file', 'secret-environment', 'identity-oidc'],
    'supporting-types.md': ['profile-minimal', 'runtime-minimal', 'device-minimal'],
    'zabbix.md': ['zabbix-selection', 'zabbix-profile'],
    'backup.md': ['backup-selection', 'backup-profile-selection', 'backup-profile',
                  'backup-application', 'backup-job'],
    'lifecycle.md': ['lifecycle-fresh'],
}


def example_text(page, name):
    text = (ROOT / 'docs/reference' / page).read_text()
    found = re.findall(r'<!-- example: ' + re.escape(name) + r' -->\n```yaml\n(.*?)\n```', text, re.S)
    if len(found) != 1:
        raise AssertionError('Expected exactly one maintained example: ' + page + '/' + name)
    return found[0] + '\n'


def example(page, name):
    return authored_config.parse(example_text(page, name).encode(), '.yaml')


class ReferenceExamples(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / 'config'
        shutil.copytree(ROOT / 'docs/examples/first-configuration', self.config)
        self.site = self.config / 'site.yaml'

    def resolve(self, selected=None, library=None):
        if selected is not None:
            self.site.write_text(json.dumps(selected))
        if library is not None:
            (self.config / 'stack.json').write_text(json.dumps(library))
        with patch('subprocess.run', side_effect=AssertionError('No process or target')), \
             patch('socket.create_connection', side_effect=AssertionError('No network')):
            plan = component_plan.resolve(self.config, self.site)
            packets = component_packet.lower_plan(plan)
        return plan, packets

    def test_worked_site_and_all_tutorial_value_examples_resolve_and_lower(self):
        selected = example('site.md', 'site-worked')
        self.resolve(selected)
        selected['contexts']['lab'] = example('contexts.md', 'context-minimal')
        selected['networks']['primary'] = example('networks.md', 'network-minimal')
        selected['storage']['local'] = example('storage.md', 'pool-minimal')
        selected['guests']['resolver'] = example('guests.md', 'guest-minimal')
        selected['guests']['resolver']['interfaces']['management'] = example('networks.md', 'nic-minimal')
        selected['apps']['recursive_a'] = example('apps.md', 'app-minimal')
        before, packets = self.resolve(selected)
        self.assertEqual(set(packets), {'resolver'})
        selected['apps']['recursive_a'].update(example('apps.md', 'app-overrides'))
        selected['guests']['resolver']['resources'] = {'memory_mib': 1024}
        after, _ = self.resolve(selected)
        self.assertEqual(after.resolved['guests']['resolver']['resources']['memory_mib'], 1024)
        self.assertEqual(after.resolved['apps']['recursive_a']['identity'], before.resolved['apps']['recursive_a']['identity'])
        for change in ('unknown-guest', 'wrong-local-scope', 'boolean-memory'):
            wrong = copy.deepcopy(selected)
            if change == 'unknown-guest': wrong['apps']['recursive_a']['guest'] = 'missing'
            elif change == 'wrong-local-scope': wrong['apps']['recursive_a']['interfaces']['local'] = {'scope':'app-network','network':'default'}
            else: wrong['guests']['resolver']['resources']['memory_mib'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.resolve(wrong)

    def test_complete_template_profile_runtime_and_app_leaves_preserve_packets(self):
        _, before = self.resolve()
        library = authored_config.read(self.config / 'stack.json')
        leaf = self.config / 'base.yaml'
        leaf.write_text(example_text('library.md', 'template-minimal'))
        library['guest_templates']['base'] = {'source':'base.yaml'}
        library['app_profiles']['recursive'] = example('supporting-types.md', 'profile-minimal')
        library['runtime_profiles']['resolver'] = example('supporting-types.md', 'runtime-minimal')
        selected = authored_config.read(self.site)
        app_leaf = self.config / 'recursive.yaml'
        app_leaf.write_text(example_text('sources.md', 'source-app'))
        selected['apps']['recursive_a'] = {'source':'recursive.yaml'}
        _, after = self.resolve(selected, library)
        self.assertEqual(after, before)
        selected['apps']['recursive_a']['display_name'] = 'Not an overlay'
        with self.assertRaises(ValueError): self.resolve(selected, library)
        selected['apps']['recursive_a'] = {'source':'recursive.yaml'}
        app_leaf.write_text(example_text('sources.md', 'source-app').replace('kind: app','kind: guest'))
        with self.assertRaises(ValueError): self.resolve(selected, library)
        for wrong in (False, None):
            template = example('library.md', 'template-minimal')
            template.pop('schema'); template.pop('kind')
            if wrong is None: template['security'].pop('protection')
            else: template['security']['protection'] = False
            with self.subTest(protection=wrong), self.assertRaises(ValueError): types.template(template)

    def test_context_storage_and_device_examples_refuse_the_documented_invalid_variations(self):
        context = example('contexts.md','context-minimal')
        context.update(example('contexts.md','context-capability'))
        types.context(context)
        wrong = copy.deepcopy(context);wrong['trust'].pop('known_hosts')
        with self.assertRaises(ValueError):types.context(wrong)
        rows=example('storage.md','storage-combination')
        types.volume(rows['volume']);types.storage_role(rows['profile_role'])
        types.app(dict(example('apps.md','app-minimal'),storage={'data':rows['app_binding']}))
        for target in ('volume','profile_role'):
            wrong=copy.deepcopy(rows)
            if target=='volume':wrong[target]['path']='/etc/example-data'
            else:wrong[target]['read_only']=True
            with self.subTest(target=target),self.assertRaises(ValueError):
                (types.volume if target=='volume' else types.storage_role)(wrong[target])
        types.device(example('supporting-types.md','device-minimal'))
        wrong=dict(example('supporting-types.md','device-minimal'),path='/dev/ttyUSB0')
        with self.assertRaises(ValueError):types.device(wrong)
        wrong=example('supporting-types.md','profile-minimal');wrong['listeners']['udp']['interface']='missing'
        with self.assertRaises(ValueError):types.profile(wrong)
        wrong=example('supporting-types.md','runtime-minimal');wrong['containers']['unbound']['cpu_limit']=True
        with self.assertRaises(ValueError):types.runtime(wrong)

    def test_network_group_rule_binding_and_middleware_examples_compile_in_combination(self):
        selected=authored_config.read(self.site)
        selected['address_groups']=example('networks.md','network-groups')
        selected['policies']={'network':{'selected_service':example('policies.md','policy-network')},
            'middlewares':{'office_only':example('policies.md','policy-middleware')}}
        selected['guests']['resolver']['network_policy']=[example('policies.md','policy-binding')]
        plan,_=self.resolve(selected)
        self.assertEqual(plan.resolved['guests']['resolver']['rules'][0]['destination'],'192.0.2.10/32')
        self.assertEqual(plan.resolved['guests']['resolver']['rules'][0]['port'],'8006')
        self.assertEqual(component_addresses.resolve(selected['address_groups'],selected['networks'])['clients'],
                         ['198.18.20.0/24','198.18.15.0/28'])
        for change in ('cidr','cycle','dhcp-flag','ranges-map','missing-binding','unused-binding'):
            wrong=copy.deepcopy(selected)
            if change=='cidr':wrong['networks']['primary']['cidr']='198.18.20.10/24'
            elif change=='cycle':wrong['address_groups']['vpn']={'members':[{'address_group':'vpn'}]}
            elif change=='dhcp-flag':wrong['guests']['resolver']['interfaces']['management']['address']={'mode':'dhcp','endpoint':'198.18.20.10'}
            elif change=='ranges-map':wrong['policies']['middlewares']['office_only']['ranges']={'address_group':'clients'}
            elif change=='missing-binding':wrong['guests']['resolver']['network_policy'][0]['endpoints']={}
            else:wrong['guests']['resolver']['network_policy'][0]['endpoints']['unused']={'external':'dns'}
            with self.subTest(change=change),self.assertRaises(ValueError):self.resolve(wrong)

    def test_network_nic_variants_and_exact_refusals(self):
        selected = authored_config.read(self.site)
        assert_typed_equal(example('networks.md', 'network-minimal'), selected['networks']['primary'],
                           'networks.md/network-minimal -> first-configuration/site.yaml:networks.primary')
        assert_typed_equal(example('networks.md', 'nic-minimal'), selected['guests']['resolver']['interfaces']['management'],
                           'networks.md/nic-minimal -> first-configuration/site.yaml:guests.resolver.interfaces.management')
        before, packets = self.resolve(selected)
        self.assertEqual(set(packets), {'resolver'})
        self.assertEqual(before.resolved['guests']['resolver']['provider_interfaces'][0]['ipv4'], '198.18.20.10/24')
        dhcp = copy.deepcopy(selected)
        nic = dhcp['guests']['resolver']['interfaces']['management']
        nic['address'] = {'mode': 'dhcp', 'endpoint': '198.18.20.10'}
        nic.pop('default_route')
        plan, _ = self.resolve(dhcp)
        provider = plan.resolved['guests']['resolver']['provider_interfaces'][0]
        self.assertEqual((provider['ipv4'], provider['ipv4_endpoint'], provider['gateway']),
                         ('dhcp', '198.18.20.10/24', None))
        manual = copy.deepcopy(selected)
        manual['guests']['resolver']['interfaces']['backend']['address'] = {'mode': 'manual'}
        plan, _ = self.resolve(manual)
        self.assertIsNone(plan.resolved['guests']['resolver']['interface_addresses']['backend'])
        self.assertEqual(plan.resolved['guests']['resolver']['provider_interfaces'][1]['ipv4'], 'manual')
        manual_control = copy.deepcopy(manual)
        manual_control['guests']['resolver']['control_interface'] = 'backend'
        expect_component_refusal(lambda: self.resolve(manual_control), 'component.control-interface',
                                 ('guests', 'resolver'))
        for vlan in (None, 1, 4094):
            valid = copy.deepcopy(selected)
            valid['networks']['primary']['vlan'] = vlan
            self.resolve(valid)
        # Each variation starts from the same complete, proven-valid source.
        # Expected diagnostics are the actual current boundary, including generic
        # resolution errors; none implies native network/service qualification.
        network_path = ('networks', 'primary')
        nic_path = ('guests', 'resolver', 'interfaces', 'management')
        variations = (
            (network_path + ('cidr',), '198.18.20.10/24', 'component.invalid', network_path),
            (network_path + ('context',), '', 'component.invalid', network_path),
            (network_path + ('bridge',), '', 'component.invalid', network_path),
            (network_path + ('vlan',), 4095, 'component.integer', network_path),
            (network_path + ('vlan',), True, 'component.integer', network_path),
            (network_path + ('gateway',), None, 'component.invalid', network_path),
            (network_path + ('gateway',), '198.18.20.0', 'component.invalid', network_path),
            (network_path + ('unexpected',), True, 'component.fields', network_path),
            (nic_path + ('network',), 'missing', 'component.invalid', ()),
            (nic_path + ('slot',), True, 'component.integer', nic_path),
            (nic_path + ('slot',), 32, 'component.integer', nic_path),
            (nic_path + ('slot',), 2, 'component.invalid', ('guests', 'resolver')),
            (nic_path + ('mac',), 'not-a-mac', 'component.invalid', nic_path),
            (nic_path + ('ipv6',), None, 'component.invalid', nic_path),
            (nic_path + ('default_route',), None, 'component.invalid', nic_path),
            (nic_path + ('address',), {'mode': 'dhcp', 'endpoint': '198.18.20.10'}, 'component.invalid', nic_path),
            (nic_path + ('address',), {'mode': 'static'}, 'component.fields', nic_path),
            (nic_path + ('address',), {'mode': 'dhcp'}, 'component.fields', nic_path),
            (nic_path + ('address',), {'mode': 'manual', 'value': '198.18.20.10'}, 'component.fields', nic_path),
            (nic_path + ('address',), {'mode': 'other'}, 'component.invalid', nic_path),
            (nic_path + ('address', 'value'), '198.18.20.0', 'component.invalid', ()),
            (nic_path + ('default_route',), False, 'component.default-route', ('guests', 'resolver')),
        )
        for path, value, code, error_path in variations:
            with self.subTest(path=path, value=value):
                wrong = copy.deepcopy(selected)
                target = wrong
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                expect_component_refusal(lambda: self.resolve(wrong), code, error_path)

    def test_unused_network_context_is_only_checked_when_consumed(self):
        selected = authored_config.read(self.site)
        selected['networks']['unused'] = dict(selected['networks']['primary'], context='missing')
        self.resolve(selected)
        selected['guests']['resolver']['interfaces']['management']['network'] = 'unused'
        expect_component_refusal(lambda: self.resolve(selected), 'component.invalid', ())

    def test_managed_connection_account_and_exposure_examples_use_real_binders_and_lowering(self):
        # The reader can obtain this complete composition from authored docs;
        # the test does not hide required declarations in a Python fixture.
        complete=ROOT/'docs/examples/relationships'
        library=authored_config.read(complete/'stack.json')
        selected=authored_config.read(complete/'site.yaml')
        shutil.copyfile(complete/'images.json',self.config/'images.json')
        self.assertEqual(selected['connections']['broker'],example('connections.md','connection-managed'))
        self.assertEqual(selected['accounts']['client'],example('connections.md','account-managed'))
        self.assertEqual(selected['secret_sources']['browser_password'],example('connections.md','account-source'))
        exposure=example('exposures.md','exposure-http');exposure.pop('schema');exposure.pop('kind')
        self.assertEqual(selected['exposures']['browser'],dict(exposure,middlewares=['headers','office_only']))
        plan,packets=self.resolve(selected,library)
        self.assertEqual(plan.resolved['apps']['browser']['origin_url'],'https://browser.example.invalid')
        self.assertIn('component-runtime.json',packets['resolver']['files'])
        self.assertEqual(selected['policies']['middlewares']['office_only'],example('policies.md','policy-middleware'))
        for change in ('both-credentials','wrong-role','duplicate-domain','missing-tls'):
            wrong=copy.deepcopy(selected)
            if change=='both-credentials':wrong['connections']['broker']['credential']={'principal':'browser','secret':'probe'}
            elif change=='wrong-role':wrong['connections']['broker']['source_interface']='missing'
            elif change=='duplicate-domain':wrong['exposures']['browser']['aliases']=['browser']
            else:wrong['exposures']['browser']['tls']='missing'
            with self.subTest(change=change),self.assertRaises(ValueError):self.resolve(wrong,library)

    def test_complete_public_transport_example_reaches_only_its_owned_file_and_read_only_mount(self):
        import component_foundation_files
        complete=ROOT/'docs/examples/backend-transport'
        library=authored_config.read(ROOT/'docs/examples/relationships/stack.json')
        selected=authored_config.read(complete/'site.yaml')
        shutil.copyfile(ROOT/'docs/examples/relationships/images.json',self.config/'images.json')
        shutil.copyfile(complete/'transport.yaml',self.config/'transport.yaml')
        declared=authored_config.read(complete/'transport.yaml')
        pem=declared['certificate']
        self.assertEqual(pem,(ROOT/'proxmox/applications/tests/transport-synthetic-public-certificate.txt').read_text())
        plan,packets=self.resolve(selected,library)
        self.assertEqual(set(packets),{'edge'})
        app=plan.resolved['apps']['ingress']
        self.assertEqual(app['settings']['route_ca_files'],{})
        self.assertEqual(app['settings']['route_ca_certificates'],{
            'backend':{'certificate':pem,'filename':'route-backend.pem'}})
        self.assertEqual(plan.resolved['transports']['backend']['server_name'],'backend.example.invalid')
        files=packets['edge']['files'];runtime=json.loads(files['component-runtime.json'])
        lowered=runtime['applications']['ingress']
        provider={'schema':'homelab-service-discovery-v1','identity':'fixture@pve!discovery',
                  'token':'fixture@pve!discovery=synthetic-source-only-value'}
        rows=component_foundation_files.files(lowered,secrets={
            'proxmox_token':json.dumps(provider).encode(),'cloudflare_dns_token':b'synthetic-source-only-value'},
            public_ca=pem.encode(),route_cas={},route_plan=lowered['route_plan'])
        trust=next(row for row in rows if row['path']=='route-backend.pem')
        self.assertEqual((trust['content'],trust['uid'],trust['gid'],trust['mode']),(pem.encode(),0,0,'0400'))
        compose=authored_config.parse(files['compose-ingress.yml'].encode(),'.yaml')
        service=next(iter(compose['services'].values()))
        mount=next(row for row in service['volumes'] if row['target']=='/etc/ssl/certs/route-backend.pem')
        self.assertTrue(mount['read_only'])
        self.assertEqual(mount['source'],lowered['identity']['runtime_directory']+'/route-backend.pem')
        shared=json.loads(next(row['content'] for row in rows if row['path']=='shared.yml'))
        self.assertEqual(shared['http']['serversTransports']['backend'],{
            'serverName':'backend.example.invalid','rootCAs':['/etc/ssl/certs/route-backend.pem']})
        self.assertEqual(shared['http']['services']['backend']['loadBalancer']['servers'],[
            {'url':'https://198.18.25.80:8443'}])
        wrong=copy.deepcopy(selected)
        wrong['policies']['transport']['backend']=example('policies.md','transport-conflicting-trust')
        expect_component_refusal(lambda:self.resolve(wrong,library),'component.transport',('policies','transport','backend'))
        wrong=copy.deepcopy(selected);wrong['external_endpoints']['backend']['protocol']='http'
        expect_component_refusal(lambda:self.resolve(wrong,library),'component.transport',('exposures','backend'))

    def test_all_adapter_property_objects_validate_and_named_invalid_properties_refuse(self):
        values=example('app-properties.md','properties-adapters')
        self.assertEqual(set(values),component_foundations.OWNED | component_properties.ADAPTERS)
        for adapter,value in values.items():
            with self.subTest(adapter=adapter):
                (component_foundations.validate if adapter in component_foundations.OWNED else component_properties.validate)(adapter,value)
        for adapter,changes in [('authentik',{'smtp':dict(values['authentik']['smtp'],use_ssl=True)}),
                ('bitwarden',{'data_uid':True}),('bitwarden',{'image_id':'retired'}),
                ('mqtt_explorer',{'connection_name':'two\nlines'})]:
            wrong=dict(values[adapter],**changes)
            with self.subTest(adapter=adapter,changes=changes),self.assertRaises(ValueError):
                (component_foundations.validate if adapter in component_foundations.OWNED else component_properties.validate)(adapter,wrong)

    def test_cloud_unmanaged_property_example_is_not_a_complete_owned_account_configuration(self):
        # Conforming reference/placement collaborators; the real property binder
        # creates the DTO consumed by the real account binder, which owns this
        # later floor. No assertion that this fragment is a deployable app.
        value=example('app-properties.md','properties-adapters')['cloudbeaver']
        app={'id':'browser','adapter':'cloudbeaver','lifecycle':'fresh',
             'origin_url':'https://browser.example.invalid',
             'resolved_connections':{'reporting':{'type':'postgresql',
                 'target':{'protocol':'tcp','address':'198.18.31.23','port':5432}}}}
        resolver=SimpleNamespace(apps={'browser':app},role_address=lambda app,role:'198.18.30.12')
        app['settings']=component_properties._cloudbeaver(resolver,app,value)
        self.assertEqual(app['settings']['managed_connections'],{})
        self.assertEqual(set(app['settings']['connections']),{'reporting'})
        with self.assertRaisesRegex(ValueError,'Keep new owned administrator connections separate'):
            component_accounts.bind(resolver,{})

    def test_secret_and_oidc_values_use_real_source_and_provider_validators(self):
        for name in ('secret-file','secret-environment'):component_secrets.source(example('identity-and-secrets.md',name))
        wrong=dict(example('identity-and-secrets.md','secret-file'),workflow_secret='FORBIDDEN')
        with self.assertRaises(ValueError):component_secrets.source(wrong)
        provider=example('identity-and-secrets.md','identity-oidc')
        resolver=SimpleNamespace(site={'identity_providers':{'login':provider}})
        exposures=SimpleNamespace(domains={'login':'login.example.invalid'},resolved={})
        self.assertEqual(component_auth.providers(resolver,exposures)['login']['issuer'],
                         'https://login.example.invalid/application/o/example/')
        for change in ({'signing_algorithms':['HS256']},{'issuer_path':'/application/o/example/?query'}):
            resolver.site['identity_providers']['login']=dict(provider,**change)
            with self.subTest(change=change),self.assertRaises(ValueError):component_auth.providers(resolver,exposures)

    def test_monitoring_selection_and_lifecycle_examples_keep_their_distinct_boundaries(self):
        selected=authored_config.read(self.site)
        fragment=example('zabbix.md','zabbix-selection');selected.update(fragment)
        # Validate source shape and the server selector, without pretending this
        # minimal fixture has an actual monitoring installation.
        self.site.write_text(json.dumps(selected));loaded,_=component_sources.site(self.site)
        resolver=SimpleNamespace(site=loaded,apps={'monitoring':{'adapter':'zabbix'}})
        self.assertEqual(component_monitoring.server(resolver),'monitoring')
        profile=example('zabbix.md','zabbix-profile');component_monitoring.profile(profile)
        selected['zabbix']=False;self.site.write_text(json.dumps(selected))
        with self.assertRaises(ValueError):component_sources.site(self.site)
        fresh=example('lifecycle.md','lifecycle-fresh')
        types.app(fresh)
        selected=example('site.md','site-worked');selected['apps']['recursive_a']=fresh
        _,before=self.resolve(selected);_,after=self.resolve(selected)
        self.assertEqual(before,after)
        with self.assertRaises(ValueError):types.app(dict(fresh,lifecycle='update'))

    def test_backup_reference_fragments_use_actual_owners_and_refuse_documented_invalid_values(self):
        # These are documented fragments, not a complete site. The library's
        # operational example supplies the integration and packet evidence.
        profile = example('backup.md', 'backup-profile')
        self.assertEqual((profile.pop('schema'), profile.pop('kind')),
                         ('homelab-components-v1', 'backup-profile'))
        component_backup.profile(profile)
        resolver = SimpleNamespace(site=example('backup.md', 'backup-selection'),
                                   library={'backup_profiles': {'pbs-client': profile}})
        for selection in (resolver.site, {'backup': {}},
                          example('backup.md', 'backup-profile-selection')):
            resolver.site = selection
            self.assertEqual(component_backup.selected(resolver), 'pbs-client')
        resolver.site = {}
        self.assertIsNone(component_backup.selected(resolver))
        for value in (True, False, {'enabled': True}):
            expect_component_refusal(lambda: component_backup.presence(value),
                                     'component.backup-presence', ())
        for value in (None, {}):
            component_backup.presence(value)
            volume = dict(example('storage.md', 'storage-combination')['volume'], backup=value)
            types.volume(volume)
        rule = example('backup.md', 'backup-application')['backup']
        component_backup.application(rule, {'data': {}, 'logs': {}})
        expect_component_refusal(lambda: component_backup.application(rule, {'data': {}, 'logs': {}, 'new': {}}),
                                 'component.backup-coverage', ())
        wrong = copy.deepcopy(rule)
        wrong['include']['data']['capture'] = 'files'
        expect_component_refusal(lambda: component_backup.application(wrong, {'data': {}, 'logs': {}}),
                                 'component.backup-consistency', ('include', 'data'))
        job = example('backup.md', 'backup-job')['backup']['job']
        component_backup_job.job(job)
        missing = copy.deepcopy(job)
        del missing['clients']
        expect_component_refusal(lambda: component_backup_job.job(missing), 'component.fields', ())
        invalid = copy.deepcopy(job)
        invalid['schedule']['calendar'] = '24:00'
        expect_component_refusal(lambda: component_backup_job.job(invalid), 'component.backup-schedule', ())

    def test_all_named_configuration_examples_are_in_the_explicit_execution_inventory(self):
        for page,names in EXAMPLES.items():
            with self.subTest(page=page):
                actual=re.findall(r'<!-- example: ([a-z0-9-]+) -->',(ROOT/'docs/reference'/page).read_text())
                self.assertEqual(sorted(actual),sorted(names))
                for name in names:self.assertIsInstance(example(page,name),dict)


if __name__=='__main__':unittest.main()
