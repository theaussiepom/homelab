"""Typed references preserve interfaces, publications and explicit rule intent."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import component_plan
import component_sources as source


def library():
    return {'schema': source.SCHEMA, 'kind': 'library',
            'guest_templates': {'base': {
                'resources': {'cpu_cores': 1, 'memory_mib': 512, 'root_gib': 8, 'os_reserve_mib': 128},
                'startup': {'started': True, 'start_on_boot': True, 'boot_order': 30},
                'security': {'unprivileged': True, 'protection': True, 'nesting': True, 'keyctl': False}}},
            'app_profiles': {'recursive': {
                'adapter': 'unbound', 'display_name': 'Recursive DNS',
                'interfaces': {'private_interface': {'required': True, 'accepts': ['app-network']},
                               'local_interface': {'required': True, 'accepts': ['guest-loopback']}},
                'listeners': {'udp_listener': {'service': 'unbound', 'namespace': 'app-network',
                    'interface': 'private_interface', 'bind': 'wildcard', 'protocol': 'udp', 'port': 53,
                    'publish': {'scope': 'guest-loopback', 'port': 5335}}},
                'endpoints': {'dns_endpoint': {'listener': 'udp_listener', 'protocol': 'udp', 'via': 'local_interface'}}}}}


def site():
    return {'schema': source.SCHEMA, 'kind': 'site',
            'contexts': {'lab': {'backend': 'proxmox-lxc', 'node': 'example-node',
                'api_endpoint': {'external': 'api'},
                'trust': {'ca_file': '/example/ca.pem', 'known_hosts': '/example/known_hosts'},
                'credentials': {'api_token': 'token', 'ssh_private_key': 'ssh'},
                'paths': {'state_root': '/example/state', 'backup_directory': '/example/backup/data',
                          'backup_mount': '/example/backup', 'backup_source': 'example:/backup'},
                'protected_guests': [9900, 9914, 9915, 9920], 'ssh_public_keys': [],
                'dns_servers': [{'external': 'dns'}]}},
            'secret_sources': {'token': {'type': 'file', 'path': '/never-read/token'},
                               'ssh': {'type': 'file', 'path': '/never-read/ssh'}},
            'external_endpoints': {'api': {'protocol': 'https', 'address': '192.0.2.10', 'port': 8006},
                                   'dns': {'protocol': 'udp', 'address': '198.18.21.53', 'port': 53}},
            'networks': {'primary': {'context': 'lab', 'cidr': '198.18.20.0/24', 'bridge': 'example0',
                                     'vlan': None, 'gateway': '198.18.20.1'},
                         'secondary': {'context': 'lab', 'cidr': '198.18.21.0/24', 'bridge': 'example1',
                                       'vlan': 121, 'gateway': '198.18.21.1'}},
            'storage': {'local': {'context': 'lab', 'pool': 'example-local'}},
            'guests': {'resolver': {'context': 'lab', 'template': 'base', 'lifecycle': 'fresh',
                'identity': {'vmid': 610, 'hostname': 'example-dns'},
                'template_file_id': 'example:vztmpl/debian.tar.zst', 'root_storage': 'local',
                'control_interface': 'management',
                'interfaces': {
                    'management': {'network': 'primary', 'slot': 0, 'mac': '02:00:00:20:00:10',
                        'address': {'mode': 'static', 'value': '198.18.20.10'},
                        'default_route': True, 'ipv6': 'manual'},
                    'backend': {'network': 'secondary', 'slot': 1, 'mac': '02:00:00:21:00:10',
                        'address': {'mode': 'static', 'value': '198.18.21.10'}, 'ipv6': 'manual'}}}},
            'apps': {'recursive_a': {'profile': 'recursive', 'guest': 'resolver', 'lifecycle': 'fresh',
                'interfaces': {'private_interface': {'scope': 'app-network', 'network': 'default'},
                               'local_interface': {'scope': 'guest-loopback'}}}}}


class PlanTests(unittest.TestCase):
    def test_vmids_are_unique_across_nodes_of_the_same_declared_api_authority(self):
        value=site()
        value['contexts']['other']=copy.deepcopy(value['contexts']['lab'])
        value['contexts']['other']['node']='another-node'
        value['storage']['other']={'context':'other','pool':'other-local'}
        for key in ('primary','secondary'):
            value['networks']['other_'+key]=dict(value['networks'][key],context='other')
        guest=copy.deepcopy(value['guests']['resolver'])
        guest.update(context='other',root_storage='other')
        guest['identity']['hostname']='another-resolver'
        for row in guest['interfaces'].values():
            row['network']='other_'+row['network'];row['mac']=row['mac'][:-2]+'11'
            row['address']['value']=row['address']['value'][:-2]+'11'
        value['guests']['another']=guest
        with self.assertRaisesRegex(ValueError,'guest-identity'):self.resolve(selected=value)
        value['external_endpoints']['other_api']={'protocol':'https','address':'192.0.2.11','port':8006}
        value['contexts']['other']['api_endpoint']={'external':'other_api'}
        plan=self.resolve(selected=value)
        self.assertEqual([v['identity']['vmid']for v in plan.resolved['guests'].values()],[610,610])
        self.assertEqual(len(plan.resolved['guests']['another']['provider_interfaces']),2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stack = self.root / 'library'
        self.consumer = self.root / 'consumer'
        self.stack.mkdir()
        self.consumer.mkdir()

    def resolve(self, authored=None, selected=None):
        (self.stack / 'stack.json').write_text(json.dumps(library() if authored is None else authored))
        path = self.consumer / 'site.json'
        path.write_text(json.dumps(site() if selected is None else selected))
        return component_plan.resolve(self.stack, path)

    def test_effective_static_route_and_secondary_gateway_omission(self):
        plan = self.resolve()
        guest = plan.resolved['guests']['resolver']
        first, second = guest['provider_interfaces']
        self.assertEqual(first, {'bridge': 'example0', 'vlan': None, 'mac': '02:00:00:20:00:10',
                         'ipv4': '198.18.20.10/24', 'gateway': '198.18.20.1', 'ipv6': 'manual'})
        self.assertNotIn('gateway', second)
        self.assertEqual(second['ipv6'], 'manual')
        self.assertEqual(guest['dns_servers'], ['198.18.21.53'])
        self.assertEqual(plan.resolved['contexts']['lab']['api_endpoint'], 'https://192.0.2.10:8006')
        self.assertEqual(plan.resolved['endpoints']['app/recursive_a/dns_endpoint']['address'], '127.0.0.1')
        plan.check()
        guest['identity']['vmid'] = 611
        with self.assertRaises(ValueError):
            plan.check()

    def test_reserved_double_root_aliases_fail_through_actual_source_resolution(self):
        for path in ('//etc','//opt/homelab-app','//var/lib/homelab-managed-credentials'):
            value=site();value['guests']['resolver']['root_paths']={'owned':{'path':path}}
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'component.path'):
                self.resolve(selected=value)
        value=site();value['guests']['resolver']['root_paths']={'owned':{'path':'/srv/example/apps'}}
        self.resolve(selected=value)

    def test_explicit_source_policy_route_derives_one_nic_without_network_policy_changes(self):
        selected = site()
        selected['guests']['resolver']['source_policy_route'] = {'interface': 'backend'}
        plan = self.resolve(selected=selected)
        guest = plan.resolved['guests']['resolver']
        self.assertEqual(guest['frontend_routing'], {'address': '198.18.21.10/24',
            'gateway': '198.18.21.1', 'mac': '02:00:00:21:00:10'})
        self.assertEqual(guest['rules'], [])
        self.assertEqual(plan.resolved['guest_dependencies'], {'resolver': []})
        self.assertNotIn('frontend_routing', self.resolve().resolved['guests']['resolver'])
        changes = [
            lambda v: v['guests']['resolver']['source_policy_route'].update(interface='management'),
            lambda v: v['guests']['resolver']['source_policy_route'].update(interface='absent'),
            lambda v: v['guests']['resolver']['source_policy_route'].update(table=10041),
            lambda v: v['networks']['secondary'].pop('gateway'),
            lambda v: v['networks']['secondary'].update(gateway='198.18.21.10'),
            lambda v: v['guests']['resolver']['interfaces']['backend'].update(address={'mode': 'manual'}),
        ]
        for change in changes:
            with self.subTest(case=changes.index(change)):
                value = copy.deepcopy(selected)
                change(value)
                with self.assertRaises(ValueError):
                    self.resolve(selected=value)

    def test_dhcp_endpoint_cidr_null_gateway_and_no_implicit_route(self):
        value = site()
        nic = value['guests']['resolver']['interfaces']['management']
        nic['address'] = {'mode': 'dhcp', 'endpoint': '198.18.20.10'}
        nic.pop('default_route')
        result = self.resolve(selected=value).resolved['guests']['resolver']['provider_interfaces'][0]
        self.assertEqual(result['ipv4'], 'dhcp')
        self.assertEqual(result['ipv4_endpoint'], '198.18.20.10/24')
        self.assertIsNone(result['gateway'])
        self.assertEqual(result['ipv6'], 'manual')
        value['guests']['resolver']['interfaces']['backend']['default_route'] = True
        with self.assertRaises(ValueError):
            self.resolve(selected=value)

    def test_two_independent_instances_and_explicit_publication_override(self):
        value = site()
        second = copy.deepcopy(value['apps']['recursive_a'])
        second['properties'] = {'publish_port': 5336}
        value['apps']['recursive_b'] = second
        plan = self.resolve(selected=value)
        a, b = plan.resolved['apps'].values()
        self.assertNotEqual(a['identity']['services'], b['identity']['services'])
        self.assertEqual(plan.resolved['endpoints']['app/recursive_a/dns_endpoint']['port'], 5335)
        self.assertEqual(plan.resolved['endpoints']['app/recursive_b/dns_endpoint']['port'], 5336)
        self.assertEqual(b['listeners']['udp_listener']['port'], 53)
        second.pop('properties')
        with self.assertRaises(ValueError):
            self.resolve(selected=value)

    def test_retained_shared_project_and_cosmetic_display_name_preserve_identity(self):
        value = site()
        guest = value['guests']['resolver']
        guest['lifecycle'] = 'retained'
        guest['compose_projects'] = {'original': {'name': 'original-project'}}
        app = value['apps']['recursive_a']
        app['lifecycle'] = 'retained'
        app['identity'] = {'phase': 'unbound', 'runtime_id': 'unbound', 'project': 'original',
                           'services': {'unbound': 'unbound'}, 'networks': {'default': 'original_default'}}
        original = self.resolve(selected=value).resolved['apps']['recursive_a']['identity']
        app['display_name'] = 'A new visible label'
        self.assertEqual(self.resolve(selected=value).resolved['apps']['recursive_a']['identity'], original)
        app['identity']['services'] = {}
        with self.assertRaises(ValueError):
            self.resolve(selected=value)

    def test_same_local_service_name_in_separate_projects_is_a_distinct_container(self):
        value = site()
        value['guests']['resolver']['compose_projects'] = {
            'first': {'name': 'project-one'}, 'second': {'name': 'project-two'}}
        first = value['apps']['recursive_a']
        first['identity'] = {'project': 'first', 'services': {'unbound': 'unbound'}}
        second = copy.deepcopy(first)
        second['identity']['project'] = 'second'
        second['properties'] = {'publish_port': 5336}
        value['apps']['recursive_b'] = second
        plan = self.resolve(selected=value)
        self.assertEqual(plan.resolved['apps']['recursive_a']['identity']['services'],
                         plan.resolved['apps']['recursive_b']['identity']['services'])
        self.assertEqual(plan.resolved['endpoints']['app/recursive_b/dns_endpoint']['port'], 5336)
        second['identity']['project'] = 'first'
        with self.assertRaises(ValueError):
            self.resolve(selected=value)

    def test_endpoint_policy_uses_one_authority_and_preserves_order_without_inferred_rules(self):
        value = site()
        value['policies'] = {'network': {'dns': {'rules': [
            {'direction': 'out', 'proto': 'udp', 'destination': {'endpoint': 'resolver'},
             'port': {'endpoint': 'resolver'}, 'interface': 'egress', 'comment': 'Existing DNS'},
            {'direction': 'out', 'proto': 'tcp', 'port': '443', 'comment': 'Existing packages'}]}}}
        value['guests']['resolver']['network_policy'] = [{'policy': 'dns',
            'interfaces': {'egress': 'backend'}, 'endpoints': {'resolver': {'external': 'dns'}}}]
        plan = self.resolve(selected=value)
        rows = plan.resolved['guests']['resolver']['rules']
        self.assertEqual(rows[0], {'direction': 'out', 'proto': 'udp', 'destination': '198.18.21.53/32',
                         'port': '53', 'interface': 'net1', 'comment': 'Existing DNS'})
        self.assertEqual([row['comment'] for row in rows], ['Existing DNS', 'Existing packages'])
        value['external_endpoints']['dns']['address'] = '198.18.21.54'
        self.assertEqual(self.resolve(selected=value).resolved['guests']['resolver']['rules'][0]['destination'],
                         '198.18.21.54/32')
        value['guests']['resolver']['network_policy'] = []
        self.assertEqual(self.resolve(selected=value).resolved['guests']['resolver']['rules'], [])

    def test_closed_invalid_routes_references_ownership_and_types(self):
        mutations = [
            lambda v: v['guests']['resolver']['identity'].update(vmid=9900),
            lambda v: v['guests']['resolver']['identity'].update(vmid=True),
            lambda v: v['guests']['resolver']['interfaces']['backend'].update(default_route=True),
            lambda v: v['guests']['resolver']['interfaces']['management'].update(default_route=False),
            lambda v: v['guests']['resolver']['interfaces']['backend'].update(slot=0),
            lambda v: v['guests']['resolver']['interfaces']['backend'].update(ipv6='auto'),
            lambda v: v['guests']['resolver']['interfaces']['backend'].update(mac='02:00:00:20:00:10'),
            lambda v: v['apps']['recursive_a']['interfaces']['private_interface'].update(network='foreign'),
            lambda v: v['apps']['recursive_a']['interfaces'].update(extra_interface={'scope': 'guest-loopback'}),
            lambda v: v['contexts']['lab'].update(api_endpoint={'external': 'dns'}),
            lambda v: v['external_endpoints']['dns'].update(port=54),
            lambda v: v['external_endpoints']['dns'].update(address='secret@example.invalid'),
            lambda v: v['secret_sources']['token'].update(value='must not be read'),
        ]
        for change in mutations:
            with self.subTest(change=mutations.index(change)):
                value = site()
                change(value)
                with self.assertRaises(ValueError):
                    self.resolve(selected=value)

    def test_named_health_and_rootfs_storage_do_not_create_a_provider_volume(self):
        spec, value = library(), site()
        spec['health_profiles'] = {'ready': {'type': 'adapter', 'check': 'readiness'}}
        profile = spec['app_profiles']['recursive']
        profile['health'] = {'ready': {'profile': 'ready'}}
        profile['storage'] = {'configuration': {'target': '/opt/example/config',
            'kind': 'directory', 'read_only': True, 'required': True}}
        value['guests']['resolver']['root_paths'] = {'configuration': {'path': '/srv/example/unbound'}}
        value['apps']['recursive_a']['storage'] = {'configuration': {'root_path': 'configuration', 'subpath': ''}}
        plan = self.resolve(spec, value)
        self.assertEqual(plan.resolved['apps']['recursive_a']['health'],
                         {'ready': {'type': 'adapter', 'check': 'readiness'}})
        self.assertNotIn('volumes', plan.resolved['guests']['resolver'])
        for unsafe in ('/run/docker.sock', '/etc', '/srv/example/../config'):
            with self.subTest(path=unsafe):
                value['guests']['resolver']['root_paths']['configuration']['path'] = unsafe
                with self.assertRaises(ValueError):
                    self.resolve(spec, value)

    def test_remote_physical_address_reference_has_no_fake_listener(self):
        spec, value = library(), site()
        spec['app_profiles']['recursive']['interfaces']['client_interface'] = {
            'required': False, 'accepts': ['guest-interface']}
        value['apps']['recursive_a']['interfaces']['client_interface'] = {'interface': 'backend'}
        value['policies'] = {'network': {'source': {'rules': [
            {'direction': 'in', 'proto': 'tcp', 'source': {'interface': 'client'},
             'port': '5432', 'comment': 'Existing dedicated source'}]}}}
        value['guests']['resolver']['network_policy'] = [{'policy': 'source',
            'interfaces': {'client': {'app': 'recursive_a', 'interface': 'client_interface'}}}]
        plan = self.resolve(spec, value)
        self.assertEqual(plan.resolved['guests']['resolver']['rules'][0]['source'], '198.18.21.10/32')
        self.assertEqual(len(plan.resolved['endpoints']), 3)
        value['policies']['network']['source']['rules'][0]['interface'] = 'client'
        with self.assertRaises(ValueError):
            self.resolve(spec, value)
        del value['policies']['network']['source']['rules'][0]['interface']
        for role in ('private', 'local', 'missing'):
            value['guests']['resolver']['network_policy'][0]['interfaces']['client']['interface'] = role
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.resolve(spec, value)


    def test_address_reference_and_listener_port_transport_are_distinct(self):
        value = site()
        value['policies'] = {'network': {'dns': {'rules': [
            {'direction': 'out', 'proto': 'tcp', 'destination': {'endpoint': 'dns'},
             'port': '53', 'comment': 'Existing explicit TCP DNS'}]}}}
        value['guests']['resolver']['network_policy'] = [{'policy': 'dns', 'endpoints': {'dns': {'external': 'dns'}}}]
        plan = self.resolve(selected=value)
        self.assertEqual(plan.resolved['guests']['resolver']['rules'][0]['port'], '53')
        self.assertEqual(len(plan.resolved['guests']['resolver']['rules']), 1)
        value['policies']['network']['dns']['rules'][0]['port'] = {'endpoint': 'dns'}
        with self.assertRaises(ValueError):
            self.resolve(selected=value)

    def test_private_archive_binding_preserves_the_declared_policy_only(self):
        spec, value = library(), site()
        spec['software'] = {'example': {'images': {'unbound': 'retained'}}}
        spec['app_profiles']['recursive']['software'] = ['example']
        original = {'local_id': 'sha256:' + '0' * 64, 'archive': '/example/original.tar',
                    'archive_sha256': '0' * 64}
        (self.stack / 'images.json').write_text(json.dumps({'retained': original}))
        value['images'] = {'retained': {'local_id': 'sha256:' + 'a' * 64,
                                      'archive': '/private/example.tar', 'archive_sha256': 'b' * 64}}
        result = self.resolve(spec, value).resolved['images']['retained']
        self.assertEqual(result['image'], 'sha256:' + 'a' * 64)
        self.assertEqual(result['archive'], '/private/example.tar')
        spec['app_profiles']['recursive']['software'] = []
        with self.assertRaisesRegex(ValueError, 'component.image-binding-unused'):
            self.resolve(spec, value)
        spec['app_profiles']['recursive']['software'] = ['example']
        for invalid in ({'repository': 'example/vendor', 'tag': 'stable', 'digest': 'sha256:' + 'c' * 64},
                        {'local_id': 'sha256:' + 'a' * 64, 'archive': 'relative.tar', 'archive_sha256': 'b' * 64}):
            value['images']['retained'] = invalid
            with self.subTest(kind=list(invalid)), self.assertRaises(ValueError):
                self.resolve(spec, value)

    def test_validation_error_identifies_safe_property_without_echoing_values(self):
        value = site()
        value['guests']['resolver']['identity']['vmid'] = 'PRIVATE_PASSWORD_MUST_NOT_APPEAR'
        with self.assertRaises(ValueError) as raised:
            self.resolve(selected=value)
        self.assertEqual(str(raised.exception), 'component.integer at guests.resolver.identity.vmid')
        self.assertNotIn('PRIVATE_PASSWORD', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
