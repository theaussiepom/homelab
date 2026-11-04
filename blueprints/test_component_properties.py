"""Unit property/adapter boundaries with synthetic conforming component fakes."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FRAMEWORK = Path(Path(__file__).resolve().parents[1])
sys.path[:0] = [str(FRAMEWORK/'blueprints'), str(FRAMEWORK/'proxmox/applications')]
import component_properties as properties
from component_errors import ComponentError


def metadata():
    return {'server_name': 'Database tools', 'recovery_admin': 'local-recovery', 'heap_mib': 1024,
            'auth_headers': {'user': 'X-User', 'team': 'X-Team'}, 'retained_pgadmin_image': 'old-client',
            'connections': {'postgresql': {'name': 'Postgres', 'database': 'postgres', 'sslmode': 'prefer'},
                            'mariadb': {'name': 'Maria', 'database': ''},
                            'postgresql-admin': {'name': 'Postgres administrator', 'database': 'postgres'},
                            'mariadb-admin': {'name': 'Maria administrator', 'database': ''}},
            'mariadb_jdbc': {'version': '3.5.11', 'sha256': 'a'*64,
                             'image_filename': 'mariadb-java-client-3.5.10.jar'}}


def connection(kind, address, port, account=False):
    value = {'type': kind, 'target': {'address': address, 'port': port, 'protocol': 'tcp'}}
    if account:value['account'] = {'owner': 'declared-consumer', 'credential_id': 'independent-account'}
    return value


def fixture():
    cloud = {'id': 'cloud', 'adapter': 'cloudbeaver', 'lifecycle': 'retained', 'properties': metadata(),
             'origin_url': 'https://db.example.invalid', 'role_addresses': {'web': '198.18.30.32'},
             'resolved_connections': {'postgresql': connection('postgresql', '198.18.31.23', 5432),
                                      'mariadb': connection('mariadb', '198.18.32.24', 3306),
                                      'postgresql-admin': connection('postgresql', '198.18.31.23', 5432, True),
                                      'mariadb-admin': connection('mariadb', '198.18.32.24', 3306, True)}}
    bitwarden = {'id': 'vault', 'adapter': 'bitwarden', 'lifecycle': 'retained',
        'properties': {'runtime_env_sha256': 'b'*64, 'issuer': {'protocol': 'https', 'domain': 'vault-issuer'},
                       'image_id': 'sha256:'+'c'*64, 'database_name': 'retained_vault', 'data_uid': 1000, 'data_gid': 1000},
        'origin_url': 'https://vault.example.invalid', 'role_addresses': {'web': '198.18.30.34'},
        'secrets': {'runtime_environment': 'old_vault_environment'},
        'resolved_connections': {'database': connection('mariadb', '198.18.32.24', 3306)}}
    edge = {'id': 'edge', 'adapter': 'traefik', 'interfaces': {'management': {'interface': 'control'}},
            'role_addresses': {'management': '198.18.25.33'}}
    pega = {'id': 'manager', 'adapter': 'pegaprox', 'properties': {'trusted_proxy': {'app': 'edge', 'interface': 'management'}},
        'role_addresses': {'web': '198.18.25.35'}, 'secrets': {'database_key': 'old_manager_key'}}
    winet = {'id': 'telemetry', 'adapter': 'winet', 'properties': {'mqtt_prefix': 'winet-extractor/site'},
        'secrets': {'options': 'old_telemetry_options'}, 'resolved_connections': {
        'broker': dict(connection('mqtt', '198.18.30.37', 1883), hostname='broker.mqtt'),
        'inverter': connection('https', '198.18.107.23', 443)}}
    node = {'id': 'flow', 'adapter': 'node_red', 'properties': {}}
    return SimpleNamespace(apps={'cloud': cloud, 'vault': bitwarden, 'edge': edge, 'manager': pega,
        'telemetry': winet, 'flow': node}, site={'domains': {'vault-issuer': 'retained-issuer.example.invalid'},
        'secret_sources': {'old_vault_environment': {'type': 'file', 'path': '/declared/controller/vault-environment.json'},
                           'old_manager_key': {'type': 'file', 'path': '/declared/controller/manager-key'},
                           'old_telemetry_options': {'type': 'file', 'path': '/declared/controller/telemetry-options.json'}}},
        image_values=lambda: {'old-client': {'image': 'registry.example.invalid/old-client@sha256:'+'d'*64}},
        role_address=lambda app, role: app['role_addresses'][role])


class ValidationUnitTests(unittest.TestCase):
    def test_each_owned_adapter_validates_its_own_complete_closed_properties(self):
        r = fixture()
        for app in r.apps.values():
            if app['adapter'] in properties.ADAPTERS:
                with self.subTest(adapter=app['adapter']):
                    self.assertEqual(properties.validate(app['adapter'], app['properties']), app['properties'])

    def test_partial_profile_defaults_do_not_require_private_instance_fields(self):
        for kind in properties.ADAPTERS:
            with self.subTest(kind=kind):self.assertEqual(properties.validate(kind, {}, partial=True), {})
        self.assertEqual(properties.validate('cloudbeaver', {'heap_mib': 1024}, partial=True), {'heap_mib': 1024})

    def test_partial_values_are_still_validated_and_full_required_values_refuse(self):
        for kind in properties.ADAPTERS-{'node_red'}:
            with self.subTest(kind=kind):
                with self.assertRaises(ComponentError):properties.validate(kind, {})
        with self.assertRaises(ComponentError):properties.validate('cloudbeaver', {'heap_mib': True}, partial=True)

    def test_unknown_bag_or_unsupported_adapter_refuses(self):
        for kind in properties.ADAPTERS:
            with self.subTest(kind=kind):
                with self.assertRaises(ComponentError):properties.validate(kind, {'legacy': {}}, partial=True)
        with self.assertRaises(ComponentError):properties.validate('future-adapter', {})
        with self.assertRaises(ComponentError):properties.validate({}, {})

    def test_cloud_metadata_cannot_supply_topology_account_or_password(self):
        for key, value in (('host', '198.18.31.99'), ('port', 4444), ('driver', 'arbitrary'),
                           ('username', 'shared-root'), ('password', 'synthetic'), ('account_id', 'foreign')):
            with self.subTest(key=key):
                value_ = metadata();value_['connections']['postgresql'][key] = value
                with self.assertRaises(ComponentError):properties.validate('cloudbeaver', value_)

    def test_cloud_header_routing_injection_duplicate_and_heap_name_limits_refuse(self):
        for mutate in (lambda v: v.update(heap_mib=255), lambda v: v.update(server_name='x\n'),
                       lambda v: v.update(recovery_admin='oidc:collision'),
                       lambda v: v['auth_headers'].update(user='X-Forwarded-Host'),
                       lambda v: v['auth_headers'].update(team='x-user')):
            with self.subTest(mutate=mutate):
                value = metadata();mutate(value)
                with self.assertRaises(ComponentError):properties.validate('cloudbeaver', value)

    def test_jdbc_delegates_the_existing_closed_official_artifact_contract(self):
        import cloudbeaver
        value = metadata()
        with patch.object(cloudbeaver, 'jdbc', wraps=cloudbeaver.jdbc) as validate:
            properties.validate('cloudbeaver', value)
        validate.assert_called_once()
        for update in ({'version': '3.5.10'}, {'url': 'https://foreign.invalid/driver.jar'}, {'sha256': 'bad'}):
            with self.subTest(update=update):
                selected = metadata();selected['mariadb_jdbc'].update(update)
                with self.assertRaises(ComponentError):properties.validate('cloudbeaver', selected)

    def test_bitwarden_hash_image_owner_database_and_issuer_refs_are_typed(self):
        original = fixture().apps['vault']['properties']
        for key, value in (('runtime_env_sha256', 'bad'), ('image_id', 'latest'), ('data_uid', True),
                           ('data_gid', 0), ('database_name', 'bad;schema'),
                           ('issuer', {'url': 'https://foreign.invalid/'})):
            with self.subTest(key=key):
                selected = dict(original, **{key: value})
                with self.assertRaises(ComponentError):properties.validate('bitwarden', selected)

    def test_pega_trusted_proxy_is_a_named_physical_role_not_an_address(self):
        for selected in ('198.18.25.33/32', {'app': 'edge'}, {'app': 'edge', 'interface': 'management', 'address': 'foreign'}):
            with self.subTest(selected=selected):
                with self.assertRaises(ComponentError):properties.validate('pegaprox', {'trusted_proxy': selected})

    def test_winet_prefix_cannot_be_url_command_or_multiline(self):
        for value in ('', 'mqtt://broker', '$(command)', 'x\ny'):
            with self.subTest(value=value):
                with self.assertRaises(ComponentError):properties.validate('winet', {'mqtt_prefix': value})


class BindingUnitTests(unittest.TestCase):
    def test_fresh_cloud_never_requires_or_looks_up_a_legacy_image(self):
        r = fixture();r.apps['cloud']['lifecycle'] = 'fresh'
        del r.apps['cloud']['properties']['retained_pgadmin_image']
        r.image_values = lambda: self.fail('Fresh Cloud must not look up any legacy image')
        self.assertNotIn('retained_pgadmin_image', properties.bind(r)['cloud'])

    def test_retained_cloud_missing_legacy_identity_and_fresh_forbidden_identity_refuse(self):
        r = fixture();del r.apps['cloud']['properties']['retained_pgadmin_image']
        with self.assertRaises(ComponentError):properties.bind(r)
        r = fixture();r.apps['cloud']['lifecycle'] = 'fresh'
        with self.assertRaises(ComponentError):properties.bind(r)

    def test_nonempty_managed_only_source_is_valid_without_inventing_legacy_metadata(self):
        r = fixture()
        for role in ('postgresql', 'mariadb'):del r.apps['cloud']['properties']['connections'][role]
        selected = properties.bind(r)['cloud']
        self.assertEqual(selected['connections'], {})
        self.assertEqual(set(selected['managed_connections']), {'postgresql-admin', 'mariadb-admin'})

    def test_empty_total_cloud_connections_refuses(self):
        r = fixture();r.apps['cloud']['properties']['connections'] = {}
        with self.assertRaises(ComponentError):properties.bind(r)

    def test_cloud_derives_all_addresses_drivers_and_separates_account_connections(self):
        r = fixture();value = properties.bind(r)['cloud']
        self.assertEqual(value['bind_address'], '198.18.30.32')
        self.assertEqual(value['public_url'], 'https://db.example.invalid')
        self.assertEqual(set(value['connections']), {'postgresql', 'mariadb'})
        self.assertEqual(set(value['managed_connections']), {'postgresql-admin', 'mariadb-admin'})
        self.assertEqual(value['connections']['postgresql']['host'], '198.18.31.23')
        self.assertEqual(value['connections']['postgresql']['sslmode'], 'prefer')
        self.assertEqual(value['managed_connections']['postgresql-admin']['account'],
                         r.apps['cloud']['resolved_connections']['postgresql-admin']['account'])

    def test_cloud_rejects_unbound_connection_wrong_engine_port_or_managed_ssl_override(self):
        for mutate in (lambda a: a['resolved_connections'].pop('postgresql'),
                       lambda a: a['resolved_connections']['postgresql'].update(type='mqtt'),
                       lambda a: a['resolved_connections']['postgresql']['target'].update(port=5433),
                       lambda a: a['properties']['connections']['postgresql-admin'].update(sslmode='disable')):
            with self.subTest(mutate=mutate):
                r = fixture();mutate(r.apps['cloud'])
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_cloud_retained_image_must_exist_and_resolve_to_pinned_identity(self):
        for catalogue in ({}, {'old-client': {'image': 'registry.example.invalid/old-client:latest'}}):
            with self.subTest(catalogue=catalogue):
                r = fixture();r.image_values = lambda: catalogue
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_cloud_artifact_is_present_exactly_when_managed_mariadb_needs_it(self):
        r = fixture();del r.apps['cloud']['properties']['mariadb_jdbc']
        with self.assertRaises(ComponentError):properties.bind(r)
        r = fixture();del r.apps['cloud']['properties']['connections']['mariadb-admin']
        with self.assertRaises(ComponentError):properties.bind(r)

    def test_bitwarden_preserves_separate_issuer_and_existing_controller_input_owner(self):
        r = fixture();value = properties.bind(r)['vault']
        self.assertEqual(value['runtime']['public_origin'], 'https://vault.example.invalid')
        self.assertEqual(value['runtime']['issuer'], 'https://retained-issuer.example.invalid')
        self.assertEqual(value['runtime']['runtime_env_file'], '/declared/controller/vault-environment.json')
        self.assertEqual(value['runtime']['environment_sha256'], 'b'*64)
        self.assertEqual(value['settings']['database_server'], '198.18.32.24')
        self.assertEqual(value['settings']['data_uid'], 1000)
        self.assertEqual(value['settings']['image_id'], 'sha256:'+'c'*64)

    def test_bitwarden_observed_http_issuer_is_metadata_not_a_new_route_or_transport(self):
        r = fixture();r.apps['vault']['properties']['issuer']['protocol'] = 'http'
        r.site['domains']['vault-issuer'] = 'localhost'
        value = properties.bind(r)['vault']
        self.assertEqual(value['runtime']['issuer'], 'http://localhost')
        self.assertEqual(value['runtime']['public_origin'], 'https://vault.example.invalid')
        self.assertNotIn('routes', value)
        self.assertNotIn('insecure_skip_verify', value)

    def test_bitwarden_issuer_unknown_protocol_path_port_or_credentials_fields_refuse(self):
        for extra in ({'protocol': 'ftp'}, {'path': '/identity'}, {'port': 8080},
                      {'username': 'shared-user'}, {'url': 'http://foreign.invalid/'}):
            with self.subTest(extra=extra):
                r = fixture();r.apps['vault']['properties']['issuer'].update(extra)
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_bitwarden_missing_existing_input_foreign_issuer_or_fresh_lifecycle_refuses(self):
        for mutate in (lambda r: r.apps['vault'].update(lifecycle='fresh'),
                       lambda r: r.apps['vault']['secrets'].pop('runtime_environment'),
                       lambda r: r.site['domains'].clear(),
                       lambda r: r.apps['vault']['resolved_connections']['database']['target'].update(port=3307)):
            with self.subTest(mutate=mutate):
                r = fixture();mutate(r)
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_existing_file_roles_cannot_select_generated_or_environment_credentials(self):
        for key in ('old_vault_environment', 'old_manager_key', 'old_telemetry_options'):
            for kind in ('generated', 'environment'):
                with self.subTest(key=key, kind=kind):
                    r = fixture();r.site['secret_sources'][key] = {'type': kind, 'name': 'UNRELATED'}
                    with self.assertRaises(ComponentError):properties.bind(r)

    def test_pega_proxy_resolves_exact_existing_management_role_and_existing_key(self):
        value = properties.bind(fixture())['manager']
        self.assertEqual(value, {'trusted_proxy': '198.18.25.33/32',
                                'database_key_source': '/declared/controller/manager-key'})

    def test_pega_rejects_foreign_nonphysical_nontraefik_same_address_or_unknown_role(self):
        for mutate in (lambda r: r.apps['manager']['properties']['trusted_proxy'].update(app='missing'),
                       lambda r: r.apps['edge'].update(adapter='pihole'),
                       lambda r: r.apps['edge']['interfaces'].update(management={'scope': 'app-network'}),
                       lambda r: r.apps['edge']['role_addresses'].update(management='198.18.25.35'),
                       lambda r: r.apps['manager']['properties']['trusted_proxy'].update(interface='missing')):
            with self.subTest(mutate=mutate):
                r = fixture();mutate(r)
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_winet_keeps_saved_broker_hostname_independent_of_backend_address(self):
        value = properties.bind(fixture())['telemetry']
        self.assertEqual(value['mqtt_server'], 'mqtt://broker.mqtt:1883')
        self.assertEqual(value['inverter_address'], '198.18.107.23')
        self.assertEqual(value['configuration_file'], '/declared/controller/telemetry-options.json')
        self.assertEqual(value['mqtt_prefix'], 'winet-extractor/site')

    def test_declared_external_broker_hostname_does_not_require_private_dns_resolution(self):
        r = fixture();broker = r.apps['telemetry']['resolved_connections']['broker'];broker.pop('hostname')
        broker['target']['address'] = 'mqtt.external.example.invalid'
        self.assertEqual(properties.bind(r)['telemetry']['mqtt_server'],
                         'mqtt://mqtt.external.example.invalid:1883')

    def test_winet_rejects_wrong_selected_ports_and_unsafe_inverter_address(self):
        for role, field, value in (('broker', 'port', 8883), ('inverter', 'port', 8443),
                                    ('inverter', 'address', '127.0.0.1'), ('inverter', 'address', '0.0.0.0')):
            with self.subTest(role=role, field=field):
                r = fixture();r.apps['telemetry']['resolved_connections'][role]['target'][field] = value
                with self.assertRaises(ComponentError):properties.bind(r)

    def test_source_binding_never_reads_secret_paths_or_emits_password_fields(self):
        r = fixture()
        with patch('builtins.open', side_effect=AssertionError('No configured file reads')):
            selected = properties.bind(r)
        self.assertEqual(selected['flow'], {})
        self.assertNotIn('password', repr(selected))
        self.assertNotIn('userPassword', repr(selected))

    def test_redacted_error_path_never_echoes_property_values(self):
        r = fixture();r.apps['telemetry']['properties']['mqtt_prefix'] = 'SYNTHETIC_PRIVATE_VALUE\n'
        with self.assertRaises(ComponentError) as raised:properties.bind(r)
        self.assertIn('apps.telemetry.properties', str(raised.exception))
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(raised.exception))

    def test_bind_uses_only_owned_adapter_validator_and_handler_boundaries(self):
        r = fixture();r.apps = {'flow': r.apps['flow']}
        with patch.object(properties, 'validate', return_value={}) as validate, \
             patch.dict(properties.HANDLERS, {'node_red': lambda resolver, app, value: {'selected': 'metadata'}}):
            self.assertEqual(properties.bind(r), {'flow': {'selected': 'metadata'}})
        validate.assert_called_once_with('node_red', {})


if __name__ == '__main__':
    unittest.main()
