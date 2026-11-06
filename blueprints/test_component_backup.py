"""PBS component units use conforming app/guest collaborators, without targets."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import component_backup as backup
from component_errors import ComponentError
import component_plan
import component_packet
import component_workflows
from test_component_plan import library, site


def profile():
    return {'type': 'pbs-client', 'software': ['pbs-client'],
            'configuration': {'ssh': {'path': '/etc/ssh', 'kind': 'directory'}}}


def fixture():
    guest = {'context': 'lab', 'identity': {'vmid': 610, 'hostname': 'example'},
        'volumes': {'data': {'path': '/srv/example', 'backup': None}},
        'root_paths': {'root': {'path': '/srv/config'}}}
    definition = {'storage': {'data': {'kind': 'directory'}, 'logs': {'kind': 'directory'},
                             'config': {'kind': 'file'}, 'database': {'kind': 'directory'}},
        'backup': {'include': {'data': {'category': 'state', 'capture': 'application-export'},
            'config': {'category': 'configuration', 'capture': 'files'},
            'database': {'category': 'database', 'capture': 'database-export'}},
            'exclude': {'logs': 'transient'},
            'configuration': {'native': {'path': '/etc/example', 'kind': 'directory'}}}}
    app = {'guest': 'one', 'profile': 'example', 'adapter': 'example', 'identity': {},
        'storage': {role: {'volume': 'data', 'subpath': role} for role in ('data', 'logs', 'database')},
        'resolved_connections': {'db': {'type': 'postgresql', 'target': {'app': 'db'}},
                                 'http': {'type': 'http', 'target': {'external': 'public'}}}}
    app['storage']['config'] = {'root_path': 'root', 'subpath': 'config.yaml'}
    app['runtime_files'] = {'directory': '/opt/homelab-app/runtime/one', 'files': ['owned.json']}
    app['sidecar_files'] = {'sidecar': {'destination': '/opt/homelab-app/one.json'}}
    return SimpleNamespace(site={'backup': None, 'contexts': {'lab': {'node': 'example-node'}}},
        library={'backup_profiles': {'pbs': profile()}, 'app_profiles': {'example': definition}},
        guests={'one': guest, 'empty': copy.deepcopy(dict(guest, identity={'vmid': 611, 'hostname': 'empty'}))},
        apps={'application': app})


class BackupUnits(unittest.TestCase):
    def test_presence_and_selection_are_closed_and_ambiguous_defaults_refuse(self):
        for value in (None, {}): backup.presence(value)
        for value in (True, False, 'yes', 1, [], {'enabled': True}):
            with self.subTest(value=value), self.assertRaises(ComponentError): backup.presence(value)
        r = fixture()
        self.assertEqual(backup.selected(r), 'pbs')
        r.site['backup'] = {}; self.assertEqual(backup.software(r), ['pbs-client'])
        r.site['backup'] = {'profile': 'pbs'}; self.assertEqual(backup.selected(r), 'pbs')
        for value in (False, 'pbs', {'profile': 'missing'}, {'profile': []}, {'enabled': True}):
            r.site['backup'] = value
            with self.subTest(value=value), self.assertRaises(ComponentError): backup.selected(r)
        r.site['backup'] = None; r.library['backup_profiles']['other'] = profile()
        with self.assertRaisesRegex(ComponentError, 'profile-selection'): backup.selected(r)
        r.site.pop('backup'); before = copy.deepcopy(r.guests)
        self.assertIsNone(backup.selected(r)); self.assertEqual(backup.software(r), [])
        self.assertIsNone(backup.bind(r)); self.assertEqual(before, r.guests)

    def test_profile_refuses_shells_empty_packages_root_paths_and_unknown_fields(self):
        backup.profile(profile())
        changes = [lambda x: x.update(type='other'), lambda x: x.update(software=[]),
            lambda x: x.update(software=['bad package']), lambda x: x.update(command='PRIVATE_SENTINEL'),
            lambda x: x['configuration']['ssh'].update(path='/'),
            lambda x: x['configuration']['ssh'].update(kind='symlink')]
        for change in changes:
            value = profile(); change(value)
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError) as caught:
                backup.profile(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_every_storage_role_has_one_disposition_and_coherent_capture_contract(self):
        r = fixture(); value = r.library['app_profiles']['example']
        backup.application(value['backup'], value['storage'])
        changes = [lambda x: x['include'].pop('data'), lambda x: x['exclude'].update(data='transient'),
            lambda x: x['exclude'].update(extra='transient'), lambda x: x['exclude'].update(logs='unknown'),
            lambda x: x['include']['data'].update(capture='files'),
            lambda x: x['include']['database'].update(capture='files'),
            lambda x: x['include']['config'].update(capture='database-export'),
            lambda x: x['include']['data'].update(category='unknown'),
            lambda x: x['configuration']['native'].update(path='/'),
            lambda x: x['configuration']['native'].update(kind='block-device')]
        for change in changes:
            selected = copy.deepcopy(value['backup']); change(selected)
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError):
                backup.application(selected, value['storage'])

    def test_bindings_derive_paths_without_copying_credentials_adding_edges_or_reading_data(self):
        r = fixture(); self.assertEqual(backup.bind(r), {'profile': 'pbs', 'mode': 'client-preparation'})
        self.assertIn('backup', r.guests['empty'])
        value = r.guests['one']['backup']; app = value['applications']['application']
        self.assertEqual(app['storage']['data']['path'], '/srv/example/data')
        self.assertEqual(app['storage']['config']['path'], '/srv/config/config.yaml')
        self.assertFalse(app['storage']['database']['include'])
        self.assertEqual(app['storage']['database']['capture'], 'database-export')
        self.assertFalse(app['storage']['logs']['include'])
        self.assertEqual(app['databases'], [{'connection': 'db', 'type': 'postgresql', 'target': {'app': 'db'}}])
        self.assertEqual(app['runtime_files'], ['/opt/homelab-app/runtime/one/owned.json', '/opt/homelab-app/one.json'])
        self.assertNotIn('password', json.dumps(value)); self.assertNotIn('rules', r.guests['one'])
        app['storage']['data']['category'] = 'changed'
        self.assertEqual(r.library['app_profiles']['example']['backup']['include']['data']['category'], 'state')

    def test_incomplete_library_or_authoritative_volume_binding_refuses(self):
        changes = [lambda r: r.library['app_profiles']['example'].pop('backup'),
                   lambda r: r.guests['one']['volumes']['data'].pop('backup'),
                   lambda r: r.apps['application']['storage'].update(data={'asset': 'unsafe'})]
        for change in changes:
            r = fixture(); change(r)
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError): backup.bind(r)


    def test_owned_compose_and_private_environment_remain_in_the_recovery_inventory(self):
        r = fixture(); app = r.apps['application']
        app['adapter'] = 'bitwarden'; app['identity']['project'] = 'shared'
        app['secret_bindings'] = {'runtime_environment': {'source_id': 'owned'}}
        r.guests['one']['compose_projects'] = {'shared': {'file': 'compose-shared.yml'}}
        backup.bind(r)
        files = r.guests['one']['backup']['applications']['application']['runtime_files']
        self.assertIn('/opt/homelab-app/compose-shared.yml', files)
        self.assertIn('/opt/homelab-app/component-application-environment.yml', files)


class BackupIntegration(unittest.TestCase):
    def test_real_source_packet_workflow_and_volume_flags_are_opt_in(self):
        import component_guest
        from private_io import encoded
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); stack = root/'library'; stack.mkdir()
            authored = library(); selected = site()
            authored['backup_profiles'] = {'pbs': profile()}
            authored['software'] = {'pbs-client': {'packages': ['proxmox-backup-client=4.2.8-1']},
                'resolver': {'images': {'unbound': 'unbound'}}}
            authored['runtime_profiles'] = {'resolver': {'containers': {'unbound': {
                'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}}}}
            authored['app_profiles']['recursive'].update(software=['resolver'], runtime=['resolver'],
                health={'ready': {'type': 'adapter', 'check': 'readiness'}},
                backup={'include': {}, 'exclude': {}})
            (stack/'stack.json').write_text(json.dumps(authored))
            (stack/'images.json').write_text(json.dumps({'unbound': {'repository': 'example/unbound',
                'tag': '1', 'digest': 'sha256:'+'a'*64}}))
            selected['guests']['resolver']['volumes'] = {
                'data': {'storage': 'local', 'slot': 0, 'path': '/srv/example', 'size_gib': 4, 'backup': None},
                'cache': {'storage': 'local', 'slot': 1, 'path': '/srv/cache', 'size_gib': 2}}
            path = root/'site.yaml'
            import yaml
            path.write_text(yaml.safe_dump(selected))
            original = component_plan.resolve(stack, path)
            before = component_packet.lower_plan(original)['resolver']
            self.assertNotIn('backup', json.loads(before['files']['site.json'])['app'])
            self.assertNotIn('backup', json.loads(before['files']['site.json'])['guest']['volumes']['cache'])
            selected['backup'] = None; path.write_text(yaml.safe_dump(selected))
            plan = component_plan.resolve(stack, path, disabled=['resolver'])
            self.assertIn('backup', plan.resolved['guests']['resolver'])
            self.assertEqual(plan.resolved['enabled'], [])
            plan = component_plan.resolve(stack, path)
            packet = component_packet.lower_plan(plan)['resolver']
            cfg = json.loads(packet['files']['site.json'])
            self.assertTrue(cfg['guest']['volumes']['data']['backup'])
            self.assertFalse(cfg['guest']['volumes']['cache']['backup'])
            self.assertEqual(cfg['deployment']['phases'][-1], backup.PHASE)
            self.assertEqual(component_workflows.model(plan)['guests']['resolver']['phases'][-1]['name'], 'PBS agent')
            component_guest.packet(packet, component_packet.INPUTS)
            for invalid in (True, False, {'profile': 'missing'}, {'enabled': True}):
                bad = copy.deepcopy(selected); bad['backup'] = invalid
                path.write_text(yaml.safe_dump(bad))
                with self.subTest(root=invalid), self.assertRaises(ComponentError):
                    component_plan.resolve(stack, path)
            cfg['deployment']['payload_phases'][backup.PHASE] = 'foreign'
            with self.assertRaises(ValueError): component_guest.phases(cfg)


if __name__ == '__main__': unittest.main()
