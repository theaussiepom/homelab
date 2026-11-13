"""Complete relationship leaves reuse the confined reader and real binders."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'proxmox/applications'))

import component_packet
import component_plan
import component_sources
import component_workflows
from component_errors import ComponentError
from test_component_explorer_latefiles import source_fixture


class RelationshipSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = self.root / 'stack'
        self.stack.mkdir()
        self.source = self.root / 'site.json'
        self.library, self.site = source_fixture()
        (self.stack / 'images.json').write_text(json.dumps({name: {
            'repository': 'example/' + name, 'tag': None, 'digest': 'sha256:' + 'a' * 64}
            for name in ('broker', 'browser', 'gateway')}))

    def resolve(self):
        (self.stack / 'stack.json').write_text(json.dumps(self.library))
        self.source.write_text(json.dumps(self.site))
        return component_plan.resolve(self.stack, self.source)

    def split(self, suffix='.yaml'):
        paths = {}
        for collection, kind in (('connections', 'connection'), ('exposures', 'exposure')):
            (self.root / collection).mkdir(exist_ok=True)
            for name, value in list(self.site[collection].items()):
                path = self.root / collection / (name + suffix)
                document = {'schema': component_sources.SCHEMA, 'kind': kind, **value}
                path.write_text(json.dumps(document) if suffix == '.json'
                                else yaml.safe_dump(document, sort_keys=False))
                self.site[collection][name] = {'source': path.relative_to(self.root).as_posix()}
                paths[collection, name] = path
        return paths

    def test_inline_json_and_yaml_leaves_have_identical_packets_graphs_and_owned_accounts(self):
        for suffix in ('.json', '.yaml', '.yml'):
            with self.subTest(suffix=suffix):
                original = copy.deepcopy(self.site)
                before = self.resolve()
                paths = self.split(suffix)
                after = self.resolve()
                self.assertEqual(component_packet.lower_plan(after), component_packet.lower_plan(before))
                self.assertEqual(component_workflows.model(after), component_workflows.model(before))
                self.assertEqual(after.resolved, before.resolved)
                self.assertEqual(after.site, before.site)
                self.assertEqual(set(after.pins['site']), {'site.json',
                    *(path.relative_to(self.root).as_posix() for path in paths.values())})
                for path in paths.values():
                    self.assertEqual(after.pins['site'][path.relative_to(self.root).as_posix()],
                                     hashlib.sha256(path.read_bytes()).hexdigest())
                    path.unlink()
                self.site = original

    def test_leaf_changes_reach_actual_binders_and_sealed_snapshot_pins(self):
        paths = self.split()
        before = self.resolve()
        path = paths['connections', 'broker']
        value = yaml.safe_load(path.read_text())
        value['hostname'] = {'alias': 'broker_alias'}
        self.site['host_aliases'] = {'broker_alias': {'hostname': 'saved-broker'}}
        path.write_text(yaml.safe_dump(value))
        after = self.resolve()
        self.assertEqual(after.resolved['apps']['browser']['resolved_connections']['broker']['hostname'],
                         'saved-broker')
        self.assertNotEqual(before.pins['site'][str(path.relative_to(self.root))],
                            after.pins['site'][str(path.relative_to(self.root))])
        self.assertEqual(before.resolved['guest_dependencies'], after.resolved['guest_dependencies'])

    def test_wrong_headers_recursive_sources_and_partial_overlays_refuse_without_value_echo(self):
        paths = self.split()
        for (collection, name), path in paths.items():
            original = path.read_text()
            doc = yaml.safe_load(original)
            values = [dict(doc, kind='app'), dict(doc, schema='foreign'),
                {key: val for key, val in doc.items() if key != 'schema'},
                {key: val for key, val in doc.items() if key != 'kind'},
                {'schema': component_sources.SCHEMA, 'kind': doc['kind'], 'source': 'never.yaml'},
                dict(doc, unknown='PRIVATE_SENTINEL'), [], None]
            for value in values:
                path.write_text(yaml.safe_dump(value))
                with self.subTest(collection=collection, value=value), self.assertRaises(ComponentError) as caught:
                    self.resolve()
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
                self.assertIn(collection, caught.exception.path)
            path.write_text(original)
            self.site[collection][name]['unknown'] = 'PRIVATE_SENTINEL'
            with self.assertRaises(ComponentError):
                self.resolve()
            del self.site[collection][name]['unknown']

    def test_confined_paths_symlinks_ambiguity_and_duplicate_fields_refuse_for_both_kinds(self):
        paths = self.split()
        for (collection, name), path in paths.items():
            original, reference = path.read_text(), self.site[collection][name]
            for value in ('../outside.yaml', '/absolute.yaml', collection + '/missing.yaml',
                          collection + '//leaf.yaml', collection + '/../leaf.yaml', None, 4):
                self.site[collection][name] = {'source': value}
                with self.subTest(collection=collection, value=value), self.assertRaises(ComponentError):
                    self.resolve()
            self.site[collection][name] = reference
            path.unlink()
            path.symlink_to(self.stack / 'images.json')
            with self.assertRaises(ComponentError):
                self.resolve()
            path.unlink()
            path.write_text(original)
            sibling = path.with_suffix('.json')
            sibling.write_text('{}')
            with self.assertRaises(ComponentError):
                self.resolve()
            sibling.unlink()
            path.write_text(original + '\nkind: exposure\n')
            with self.assertRaises(ComponentError):
                self.resolve()
            path.write_text(original)

    def test_complete_leaf_uses_existing_connection_refusal_contract(self):
        path = self.split()['connections', 'broker']
        original = yaml.safe_load(path.read_text())
        changes = [{'consumer': {'app': 'missing', 'connection': 'broker'}},
                   {'consumer': {'app': 'browser', 'connection': 'missing'}},
                   {'target': {'external': 'missing'}}, {'source_interface': 'missing_interface'},
                   {'readiness': 'start'}, {'transport': 'missing'},
                   {'account': 'missing'}, {'credential': {'principal': 'client', 'secret': 'probe'}}]
        for change in changes:
            path.write_text(yaml.safe_dump({**original, **change}))
            with self.subTest(change=change), self.assertRaises(ComponentError):
                self.resolve()
        path.write_text(yaml.safe_dump(original))
        self.resolve()

    def test_complete_leaf_uses_existing_exposure_refusal_and_origin_contract(self):
        path = self.split()['exposures', 'browser']
        original = yaml.safe_load(path.read_text())
        for change in ({'type': 'unknown'}, {'domain': 'missing'}, {'tls': 'missing'},
                       {'ingress': {'external': 'api'}}, {'endpoint': {'app': 'missing', 'endpoint': 'web_endpoint'}},
                       {'aliases': ['browser']}, {'middlewares': ['missing']}, {'transport': 'missing'}):
            path.write_text(yaml.safe_dump({**original, **change}))
            with self.subTest(change=change), self.assertRaises(ComponentError):
                self.resolve()
        path.write_text(yaml.safe_dump(original))
        self.assertEqual(self.resolve().resolved['apps']['browser']['origin_url'],
                         'https://browser.example.invalid')


if __name__ == '__main__':
    unittest.main()
