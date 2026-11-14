"""Source-root authority and byte preservation before component resolution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import authored_config
import component_adapters
import component_sources as source


class SourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        return path

    def test_independent_adapters_have_no_fixed_guest_layout(self):
        self.assertEqual(len(component_adapters.ADAPTERS), 20)
        self.assertEqual(component_adapters.adapter('pihole')['services'], ('pihole',))
        self.assertEqual(component_adapters.adapter('unbound')['services'], ('unbound',))
        self.assertEqual(component_adapters.adapter('mqtt')['services'], ('mqtt',))
        self.assertEqual(component_adapters.adapter('mqtt_explorer')['services'],
                         ('mqtt_explorer', 'explorer_gateway'))
        self.assertEqual(component_adapters.adapter('postgresql')['native'], ('postgresql',))
        for invalid in ('automation', 'dns', 'unknown', None, []):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                component_adapters.adapter(invalid)

    def test_local_definitions_and_source_pins(self):
        self.write('profiles/recursive.json', {'schema': source.SCHEMA, 'kind': 'app-profile',
                                              'adapter': 'unbound'})
        self.write('stack.json', {'schema': source.SCHEMA, 'kind': 'library',
                   'guest_templates': {'base': {}},
                   'app_profiles': {'dns': {'source': 'profiles/recursive.json'}}})
        library, authority = source.library(self.root)
        self.assertEqual(library['app_profiles']['dns'], {'adapter': 'unbound'})
        self.assertEqual(set(authority.pins), {'stack.json', 'profiles/recursive.json'})
        self.assertEqual(library['policies']['network'], {})

    def test_wrong_definition_kind_recursion_and_unknown_top_level_refuse(self):
        authority = source.Sources(self.root)
        self.write('wrong.json', {'schema': source.SCHEMA, 'kind': 'guest-template'})
        self.write('recursive.json', {'schema': source.SCHEMA, 'kind': 'app-profile',
                                      'source': 'wrong.json'})
        with self.assertRaises(ValueError):
            authority.definition({'source': 'wrong.json'}, 'app-profile')
        # A second source is returned as unsupported definition data; the small
        # receiving definition validator must reject it, never recursively read.
        self.assertEqual(authority.definition({'source': 'recursive.json'}, 'app-profile'),
                         {'source': 'wrong.json'})
        self.write('stack.json', {'schema': source.SCHEMA, 'kind': 'library',
                   'guest_templates': {}, 'app_profiles': {}, 'legacy': {}})
        with self.assertRaises(ValueError):
            source.library(self.root)

    def test_raw_literal_evidence_is_not_json_reserialized(self):
        raw = b'{ "proof": [ 1, 2 ] }\n\n'
        (self.root / 'literal.json').write_bytes(raw)
        declaration = {'type': 'raw-utf8', 'source': 'literal.json',
                       'sha256': hashlib.sha256(raw).hexdigest()}
        result = source.Sources(self.root).evidence(declaration)
        self.assertEqual(result['text'].encode(), raw)
        self.assertNotEqual(result['text'], json.dumps(json.loads(raw)))
        with self.assertRaises(ValueError):
            source.Sources(self.root).asset(dict(declaration, sha256='0' * 64))

    def test_ongoing_callback_evidence_source_and_inline_forms_are_closed(self):
        proof = [{'exact': 'public synthetic callback record'}]
        path = self.write('proof.json', proof)
        evidence = {'type': 'identity-callbacks', 'source': 'proof.json',
                    'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        authority = source.Sources(self.root)
        self.assertEqual(authority.evidence(evidence)['document'], proof)
        self.assertEqual(authority.evidence({'type': 'identity-callbacks', 'document': proof})['document'], proof)
        self.assertEqual(authority.evidence({'type': 'identity-callbacks', 'document': []})['document'], [])
        for invalid in (dict(evidence, document=proof),
                        {'type': 'identity-callbacks', 'document': {}},
                        {'type': 'identity-callbacks', 'document': None},
                        {'type': 'identity-callbacks', 'source': False, 'sha256': 'a'*64},
                        {'type': 'identity-callbacks', 'source': 'proof.yaml', 'sha256': 'a'*64},
                        {'type': 'accepted-release', 'document': proof}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                authority.evidence(invalid)

    def test_no_symlink_escape_parent_or_ambiguous_document(self):
        self.write('a.json', {})
        authority = source.Sources(self.root)
        (self.root / 'link.json').symlink_to(self.root / 'a.json')
        (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        for name in ('../escape.json', '/etc/passwd', 'link.json', 'linked/a.json'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                authority.raw(name)
        (self.root / 'a.yaml').write_text('{}')
        with self.assertRaises(ValueError):
            authority.document('a.json')

    def test_same_snapshot_cannot_be_replaced_silently(self):
        path = self.write('asset.json', {'old': True})
        authority = source.Sources(self.root)
        authority.raw('asset.json')
        path.write_text('{"new":true}')
        with self.assertRaises(ValueError):
            authority.raw('asset.json')

    def test_directory_swap_cannot_redirect_an_anchored_read_outside_root(self):
        self.write('inside/asset.json', {'origin': 'inside'})
        outside_temporary = tempfile.TemporaryDirectory(dir=self.root.parent)
        self.addCleanup(outside_temporary.cleanup)
        outside = Path(outside_temporary.name).resolve()
        (outside / 'asset.json').write_text('{"origin":"outside"}')
        authority = source.Sources(self.root)
        original = source.os.open
        swapped = False

        def controlled(name, flags, *args, **kwargs):
            nonlocal swapped
            if name == 'asset.json' and kwargs.get('dir_fd') is not None and not swapped:
                (self.root / 'inside').rename(self.root / 'original-inside')
                (self.root / 'inside').symlink_to(outside, target_is_directory=True)
                swapped = True
            return original(name, flags, *args, **kwargs)

        with mock.patch.object(source.os, 'open', side_effect=controlled):
            result = authority.raw('inside/asset.json')
        self.assertTrue(swapped)
        self.assertEqual(json.loads(result), {'origin': 'inside'})
        with self.assertRaises(ValueError):
            authority.raw('inside/asset.json')

    def test_site_root_zabbix_and_evidence_do_not_mutate_inputs(self):
        value = dict(schema=source.SCHEMA, kind='site', contexts={}, networks={},
                     storage={}, guests={}, apps={}, zabbix=None,
                     evidence={'callbacks': {'type': 'identity-callbacks', 'document': [{'exact': '  literal\n'}]}})
        path = self.write('site.json', value)
        site, _ = source.site(path)
        self.assertIsNone(site['zabbix'])
        self.assertEqual(site['evidence']['callbacks']['document'][0]['exact'], '  literal\n')
        value['zabbix'] = {'server': 'monitor'}
        self.assertEqual(source.site(self.write('site.json', value))[0]['zabbix'], {'server': 'monitor'})
        for invalid in (True, {}, {'server': 'monitor', 'enabled': True}):
            value['zabbix'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                source.site(self.write('site.json', value))

    def test_snapshot_parser_keeps_redacted_errors_and_json_scalar_rules(self):
        self.assertEqual(authored_config.parse(b'zabbix:\n', '.yaml'), {'zabbix': None})
        for raw, suffix in ((b'password: !unsafe SECRET', '.yaml'),
                            (b'{"password":"SECRET","password":"other"}', '.json'),
                            (b'\xffSECRET', '.json')):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, '^' + authored_config.ERROR + '$'):
                authored_config.parse(raw, suffix)


if __name__ == '__main__':
    unittest.main()
