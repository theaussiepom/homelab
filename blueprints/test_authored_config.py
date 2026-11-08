"""Authored YAML keeps exact JSON values and fails closed before deployment."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import authored_config as a
import compile as c
import component_monitoring
from types import SimpleNamespace
import workflows


class AuthoredConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, text, suffix='.yaml'):
        path = self.root / ('source' + suffix)
        path.write_text(text)
        return path

    def refuses(self, text, suffix='.yaml'):
        path = self.file(text, suffix)
        try:
            with self.assertRaisesRegex(ValueError, '^' + a.ERROR + '$') as caught:
                a.read(path)
            self.assertNotIn('private-sentinel', str(caught.exception))
        finally:
            path.unlink()

    def test_yaml_preserves_recursive_json_types_and_literal_bytes(self):
        expected = {'null': None, 'bools': [True, False], 'ints': [0, -8, 42],
                    'float': [0.5, -1.2e3, 1e-9],
                    'strings': ['yes', 'on', 'off', '2026-11-04', '001', '1:20', '${inputs}',
                                'private-sentinel\n  exact\n\n', 'no final newline'],
                    'nested': {'<<': 'literal', 'str': ''}}
        for suffix, raw in (('.json', json.dumps(expected)),
                            ('.yaml', yaml.safe_dump(expected, sort_keys=False))):
            path = self.file(raw, suffix)
            actual = a.read(path)
            self.assertEqual(actual, expected)
            def types(value):
                return (type(value), {k: types(v) for k,v in value.items()} if isinstance(value, dict)
                        else [types(v) for v in value] if isinstance(value, list) else None)
            self.assertEqual(types(actual), types(expected))
            path.unlink()
        value = a.read(self.file('yes: yes\non: on\ndate: 2026-11-04\ntext: |+\n  one\n\n'))
        self.assertEqual(value, {'yes':'yes', 'on':'on', 'date':'2026-11-04','text':'one\n\n'})

    def test_duplicate_unsafe_and_unsupported_yaml_refuse_without_source_echo(self):
        for text in ('private-sentinel: [', 'x: 1\nx: 2', 'x: &id 1', 'x: *id',
                     'x: !!str private-sentinel', 'x: !custom private-sentinel',
                     'x: !!python/object/apply:os.system [private-sentinel]',
                     '? [a, b]\n: value', 'true: value', '1: value',
                     '<<: {x: 1}', 'x: 1\n---\nx: 2', 'x: .inf', 'x: -.Inf', 'x: .NaN', 'x: 1e9999'):
            with self.subTest(text=text): self.refuses(text)
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e9999}', 'private-sentinel'):
            with self.subTest(text=text): self.refuses(text, '.json')
        self.assertEqual(a.read(self.file('"<<": ordinary string key')), {'<<':'ordinary string key'})

    def test_empty_zabbix_property_is_null_and_selects_the_same_monitoring_graph(self):
        for raw in ('zabbix:\n', 'zabbix: null\n', '{"zabbix":null}'):
            path = self.file(raw)
            value = a.read(path)
            self.assertEqual(value, {'zabbix': None})
            self.assertEqual(component_monitoring.server(SimpleNamespace(site=value,apps={
                'observer':{'adapter':'zabbix'}})),'observer')
            path.unlink()

    def test_each_variant_is_exact_and_siblings_are_ambiguous_even_for_explicit_paths(self):
        for suffix in a.SUFFIXES:
            path = self.root / ('site' + suffix);path.write_text('{}')
            self.assertEqual(a.site_path(self.root), path)
            self.assertEqual(a.source_path(path), path)
            for other in set(a.SUFFIXES)-{suffix}:
                with self.assertRaises(ValueError): a.source_path(path.with_suffix(other))
            extra = path.with_suffix(next(v for v in a.SUFFIXES if v != suffix));extra.write_text('{}')
            with self.assertRaises(ValueError): a.site_path(self.root)
            with self.assertRaises(ValueError): a.read(path)
            extra.unlink();path.unlink()
        with self.assertRaises(ValueError): a.site_path(self.root)
        with self.assertRaises(ValueError): a.source_path(self.root/'site.txt')

    def test_nonregular_symlink_and_encoding_sources_refuse(self):
        path = self.root/'site.yaml';path.mkdir()
        with self.assertRaises(ValueError): a.read(path)
        path.rmdir();path.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError): a.read(path)
        path.unlink();path.write_text('{}')
        path.write_bytes(b'\xff')
        with self.assertRaisesRegex(ValueError,a.ERROR): a.read(path)
        path.unlink();os.mkfifo(path)
        with self.assertRaises(ValueError): a.read(path)

    def test_parser_bounds_refuse_before_unbounded_work(self):
        for suffix in ('.json','.yaml'):
            path=self.file('[1,2,3]',suffix)
            for field,limit in (('MAX_BYTES',3),('MAX_NODES',3),('MAX_DEPTH',1)):
                with self.subTest(suffix=suffix,field=field), patch.object(a,field,limit), self.assertRaises(ValueError): a.read(path)
            path.unlink()
        self.refuses('['*70+'0'+']'*70)
        path=self.file('{}')
        with patch.object(a.os,'open',side_effect=PermissionError('private-sentinel')),self.assertRaisesRegex(ValueError,a.ERROR):a.read(path)
        with patch.object(a,'_identity',side_effect=[1,2]),self.assertRaises(ValueError):a.read(path)
        for value in (object(), {'x':{1:'wrong'}}, float('inf')):
            with self.assertRaises(ValueError):a._shape(value)
        with patch.object(a.yaml,'load',side_effect=RecursionError('private-sentinel')),self.assertRaisesRegex(ValueError,a.ERROR):a.read(path)

    def test_cli_site_root_and_explicit_file_are_mutually_exclusive(self):
        path=self.root/'site.yaml';path.write_text('{}')
        for args in (['--site-root',str(self.root)],['--site',str(path)]):
            with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check',*args]),patch.object(c,'compile_site',return_value={}) as compile_site:
                c.main();self.assertEqual(compile_site.call_args.args,(self.root,path,[]))
        with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check','--site',str(path.with_suffix('.json'))]),self.assertRaises(ValueError):c.main()
        with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check','--site',str(path),'--site-root',str(self.root)]),self.assertRaises(SystemExit):c.main()


    def test_selected_lock_extractor_keeps_only_required_compiler_packages(self):
        import config_environment
        script=workflows.phase_recipe()[0]['steps'][6]['run']
        lock=self.root/'requirements.lock.txt';original=(c.ROOT/'requirements.lock.txt').read_text()
        lock.write_text(original);result=config_environment.selected(lock)
        self.assertEqual([line.split('==')[0] for line in result.splitlines() if not line.startswith(' ')],
                         ['pyyaml','cryptography','cffi','pycparser'])
        self.assertNotIn('# via',result)
        for raw in ('',original+original,original.replace('pyyaml==','pyyaml>=',1),
                    original.replace('cryptography==','cryptography>=',1),
                    original.replace('    --hash=sha256:', '    --other=sha256:')):
            lock.write_text(raw)
            with self.subTest(raw=raw[:30]),self.assertRaises(ValueError):config_environment.selected(lock)
        lock.unlink();lock.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):config_environment.selected(lock)
        self.assertIn('--require-hashes --no-deps',script);self.assertIn('-m pip --isolated install',script)
        self.assertNotIn('APPLICATION_SSH_KEY',script);self.assertNotIn('PROXMOX_APP_TOKEN',script)
