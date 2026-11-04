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
        spec = {'guests': {'monitoring': {}, 'dns': {}}}
        for raw in ('zabbix:\n', 'zabbix: null\n', '{"zabbix":null}'):
            path = self.file(raw)
            value = a.read(path)
            self.assertEqual(value, {'zabbix': None})
            self.assertTrue(c.zabbix.enabled(value))
            self.assertEqual(c.zabbix.selected(spec, value), spec)
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
        self.assertIsNone(a.profile_path(self.root, 'dns', optional=True))
        with self.assertRaises(ValueError): a.profile_path(self.root, 'dns')
        for guest in ('../dns', '', None):
            with self.subTest(guest=guest), self.assertRaises(ValueError): a.profile_path(self.root, guest)
        profile = self.root/'guests/dns/profile.yml';profile.parent.mkdir(parents=True);profile.write_text('{}')
        self.assertEqual(a.profile_path(self.root,'dns'), profile)

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

    def test_cli_site_root_and_legacy_explicit_file_are_mutually_exclusive(self):
        path=self.root/'site.yaml';path.write_text('{}')
        for args in (['--site-root',str(self.root)],['--site',str(path)]):
            with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check',*args]),patch.object(c,'compile_stack') as compile_stack:
                c.main();self.assertEqual(compile_stack.call_args.args,(self.root,{},[]))
        with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check','--site',str(path.with_suffix('.json'))]),self.assertRaises(ValueError):c.main()
        with patch.object(sys,'argv',['compile','--stack',str(self.root),'--check','--site',str(path),'--site-root',str(self.root)]),self.assertRaises(SystemExit):c.main()

    def test_hosted_selector_uses_declared_source_setup_and_same_yaml_json_selection(self):
        spec={'guests':{'dns':{'depends_on':[]},'monitoring':{'depends_on':['dns']}}}
        phase=self.root/'.github/workflows/phase.yml';phase.parent.mkdir(parents=True)
        phase.write_text('jobs:\n  run:\n    uses: owner/framework/.github/workflows/guest-phase.yml@'+'a'*40+'\n')
        with patch.object(c,'manifest',return_value=spec):
            gate=workflows.models(self.root)['deploy.yml']['jobs']['selection']
        self.assertEqual(gate['timeout-minutes'],2)
        self.assertNotIn('environment',gate);self.assertNotIn('secrets',gate)
        recipe=workflows.phase_recipe()[0]['steps']
        for actual,expected in zip(gate['steps'][:-1],recipe[1:7],strict=True):
            actual=copy.deepcopy(actual);expected=copy.deepcopy(expected)
            actual.pop('name',None);expected.pop('name',None);self.assertEqual(actual,expected)
            self.assertNotIn('env',actual)
        self.assertNotIn('/var/lib/homelab-bootstrap',json.dumps(gate))
        source=self.root/'framework-source/blueprints';source.mkdir(parents=True)
        (source/'authored_config.py').write_bytes(Path(a.__file__).read_bytes())
        step=gate['steps'][-1];output=self.root/'output';output.touch()
        env={'PATH':os.environ['PATH'],'HOMELAB_CONFIG_PYTHON':sys.executable,'GITHUB_OUTPUT':str(output),**step['env']}
        cases=[('zabbix:\n','[]',0,'true'),('zabbix: null\n','[]',0,'true'),
               ('{}','[]',0,'false'),('zabbix: true','[]',1,None),
               ('zabbix:\n','["monitoring"]',1,'true'),('zabbix:\n','null',1,None)]
        for suffix in a.SUFFIXES:
            for raw,disabled,status,zabbix in cases:
                if suffix=='.json':
                    raw=json.dumps({'zabbix':None} if raw.startswith('zabbix:') and 'true' not in raw else {'zabbix':True} if 'true' in raw else {})
                path=self.root/('site'+suffix);path.write_text(raw);output.write_text('')
                result=subprocess.run(['bash','-e','-o','pipefail','-c',step['run']],cwd=self.root,env=dict(env,DISABLED=disabled),capture_output=True,text=True)
                self.assertEqual(result.returncode,status,result.stderr)
                self.assertEqual(output.read_text(),'' if zabbix is None else 'zabbix='+zabbix+'\n')
                path.unlink()

    def test_selected_lock_extractor_uses_only_exact_pyyaml_hashblock(self):
        script=workflows.phase_recipe()[0]['steps'][6]['run']
        source=script.split("<<'PYCODE'\n",1)[1].split('\nPYCODE',1)[0]
        lock=self.root/'framework-source/requirements.lock.txt';lock.parent.mkdir();original=(c.ROOT/'requirements.lock.txt').read_text()
        output=self.root/'pyyaml.lock'
        def run(raw):
            lock.write_text(raw)
            return subprocess.run([sys.executable,'-c',source,str(output)],cwd=self.root,capture_output=True,text=True)
        result=run(original);self.assertEqual(result.returncode,0,result.stderr)
        lines=output.read_text().splitlines();self.assertTrue(lines[0].startswith('pyyaml=='))
        self.assertTrue(all(line.startswith('    --hash=sha256:') for line in lines[1:]));self.assertNotIn('# via',output.read_text())
        for raw in ('',original+original,original.replace('pyyaml==','pyyaml>=',1),original.replace('pyyaml==6.0.3 \\','pyyaml==6.0.3 --index-url private-sentinel \\',1),original.replace('    --hash=sha256:', '    --other=sha256:')):
            with self.subTest(raw=raw[:30]):self.assertNotEqual(run(raw).returncode,0)
        lock.unlink();lock.symlink_to(self.root/'missing');self.assertNotEqual(subprocess.run([sys.executable,'-c',source,str(output)],cwd=self.root,capture_output=True).returncode,0)
        self.assertIn('--require-hashes --no-deps',script);self.assertIn('-m pip --isolated install',script)
        self.assertNotIn('APPLICATION_SSH_KEY',script);self.assertNotIn('PROXMOX_APP_TOKEN',script)
