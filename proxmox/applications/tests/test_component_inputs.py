"""Static-input units use a conforming compiled guest; one real attempt lock path."""
import copy
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_guest
import component_inputs as inputs
from component_payload import BINDING_SCHEMA
from deployment_state import DeploymentAttempt
from private_io import encoded, sha, write_new


class StaticInputTests(unittest.TestCase):
    def test_stdlib_receiver_rejects_double_root_path_aliases(self):
        for value in ('//etc','//opt/homelab-app','//var/lib/homelab-managed-credentials'):
            with self.subTest(path=value),self.assertRaises(ValueError):component_guest.path(value)
        self.assertEqual(component_guest.path('/srv/example/apps'),Path('/srv/example/apps'))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        self.inputs = self.root/'inputs'; self.identity = 'a'*64
        directory = self.inputs/'example'/self.identity
        for name in ('state', 'workspace'):
            (self.root/name).mkdir(mode=0o700)
        self.cfg = {'schema': component_guest.CONFIG_SCHEMA,
            'site': {'node': 'example-node', 'api_endpoint': 'https://192.0.2.10:8006/'},
            'guest': {'vmid': 610, 'hostname': 'example', 'memory_mib': 512,
                'interfaces': [{'ipv4': '198.18.20.10/24', 'mac': '02:00:00:20:00:10'}]},
            'ssh_public_keys': [], 'paths': {'state_root': str(self.root/'state'),
                'ca_file': str(self.root/'ca'), 'known_hosts': str(self.root/'known_hosts'),
                'api_token': str(self.root/'api-token'), 'private_key': str(self.root/'key'),
                'backup_mount': str(self.root/'backup'), 'backup_directory': str(self.root/'backup/data'),
                'backup_source': 'example:/backup'},
            'deployment': {'contract': 3, 'capabilities': ['linux','docker'],
                'input_identity': self.identity, 'input_directory': str(directory),
                'runtime_file': str(directory/'component-runtime.json'), 'lifecycle': 'fresh',
                'protected_guests': [9900], 'phases': ['preparation','resolver'],
                'applications': {'resolver': {'id': 'resolver_a', 'adapter': 'unbound', 'lifecycle': 'fresh',
                    'runtime_id': 'resolver_a', 'project': 'example-resolver', 'compose_file': 'compose-resolver.yml',
                    'services': ['resolver_a_unbound']}}, 'payload_phases': {'resolver': 'resolver_a'}},
            'app': {'kind': 'example', 'vmid': 610, 'hostname': 'example', 'memory_mib': 512,
                'address': '198.18.20.10', 'mac': '02:00:00:20:00:10', 'packages': [],
                'service_health_checks': {'resolver': [{'name':'ready','argv':['true'],'expect':''}]}}}
        self.packet = {'schema': component_guest.PACKET_SCHEMA, 'guest': 'example', 'enabled': True,
            'identity': self.identity, 'files': {'site.json': encoded(self.cfg).decode(),
                'component-runtime.json': encoded({'schema':'homelab-component-runtime-v1',
                    'guest':{'id':'example'}, 'applications':{'resolver_a':{'id':'resolver_a',
                        'adapter':'unbound','lifecycle':'fresh','identity':{'phase':'resolver',
                            'runtime_id':'resolver_a','services':{'unbound':'resolver_a_unbound'}},
                        'project_name':'example-resolver','project_file':'compose-resolver.yml'}}}).decode(),
                'compose-resolver.yml':encoded({'name':'example-resolver','services':{}}).decode()}}
        self.path = self.root/'packet.json'; write_new(self.path, encoded(self.packet))
        write_new(self.root/'ca', b'public synthetic certificate\n')
        self.environment = patch.dict(os.environ, {'GITHUB_RUN_ID':'101','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_RUN_NUMBER':'10','GITHUB_REPOSITORY':'example/private',
            'HOMELAB_DEPLOYMENT_WORKFLOW':'example/private/.github/workflows/deploy.yml@'+'b'*40,
            'GITHUB_SHA':'c'*40,'GITHUB_WORKSPACE':str(self.root/'workspace')})
        self.environment.start(); self.addCleanup(self.environment.stop)
        source = patch('deployment_inputs.source_hash', return_value='d'*64)
        source.start(); self.addCleanup(source.stop)

    def prepare(self, create=True):
        return inputs.prepare(self.path, self.inputs, create=create)

    def snapshot(self, directory):
        return {str(p.relative_to(directory)):(p.stat().st_ino,p.stat().st_mode,p.read_bytes())
                for p in directory.rglob('*') if p.is_file()}

    def test_create_once_repeat_verify_and_separate_app_directory_do_not_rebind_static_inputs(self):
        cfg, site = self.prepare()
        before = self.snapshot(self.inputs)
        expected = inputs.binding(cfg, site)
        self.prepare(create=False)
        self.assertEqual(self.snapshot(self.inputs), before)
        self.assertEqual(expected['schema'], BINDING_SCHEMA)
        self.assertEqual(set(expected), {'schema','vmid','site_sha256','source_sha256','input_identity',
                                         'app_inputs_directory','input_hashes'})
        folder = inputs.app_directory(cfg, create=True)
        from component_payload import prepare
        prepare(folder, self.identity, 'resolver_a', {'private-file':b'synthetic-private'})
        self.assertEqual(inputs.binding(cfg, site), expected)
        self.assertFalse(any('private-file' in key for key in expected['input_hashes']))

    def test_missing_verify_only_partial_publication_and_drift_preserve_files(self):
        with self.assertRaises(ValueError):
            self.prepare(create=False)
        original = inputs.write_new
        def fail(name, raw, **kwargs):
            if name == inputs.MANIFEST:
                raise OSError('synthetic publication failure')
            original(name, raw, **kwargs)
        with patch.object(inputs,'write_new',side_effect=fail), self.assertRaises(OSError):
            self.prepare()
        before = self.snapshot(self.inputs)
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertEqual(self.snapshot(self.inputs), before)

    def test_static_file_or_manifest_tamper_and_symlink_are_refused(self):
        cfg, site = self.prepare()
        path = Path(cfg['deployment']['input_directory'])/'component-runtime.json'
        before = path.read_bytes(); path.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.prepare()
        path.write_bytes(before); path.chmod(0o644)
        with self.assertRaises(ValueError):
            inputs.binding(cfg,site)
        path.chmod(0o600); path.unlink(); path.symlink_to(self.root/'ca')
        with self.assertRaises(OSError):
            self.prepare()

    def test_attempt_holds_locks_before_static_publication_and_never_reads_app_secrets(self):
        calls = []
        def prepare(create):
            work = self.root/'state/610'
            self.assertTrue((work/'workflow.lock').exists())
            self.assertTrue((work/'deployment.lock').exists())
            cfg, site = self.prepare(create)
            calls.append(create)
            return inputs.binding(cfg,site)
        with patch('component_input_secrets.selected', side_effect=AssertionError('No app secrets')), \
             patch('managed_credentials.credential', side_effect=AssertionError('No credentials')):
            with DeploymentAttempt(self.cfg,None,['preparation','resolver'],prepare_inputs=prepare) as attempt:
                self.assertEqual(calls,[True])
                self.assertEqual(attempt.binding['schema'],BINDING_SCHEMA)
                self.assertFalse(attempt.hold.exists())
                self.assertFalse((attempt.work/'terraform.tfstate').exists())
                self.assertFalse((Path(self.cfg['deployment']['input_directory'])/'applications').exists())

    def test_foreign_ordinary_hold_allows_only_exact_static_verification_and_no_phase_mutation(self):
        self.prepare()
        work=self.root/'state/610';work.mkdir(mode=0o700)
        hold=work/'ORDINARY-HOLD.json';write_new(hold,encoded({'foreign':True}))
        before=self.snapshot(self.inputs);original=hold.read_bytes();calls=[]
        def prepare(create):
            calls.append(create);cfg,site=self.prepare(create);return inputs.binding(cfg,site)
        with DeploymentAttempt(self.cfg,None,['preparation','resolver'],prepare_inputs=prepare) as attempt:
            with self.assertRaises(ValueError):
                attempt.phase_ready('resolver')
        self.assertEqual(calls,[False]);self.assertEqual(hold.read_bytes(),original)
        self.assertEqual(self.snapshot(self.inputs),before)
        self.assertFalse((work/'ordinary-101-1').exists())

    def test_refused_historical_evidence_leaves_only_static_input_evidence(self):
        def prepare(create):
            cfg,site=self.prepare(create)
            return inputs.binding(cfg,site)
        with patch('coordinated_evidence.inspect', side_effect=ValueError('synthetic missing historical evidence')):
            with self.assertRaises(ValueError):
                with DeploymentAttempt(self.cfg,None,['preparation','resolver'],prepare_inputs=prepare):
                    self.fail('unqualified evidence was admitted')
        work=self.root/'state/610'
        self.assertFalse((work/'ORDINARY-HOLD.json').exists())
        self.assertFalse((work/'terraform.tfstate').exists())
        self.assertFalse((Path(self.cfg['deployment']['input_directory'])/'applications').exists())
        before=self.snapshot(self.inputs)
        self.prepare(create=False)
        self.assertEqual(before,self.snapshot(self.inputs))

    def test_lock_contention_precedes_static_preparation(self):
        work=self.root/'state/610';work.mkdir(mode=0o700)
        descriptor=os.open(work/'deployment.lock',os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with DeploymentAttempt(self.cfg,None,['preparation','resolver'],
                        prepare_inputs=lambda _: self.fail('preparation ran before lock ownership')):
                    pass
        finally:
            os.close(descriptor)
        self.assertFalse(self.inputs.exists())

    def test_retained_container_writer_assertion_is_required_before_publication(self):
        value=copy.deepcopy(self.packet)
        cfg=json.loads(value['files']['site.json'])
        cfg['deployment']['applications']['resolver']['lifecycle']='retained'
        runtime=json.loads(value['files']['component-runtime.json'])
        runtime['applications']['resolver_a']['lifecycle']='retained'
        value['files']['component-runtime.json']=encoded(runtime).decode()
        for asserted in (None,False):
            if asserted is None:cfg['app'].pop('exclusive_writer_confirmed',None)
            else:cfg['app']['exclusive_writer_confirmed']=asserted
            value['files']['site.json']=encoded(cfg).decode()
            with self.subTest(asserted=asserted),self.assertRaisesRegex(ValueError,'writer assertion'):
                component_guest.packet(value,self.inputs)
        self.assertFalse(self.inputs.exists())
        cfg['app']['exclusive_writer_confirmed']=True
        value['files']['site.json']=encoded(cfg).decode()
        component_guest.packet(value,self.inputs)


if __name__ == '__main__':
    unittest.main()
