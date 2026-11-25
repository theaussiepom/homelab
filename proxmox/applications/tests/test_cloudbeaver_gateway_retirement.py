"""Require the sealed Compose, container and both file identities before retiring the gateway."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cloudbeaver_gateway_retirement as gateway
import component_prepare


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.compose = gateway.ROOT / 'compose.yml'
        self.runtime = gateway.ROOT / 'runtime'
        self.cid = '7' * 64
        self.hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in gateway.MOUNTS}
        self.proof = dict(project='tools', gateway='login', runtime=str(self.runtime),
                          image='example.invalid/proxy@sha256:' + 'a' * 64, previous_compose_sha256='1' * 64,
                          next_compose_sha256='2' * 64, files=self.hashes.copy())
        self.live = dict(self.hashes, **{'compose.yml': self.proof['previous_compose_sha256']})
        self.labels = {'com.docker.compose.project':'tools', 'com.docker.compose.service':'login'}
        self.mounts = [{'Source': str(self.runtime / name), 'Destination': target, 'RW': False, 'Type': 'bind'}
                       for name, target in gateway.MOUNTS.items()]
        self.commands = []

    def docker(self, *args):
        self.commands.append(args)
        if args[0] == 'ps':
            return self.cid
        if args[0] == 'inspect':
            return json.dumps([self.proof['image'], self.labels, self.mounts])
        if args[0] == 'rm':
            self.cid = ''

    def file_hash(self, path, uid, mode):
        self.assertEqual((uid, mode), (0, 0o600) if path == self.compose else (65532, 0o400))
        if path.name not in self.live:
            raise FileNotFoundError
        return self.live[path.name]

    def retire(self):
        with patch.object(gateway, 'docker', self.docker), patch.object(gateway, 'verified_file', self.file_hash), \
             patch.object(Path, 'resolve', autospec=True, side_effect=lambda path, strict: path), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o755)), \
             patch.object(Path, 'unlink', autospec=True, side_effect=lambda p: self.live.pop(p.name)):
            return gateway.retire(self.proof, self.compose)

    def test_remove_verified_id_and_only_its_files_then_repeat(self):
        cid = self.cid
        self.assertTrue(self.retire())
        self.assertEqual(self.commands[-2:], [('stop','--time','60',cid), ('rm',cid)])
        self.assertEqual(set(self.live), {'compose.yml'})
        self.live['compose.yml'] = self.proof['next_compose_sha256']
        self.assertFalse(self.retire())

    def test_partial_cleanup_and_refusal_before_mutation(self):
        for drift in ('old-compose','new-compose-live-gateway','wrong-service','duplicate-container',
                      'foreign-mount','writable-mount','missing-options','changed-config'):
            with self.subTest(drift=drift):
                self.setUp()
                if drift == 'old-compose': self.live['compose.yml'] = 'bad'
                if drift == 'new-compose-live-gateway': self.live['compose.yml'] = self.proof['next_compose_sha256']
                if drift == 'wrong-service': self.labels['com.docker.compose.service'] = 'other'
                if drift == 'duplicate-container': self.cid += '\n' + '8' * 64
                if drift == 'foreign-mount': self.mounts[0]['Source'] = '/another/app'
                if drift == 'writable-mount': self.mounts[0]['RW'] = True
                if drift == 'missing-options': del self.live['oauth2.cfg']
                if drift == 'changed-config': self.live['oauth2-alpha.json'] = 'changed'
                before = self.live.copy()
                with self.assertRaises(ValueError): self.retire()
                self.assertEqual(self.live, before)
                self.assertFalse(any(row[0] in ('stop','rm') for row in self.commands))
        self.setUp()
        self.cid = ''
        del self.live['oauth2.cfg']
        self.assertTrue(self.retire())

    def test_owned_regular_file_only_and_sanitized_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owned'
            path.write_bytes(b'synthetic')
            path.chmod(0o600)
            self.assertEqual(gateway.verified_file(path, os.getuid(), 0o600), hashlib.sha256(b'synthetic').hexdigest())
            with self.assertRaises(ValueError): gateway.verified_file(path, os.getuid(), 0o400)
        with patch('subprocess.run', return_value=SimpleNamespace(stdout='  sample\n')):
            self.assertEqual(gateway.docker('ps'), 'sample')
        script = gateway.__file__
        with patch.object(sys, 'argv', [script, '/tmp/other']), patch.object(sys, 'stdin', io.StringIO('{}')), \
             contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit):
            runpy.run_path(script, run_name='__main__')
        self.assertEqual(output.getvalue(), '')

    def test_controller_seals_previous_file_hashes_and_reuses_same_generation_proof(self):
        previous = Path('/previous')
        cfg = {'site':{'node':'fixture'},'guest':{'vmid':401,'hostname':'tools'},
               'deployment':{'input_directory':str(previous),'input_identity':'prior'}}
        new_cfg = dict(cfg, deployment={'input_directory':'/current','input_identity':'next'})
        old = {'id':'console', 'adapter':'cloudbeaver', 'project_name':'tools', 'project_file':'compose.yml',
               'storage_paths':{}, 'identity':{'phase':'console', 'runtime_id':'db', 'services':{
                   'cloudbeaver':'server','auth_gateway':'login'}, 'networks':{'private':'db'},
                   'runtime_directory':'/opt/homelab-app/runtime/db'},
               'authentication_resolved':{'version':1},
               'software_selection':{'images':{'auth_gateway':{'image':self.proof['image']}}}}
        new = dict(old, authentication_resolved={'type':'forward-auth'},
                   identity=dict(old['identity'], services={'cloudbeaver':'server'}))
        binding = {'input_identity':'prior','app_inputs_directory':str(previous/'applications'),
                   'input_hashes':{str(previous/'compose.yml'):'old-hash'}}
        success = {'binding':binding,'phase_inputs':{'console':{'app':'console'}}}
        history = success,cfg,{'console':old}
        payload = SimpleNamespace(manifest=json.dumps({'files':self.hashes}),directory=previous/'applications/console')
        attempt = SimpleNamespace(cfg=new_cfg)
        with patch.object(component_prepare.component_generation,'previous',return_value=history), \
             patch.object(component_prepare.component_payload.AppPayload,'load',return_value=payload), \
             patch.object(component_prepare,'regular',return_value=b'new public compose'):
            proof = component_prepare.cloudbeaver_retirement(attempt, new)
            self.assertEqual((proof['gateway'], proof['files'], proof['previous_compose_sha256']),
                             ('login', self.hashes, 'old-hash'))
            with self.assertRaises(ValueError):
                component_prepare.cloudbeaver_retirement(attempt, dict(new, project_name='other'))
            history[2]['console'] = new
            self.assertIsNone(component_prepare.cloudbeaver_retirement(attempt, new))
            binding['input_identity'] = 'next'
            payload.manifest = json.dumps({'files':{'gateway-retirement.json':'pinned'}})
            with patch.object(component_prepare,'read_json',return_value=proof):
                self.assertEqual(component_prepare.cloudbeaver_retirement(attempt, new), proof)
